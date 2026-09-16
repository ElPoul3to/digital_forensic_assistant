from dfa.generation.citations import validate
from dfa.router.router import Route, decide, extract_filters


def test_router_heuristics():
    assert decide("Which ATT&CK techniques match the sudo activity on app-1?", use_llm=False).route == Route.EVIDENCE_ATTACK
    assert decide("Map the sudo activity to MITRE", use_llm=False).route == Route.EVIDENCE_ATTACK
    # attack_only is never chosen from keywords: without the LLM an ATT&CK mention searches both tiers
    assert decide("What is T1078.002?", use_llm=False).route == Route.EVIDENCE_ATTACK
    q = "One of the downloaded files on the target system is a scanning tool. What is the name of the tool? What is the ATT&CK technique related ?"
    assert decide(q, use_llm=False).route == Route.EVIDENCE_ATTACK
    d = decide("Who logged in from 190.166.87.164 on host app-1 after 2010-04-20?", use_llm=False)
    assert d.route == Route.EVIDENCE_ONLY
    assert d.filters.ip == "190.166.87.164" and d.filters.host == "app-1"
    assert d.filters.ts_from.isoformat().startswith("2010-04-20")
    assert decide("anything", route="evidence+attack", use_llm=False).reason == "explicit"


def test_router_aggregate_flag():
    d = decide("Count the total number of lines of www-access.log file of the apache server", use_llm=False)
    assert d.aggregate and d.route == Route.EVIDENCE_ONLY and "timeline query" in d.reason
    assert decide("Which external IP addresses successfully logged in as root via SSH?", use_llm=False).aggregate
    assert decide("How many failed SSH logins were there?", use_llm=False).aggregate
    assert not decide("When was the account dhg created and by which process?", use_llm=False).aggregate
    assert not decide("What is T1078.002?", use_llm=False).aggregate


def test_filter_extraction():
    f = extract_filters("show sudo commands by user wind3str0y between 2010-04-25 and 2010-04-27")
    assert f.user == "wind3str0y" and f.ts_from.day == 25 and f.ts_to.day == 27
    assert extract_filters("does T1059.004 apply?").ids == ["T1059.004"]
    # ordinary English after "user"/"account" is not a username
    assert extract_filters("Which user accounts were created with UID 0 and when?").user is None
    assert extract_filters("was the account created by useradd?").user is None
    assert extract_filters("What did the account user1 do from 76.191.195.140?").user == "user1"
    assert extract_filters("From which IP address did the user dhg log in over SSH?").user == "dhg"


def test_citation_validation():
    v = validate("root logged in [E1] and used sudo [E2]; matches [T1078.002] and [E9].", {"E1", "E2", "T1078.002"})
    assert v.valid == ["E1", "E2", "T1078.002"] and v.invalid == ["E9"]
    assert "[E9?invalid]" in v.answer
    v = validate("365 lines [S1], e.g. [E1]; [R1] is gone.", {"S1", "E1"})
    assert v.valid == ["S1", "E1"] and v.invalid == [] and "[R1]" in v.answer  # [R#] is no longer a citation label
    # an ATT&CK id without an ATT&CK entry in context is model knowledge, marked but not "invented evidence"
    v = validate("created a UID 0 account [E1], likely [T1136.001].", {"E1"})
    assert v.valid == ["E1"] and v.invalid == [] and v.unverified_attack == ["T1136.001"]
    assert "[T1136.001?unverified]" in v.answer


def test_collapse_duplicates_keeps_the_odd_line_out():
    from dfa.retrieval.retriever import Hit, collapse_duplicates

    def hit(i, text, score):
        return Hit(id=str(i), collection="case_c", text=text, payload={"granularity": "event"}, score=score)

    probes = [hit(i, f'123.4.59.{i} - - [19/Apr/2010:08:{i:02d}:30 -0700] "GET http://proxyjudge1.proxyfire.net/fastenv HTTP/1.1" 404 1466', 1.0 - i / 100) for i in range(15)]
    odd = hit(99, '193.109.122.56 - - [20/Apr/2010:00:00:01 -0700] "CONNECT 72.51.18.254:6677 HTTP/1.0" 301 - "pxyscand/2.1"', 0.5)
    out = collapse_duplicates(probes + [odd], 3)
    assert len(out) == 4 and out[-1] is odd and [h.id for h in out[:3]] == ["0", "1", "2"]
    assert len(collapse_duplicates(probes, 0)) == 15  # disabled
    window = Hit(id="w", collection="case_c", text=probes[0].text, payload={"granularity": "window"}, score=0.9)
    assert window in collapse_duplicates(probes + [window], 1)  # windows are never collapsed against events


def test_lineage_questions_get_a_timeline_query():
    from dfa.router.router import is_aggregate

    assert is_aggregate("What is the creation date and time of the parent process of powershell.exe?")
    assert is_aggregate("Which process is the parent of cmd.exe and what is its start time?")
    assert not is_aggregate("Is powershell.exe suspicious here?")
