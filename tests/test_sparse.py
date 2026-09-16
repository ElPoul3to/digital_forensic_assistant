from dfa.retrieval.sparse import encode, tokenize


def test_tokenize_keeps_iocs_and_subtokens():
    toks = tokenize("Accepted password for root from 190.166.87.164 port 41113 ssh2")
    assert "190.166.87.164" in toks
    assert "190" in toks and "164" in toks
    assert "root" in toks
    assert "for" not in toks


def test_encode_is_deterministic():
    a = encode("sudo: user3 : COMMAND=/bin/su")
    b = encode("sudo: user3 : COMMAND=/bin/su")
    assert a == b and a[0]
