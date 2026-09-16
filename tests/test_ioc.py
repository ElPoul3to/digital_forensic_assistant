from dfa.ingestion import ioc


def test_ipv4_versions_and_times_are_not_ips():
    r = ioc.extract("Version=4.0.0.0, Culture=neutral; msedge 114.0.1823.43 at 11:32:42; listen 0.0.0.0:443; peer 10.0.4.17")
    assert r.ip == ["0.0.0.0", "10.0.4.17"]
    assert ioc.extract("AutoLaunch/4.0.0.1/ and v1.0.0.1 and 2.0.0.0").ip == []
    assert ioc.extract(".NET Framework 4.6.0.0, product 6.2.1.0, 10.0.0.0, Assembly 3.5.30729.1").ip == []
    assert ioc.extract("resolvers 8.8.8.8 and 1.1.1.1 and 9.9.9.9").ip == ["8.8.8.8", "1.1.1.1", "9.9.9.9"]


def test_ipv6_forms():
    r = ioc.extract("from fe80::1 and 2001:db8::8a2e:370:7334 and 2001:0db8:0000:0000:0000:0000:0000:0001 via ::1")
    assert r.ip == ["fe80::1", "2001:db8::8a2e:370:7334", "2001:0db8:0000:0000:0000:0000:0000:0001", "::1"]
    # clock times, MAC addresses and GUID fragments are not IPv6
    assert ioc.extract("at 11:32:42 mac 00:11:22:33:44:55 id 53b39e88-18c4-11ea").ip == []


def test_domains_need_a_real_tld():
    r = ioc.extract("windows.backgroundtasks icon.png fiber.scheduler task.classid 1.0.mum app.service "
                    "evil.example.com dc01.acme.local update.microsoft.com c2.badguy.ru cdn.site.io")
    assert r.domain == ["evil.example.com", "dc01.acme.local", "update.microsoft.com", "c2.badguy.ru", "cdn.site.io"]


def test_hashes_need_entropy():
    r = ioc.extract("md5 00000000000000000000000000000000 blob 010200000000000f0300000001000000 "
                    "real fc265b143cb64f9fdb888e87090c6647")
    assert r.hash == ["fc265b143cb64f9fdb888e87090c6647"]
