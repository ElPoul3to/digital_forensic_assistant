"""PCAP / PCAPNG: protocol events (DNS, HTTP requests and responses, TLS SNI, SMB)
and per-flow summaries.  Raw packets are never indexed; flows are aggregated into
one event each with first/last seen, packet and byte counts.

HTTP responses are reassembled per TCP flow (Content-Length / chunked / until
FIN), decompressed (gzip, deflate) and characterised: scripts, obfuscated
JavaScript, shellcode patterns, heap spray, hidden iframes, executables, PDFs,
Java / Flash.  The event's record reference is the frame where the response
completed, which is the packet number Wireshark shows for it.

Payload content is indexed too, so what is *inside* the data is searchable:
- ``http_body`` events: text bodies are split into segments; binary bodies
  (executables, archives, ...) yield their notable printable strings (compiler
  banners, paths, URLs, DLL / API names, registry keys, ...), like ``strings``.
- ``tcp_data`` / ``udp_data`` events: payloads of packets no protocol handler
  claimed (IRC, custom C2, plain-text protocols), capped per flow.
- POST bodies are previewed on the request event.

Active Directory traffic and traffic patterns (see ``pcap_ad.py``):
- Kerberos AS/TGS requests and replies, AP-REQ and KRB-ERROR as
  ``krb_*`` events (who, service, encryption types, pre-auth, error names)
  with flags for the usual abuses (RC4-only service requests, no pre-auth,
  bad password / unknown user errors).
- LDAP binds, searches (filter rendered, reconnaissance filters flagged),
  result counts, modify / add / delete requests as ``ldap_*`` events.
- ``beacon_candidate`` events for regular connection / request / DNS series.
- ``rare_domain`` events for names queried by a single client a few times,
  DGA-looking names and tunnelling-shaped names.
"""

from __future__ import annotations

import logging
import re
import zlib
from collections.abc import Iterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from dfa.ingestion import ioc
from dfa.ingestion.parsers import pcap_ad as ad
from dfa.ingestion.parsers.base import ParseContext, register
from dfa.ingestion.schema import IOC, Category, Event, Source

log = logging.getLogger(__name__)
_PORT_NAMES = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http", 88: "kerberos", 110: "pop3", 135: "msrpc",
               139: "netbios", 143: "imap", 389: "ldap", 443: "https", 445: "smb", 464: "kpasswd", 587: "smtp", 636: "ldaps", 3268: "ldap-gc", 3269: "ldaps-gc",
               993: "imaps", 1080: "socks", 1433: "mssql", 3128: "proxy", 3306: "mysql", 3389: "rdp", 4444: "metasploit?",
               5900: "vnc", 5985: "winrm", 5986: "winrms", 6660: "irc", 6661: "irc", 6662: "irc", 6663: "irc", 6664: "irc", 6665: "irc",
               6666: "irc", 6667: "irc", 6668: "irc", 6669: "irc", 6697: "ircs", 8000: "http-alt", 8080: "http-alt", 8443: "https-alt",
               8888: "http-alt", 9001: "tor"}


@dataclass
class Flow:
    first: float
    last: float
    packets: int = 0
    bytes: int = 0
    flags: set[str] = field(default_factory=set)


def _first(x):
    """scapy >= 2.6 exposes qd/an as lists; older versions as a packet chain."""
    if x is None:
        return None
    if isinstance(x, list):
        return x[0] if x else None
    return x


def _rrs(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    out = []
    rr = x
    while rr is not None and rr.name == "DNSRR":
        out.append(rr)
        rr = rr.payload if rr.payload else None
    return out


def _qname(q) -> str:
    name = getattr(q, "qname", b"")
    return (name.decode(errors="replace") if isinstance(name, bytes) else str(name)).rstrip(".")


def _ts(t: float) -> datetime:
    return datetime.fromtimestamp(float(t), tz=UTC)


_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ", b"CONNECT ", b"PROPFIND ")
_SHELLCODE = re.compile(rb"(?:%u[0-9a-fA-F]{4}){8,}|(?:\\x[0-9a-fA-F]{2}){16,}|\x90{16,}")
_OBFUSCATED = re.compile(rb"unescape\s*\(|fromCharCode|\beval\s*\(|charCodeAt|\.replace\s*\(\s*/|String\.fromCharCode|document\.write\s*\(\s*unescape", re.IGNORECASE)
_HEAP_SPRAY = re.compile(rb"0x0[cd]0[cd]0[cd]0[cd]|%u0[cd]0[cd]%u0[cd]0[cd]|spray", re.IGNORECASE)
_HIDDEN_IFRAME = re.compile(rb"<iframe[^>]*(?:width\s*=\s*[\"']?0|height\s*=\s*[\"']?0|visibility\s*:\s*hidden|display\s*:\s*none)", re.IGNORECASE)
_ACTIVEX = re.compile(rb"ActiveXObject|classid\s*=|<object[^>]*clsid", re.IGNORECASE)
_TITLE = re.compile(rb"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_MAX_BODY = 1 << 20  # bytes kept per response for characterisation
_BODY_PARTS = 8  # max http_body events per response
_PART_CHARS = 900  # characters per http_body event
_DATA_PER_FLOW = 30  # max tcp_data / udp_data events per flow
_MIN_STRING = 6
_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % _MIN_STRING)
_UTF16_RUN = re.compile(rb"(?:[\x20-\x7e]\x00){%d,}" % _MIN_STRING)
_NOTABLE = re.compile(
    r"gcc|mingw|msvc|visual c|borland|delphi|\.pdb\b|compiled|copyright|version|product|company|"
    r"https?://|www\.|ftp://|\b\d{1,3}(?:\.\d{1,3}){3}\b|[a-z0-9-]+\.(?:com|net|org|ru|cn|info|biz|io)\b|"
    r"[a-z]:\\|\\\\|/(?:bin|etc|tmp|home|usr|var|opt)/|hkey_|software\\|currentversion|\.(?:dll|exe|sys|bat|ps1|vbs|jar|dat|cfg|ini)\b|"
    r"cmd\.exe|powershell|wscript|cscript|rundll32|regsvr32|schtasks|netsh|bitsadmin|certutil|"
    r"createremotethread|virtualalloc|writeprocessmemory|urldownloadtofile|internetopen|winexec|shellexecute|"
    r"getprocaddress|loadlibrary|wsastartup|connect|recv|send|socket|password|passwd|login|user|admin|"
    r"\bkey\b|\bbot\b|irc|nick|join|privmsg|mutex|inject|payload|shell|download|upload|mailto:|\w+@\w+\.\w+",
    re.IGNORECASE,
)
_TEXT_CT = ("text/", "javascript", "json", "xml", "html", "x-www-form-urlencoded")


def _strings(data: bytes, limit: int = 4000) -> list[str]:
    """Printable ASCII and UTF-16LE runs, in file order, de-duplicated."""
    found: list[tuple[int, str]] = [(m.start(), m.group().decode("ascii")) for m in _ASCII_RUN.finditer(data)]
    found += [(m.start(), m.group().decode("utf-16le", errors="replace")) for m in _UTF16_RUN.finditer(data)]
    found.sort()
    out, seen = [], set()
    for _, t in found:
        t = t.strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)
            if len(out) >= limit:
                break
    return out


def _notable_first(strs: list[str]) -> list[str]:
    """Strings an analyst greps for first, then the rest by length."""
    hot = [t for t in strs if _NOTABLE.search(t)]
    rest = sorted((t for t in strs if t not in set(hot)), key=len, reverse=True)
    return hot + rest


def _is_text(data: bytes, content_type: str) -> bool:
    if any(k in content_type.lower() for k in _TEXT_CT):
        return True
    sample = data[:4000]
    return bool(sample) and sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13)) / len(sample) > 0.9


def _segments(text: str, size: int, max_parts: int) -> list[str]:
    text = re.sub(r"\s+", " ", text).strip()
    return [text[i:i + size] for i in range(0, min(len(text), size * max_parts), size)]


def _body_parts(body: bytes, content_type: str, flags: list[str]) -> tuple[str, list[str]]:
    """(kind, parts) — text segments for text bodies, notable strings for binary ones."""
    if _is_text(body, content_type):
        return "text", _segments(body.decode(errors="replace"), _PART_CHARS, _BODY_PARTS)
    strs = _notable_first(_strings(body))
    if not strs:
        return "binary", []
    kind = next((f for f in flags if f in ("pe_file", "pdf", "jar_zip", "flash", "java_class")), "binary")
    return kind, _segments(" | ".join(strs), _PART_CHARS, _BODY_PARTS)


@dataclass
class _Response:
    first_frame: int
    ts: float
    status: int
    reason: str
    headers: dict[str, str]
    body: bytearray
    content_length: int | None
    chunked: bool
    request: dict | None  # the request this answers (frame, method, uri, host)
    server: str
    client: str
    port: int
    seen: int = 0  # body bytes seen (may exceed len(body) once capped)

    def complete(self) -> bool:
        if self.status in (204, 304) or 100 <= self.status < 200:
            return True
        if self.content_length is not None:
            return self.seen >= self.content_length
        if self.chunked:
            return self.body.endswith(b"0\r\n\r\n") or b"\r\n0\r\n\r\n" in self.body[-16:]
        return False  # until FIN / next message / end of capture


def _parse_headers(head: bytes) -> tuple[bytes, dict[str, str]]:
    lines = head.split(b"\r\n")
    hdrs: dict[str, str] = {}
    for line in lines[1:]:
        k, _, v = line.partition(b":")
        if _:
            hdrs[k.strip().lower().decode(errors="replace")] = v.strip().decode(errors="replace")
    return lines[0], hdrs


def _dechunk(body: bytes) -> bytes:
    out, pos = bytearray(), 0
    while pos < len(body):
        end = body.find(b"\r\n", pos)
        if end < 0:
            break
        try:
            n = int(body[pos:end].split(b";")[0].strip() or b"0", 16)
        except ValueError:
            break
        if n == 0:
            break
        out += body[end + 2:end + 2 + n]
        pos = end + 2 + n + 2
    return bytes(out) or body


def _decode_body(body: bytes, headers: dict[str, str], chunked: bool) -> tuple[bytes, bool]:
    """Undo chunking and gzip / deflate; tolerant of truncated data. Returns (bytes, decoded_ok)."""
    if chunked:
        body = _dechunk(body)
    enc = headers.get("content-encoding", "").lower()
    if "gzip" in enc or "deflate" in enc:
        for wbits in ((16 + zlib.MAX_WBITS,) if "gzip" in enc else (zlib.MAX_WBITS, -zlib.MAX_WBITS)):
            try:
                return zlib.decompressobj(wbits).decompress(body), True
            except zlib.error:
                continue
        return body, False
    return body, True


# Not exhaustive
def _characterise(body: bytes, content_type: str, status: int, headers: dict[str, str]) -> tuple[list[str], str, dict]:
    """Flags and a short printable preview of a response body."""
    flags: list[str] = []
    ct = content_type.lower()
    low = body[:_MAX_BODY].lower()
    if 300 <= status < 400 and headers.get("location"):
        flags.append("redirect")
    if not body:
        if status not in (204, 304) and not (100 <= status < 200) and "redirect" not in flags:
            flags.append("empty_body")
    else:
        if body[:2] == b"MZ":
            flags.append("pe_file")
        elif body[:4] == b"%PDF":
            flags.append("pdf")
        elif body[:4] == b"PK\x03\x04":
            flags.append("jar_zip")
        elif body[:3] in (b"CWS", b"FWS", b"ZWS"):
            flags.append("flash")
        elif body[:4] == b"\xca\xfe\xba\xbe":
            flags.append("java_class")
        n_script = low.count(b"<script")
        if n_script:
            flags.append("script")
        if _OBFUSCATED.search(body):
            flags.append("obfuscated_js")
        if _SHELLCODE.search(body):
            flags.append("shellcode")
        if _HEAP_SPRAY.search(body):
            flags.append("heap_spray")
        if b"<iframe" in low:
            flags.append("hidden_iframe" if _HIDDEN_IFRAME.search(body) else "iframe")
        if b"<applet" in low or b"application/x-java" in low or b".jar" in low:
            flags.append("java_applet")
        if _ACTIVEX.search(body):
            flags.append("activex")
        if b"<embed" in low or b"application/x-shockwave-flash" in low or b".swf" in low:
            flags.append("flash_embed")
        if b"<object" in low and "activex" not in flags:
            flags.append("object_tag")
        if ("html" in ct or "javascript" in ct or ct.startswith("text/")) and n_script == 0 and "iframe" not in flags \
                and "hidden_iframe" not in flags and "object_tag" not in flags and "activex" not in flags and "obfuscated_js" not in flags:
            flags.append("no_script")  # plain content: no script, iframe, object or obfuscation
    details: dict = {}
    if m := _TITLE.search(body[:20000]):
        details["title"] = re.sub(rb"\s+", b" ", m.group(1)).strip().decode(errors="replace")[:100]
    text = re.sub(rb"<[^>]{0,200}>", b" ", body[:4000]) if "html" in ct else body[:4000]
    text = re.sub(rb"[^\x20-\x7e]+", b" ", text)
    preview = re.sub(rb"\s+", b" ", text).strip().decode(errors="replace")[:160]
    return flags, preview, details


def _mk(ctx: ParseContext, path: Path, ref: str, ts: datetime | None, cat: Category, action: str, summary: str,
        raw: str, ips: list[str], extra: dict | None = None) -> Event:
    ev_ioc: IOC = ioc.extract(summary)
    for ip in ips:
        if ip and ip not in ev_ioc.ip:
            ev_ioc.ip.append(ip)
    return Event(case_id=ctx.case_id, timestamp=ts, source=Source.PCAP, source_file=path.name, record_ref=ref,
                 host=ctx.host_hint, category=cat, action=action, ioc=ev_ioc, summary=summary[:1000], raw=raw[:2000], extra=extra or {})


class PcapParser:
    kinds = ("pcap", "pcapng")

    def parse(self, path: Path, ctx: ParseContext) -> Iterator[Event]:
        from scapy.all import DNS, IP, TCP, UDP, PcapReader, Raw
        from scapy.layers.inet6 import IPv6

        try:
            from scapy.layers.tls.extensions import ServerName  # noqa: F401
            from scapy.layers.tls.handshake import TLSClientHello
            tls_ok = True
        except Exception:  # noqa: BLE001
            tls_ok = False
            TLSClientHello = None
        try:
            from scapy.layers.kerberos import Kerberos
            krb_ok = True
        except Exception:  # noqa: BLE001
            krb_ok, Kerberos = False, None
        try:
            from scapy.layers.ldap import CLDAP, LDAP
            ldap_ok = True
        except Exception:  # noqa: BLE001
            ldap_ok, LDAP, CLDAP = False, None, None

        flows: dict[tuple, Flow] = {}
        last_request: dict[tuple, dict] = {}  # flow key -> last HTTP request seen (frame, method, uri, host)
        pending: dict[tuple, _Response] = {}  # flow key -> HTTP response being reassembled
        http_server: dict[tuple, str] = {}  # flow key -> IP that received an HTTP request (the port heuristic can be wrong)
        data_count: dict[tuple, int] = {}  # flow key -> tcp_data / udp_data events emitted
        flow_keys: dict[tuple, tuple] = {}  # (proto, unordered endpoints) -> canonical (proto, server, sport, client, cport)
        series: dict[tuple[str, str, str], list[float]] = {}  # (kind, client, target) -> timestamps, for beacon detection
        domains: dict[str, ad.DomainStats] = {}  # registered domain -> DNS stats, for rare-domain detection
        krb_user: dict[str, str] = {}  # client IP -> last principal seen in an AS exchange (TGS-REQs do not name the user)
        ldap_bound: dict[tuple, str] = {}  # flow key -> DN of the last successful bind
        ldap_binding: dict[tuple, str] = {}  # flow key -> DN of the bind awaiting its result
        ldap_searches: dict[tuple, dict] = {}  # (flow key, messageID) -> search request + entry counter
        frame = 0

        def series_add(kind: str, client: str, target: str, t: float) -> None:
            series.setdefault((kind, client, target), []).append(t)

        def dom_stats(qname: str, t: float) -> ad.DomainStats:
            reg = ad.registered_domain(qname)
            d = domains.get(reg)
            if d is None:
                d = domains[reg] = ad.DomainStats(domain=reg, first=t, last=t)
            d.last = max(d.last, t)
            return d

        def finish(key: tuple, at_frame: int) -> list[Event]:
            r = pending.pop(key)
            body, decoded = _decode_body(bytes(r.body), r.headers, r.chunked)
            ctype = r.headers.get("content-type", "")
            flags, preview, details = _characterise(body, ctype, r.status, r.headers)
            if r.content_length is not None and r.seen < r.content_length:
                flags.append("truncated")
            if not decoded:
                flags.append("undecodable")
            req = r.request or {}
            what = f"{req.get('method', '?')} {req.get('uri', '?')}" if req else "unknown request"
            host = req.get("host") or ""
            frames = f"frame {r.first_frame}" if r.first_frame == at_frame else f"frames {r.first_frame}-{at_frame}"
            summary = (f"HTTP response {r.status} {r.reason} (packet {at_frame}) for {what}" + (f" host={host}" if host else "")
                       + f" ({ctype or 'no content-type'}; {r.seen} bytes" + (f", {len(body)} decoded" if len(body) != r.seen else "") + ")"
                       + f" from {r.server}:{r.port} to {r.client}" + (f" [{' '.join(flags)}]" if flags else "")
                       + (f" title=\"{details['title']}\"" if details.get("title") else "")
                       + (f" body: {preview}" if preview else ""))
            raw = (f"{frames}\nHTTP/1.x {r.status} {r.reason}\n" + "\n".join(f"{k}: {v}" for k, v in list(r.headers.items())[:25])
                   + "\n\n" + body[:1200].decode(errors="replace"))
            ext = {"status": r.status, "content_type": ctype, "content_length": r.content_length, "bytes": r.seen,
                   "decoded_bytes": len(body), "flags": flags, "first_frame": r.first_frame, "last_frame": at_frame,
                   "request_frame": req.get("frame"), "method": req.get("method"), "uri": req.get("uri"), "host": host,
                   "server_header": r.headers.get("server"), "location": r.headers.get("location"), **details}
            events = [_mk(ctx, path, f"frame {at_frame}", _ts(r.ts), Category.WEB, "http_response", summary, raw, [r.server, r.client], ext)]
            if len(body) > 200 or (body and "text" not in (ctype or "").lower()):
                kind, parts = _body_parts(body, ctype, flags)
                for i, part in enumerate(parts, 1):
                    label = "strings in" if kind not in ("text",) else "content of"
                    bsum = (f"HTTP response body: {label} the {kind.replace('_', ' ')} {what} (packet {at_frame}, part {i}/{len(parts)}, "
                            f"{ctype or 'unknown type'}, {len(body)} bytes" + (f", host {host}" if host else "") + f", server {r.server}): {part}")
                    events.append(_mk(ctx, path, f"frame {at_frame} body {i}/{len(parts)}", _ts(r.ts), Category.WEB, "http_body",
                                      bsum, part, [r.server, r.client],
                                      {"response_frame": at_frame, "request_frame": req.get("frame"), "uri": req.get("uri"), "host": host,
                                       "content_type": ctype, "kind": kind, "part": i, "parts": len(parts), "flags": flags}))
            return events

        with PcapReader(str(path)) as reader:
            for pkt in reader:
                frame += 1
                ipl = pkt.getlayer(IP) or pkt.getlayer(IPv6)
                if ipl is None:
                    continue
                src, dst = ipl.src, ipl.dst
                t = float(pkt.time)
                proto, sport, dport = "ip", 0, 0
                if pkt.haslayer(TCP):
                    proto, sport, dport = "tcp", pkt[TCP].sport, pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    proto, sport, dport = "udp", pkt[UDP].sport, pkt[UDP].dport
                # canonical flow key: which side is the server? SYN direction > well-known port > lower port
                pair = (proto, frozenset(((src, sport), (dst, dport))))
                key = flow_keys.get(pair)
                if key is None:
                    tcp_flags = int(pkt[TCP].flags) if proto == "tcp" else 0
                    if proto == "tcp" and tcp_flags & 0x02 and not tcp_flags & 0x10:
                        srv_side = True  # SYN goes to the server
                    elif (dport in _PORT_NAMES) != (sport in _PORT_NAMES):
                        srv_side = dport in _PORT_NAMES
                    else:
                        srv_side = dport <= sport
                    key = (proto, dst, dport, src, sport) if srv_side else (proto, src, sport, dst, dport)
                    flow_keys[pair] = key
                fl = flows.get(key)
                if fl is None:
                    fl = flows[key] = Flow(first=t, last=t)
                fl.last = max(fl.last, t)
                fl.packets += 1
                fl.bytes += len(pkt)
                if proto == "tcp":
                    f = pkt[TCP].flags
                    if f & 0x02 and not f & 0x10:
                        fl.flags.add("SYN")
                        series_add("tcp_connect", src, f"{dst}:{dport}", t)
                    if f & 0x04:
                        fl.flags.add("RST")
                    if (f & 0x01 or f & 0x04) and key in pending and src == http_server.get(key, key[1]):  # server closed
                        yield from finish(key, frame)

                # --- HTTP (any port, sniffed on payload) ---
                if proto == "tcp" and pkt.haslayer(Raw):
                    payload = bytes(pkt[Raw].load)
                    if payload[:9].startswith(_METHODS):
                        http_server[key] = dst
                        if key in pending:  # a new request ends a response without length
                            yield from finish(key, frame)
                        head = payload[:2000]
                        first = head.split(b"\r\n", 1)[0]
                        host = ua = referer = ""
                        for line in head.split(b"\r\n")[1:40]:
                            low = line.lower()
                            if low.startswith(b"host:"):
                                host = line[5:].strip().decode(errors="replace")
                            elif low.startswith(b"user-agent:"):
                                ua = line[11:].strip().decode(errors="replace")
                            elif low.startswith(b"referer:"):
                                referer = line[8:].strip().decode(errors="replace")
                        parts = first.decode(errors="replace").split(" ")
                        method, uri = (parts[0], parts[1]) if len(parts) >= 2 else (parts[0], "")
                        last_request[key] = {"frame": frame, "method": method, "uri": uri, "host": host}
                        series_add("http_request", src, host or f"{dst}:{dport}", t)
                        _, _, req_body = payload.partition(b"\r\n\r\n")
                        body_preview = re.sub(r"\s+", " ", req_body[:2000].decode(errors="replace")).strip()[:300] if req_body else ""
                        yield _mk(ctx, path, f"frame {frame}", _ts(t), Category.WEB, "http_request",
                                  f"HTTP {first.decode(errors='replace')} (packet {frame}) host={host} from {src} to {dst}:{dport} UA=\"{ua[:100]}\""
                                  + (f" referer={referer[:120]}" if referer else "") + (f" body: {body_preview}" if body_preview else ""),
                                  payload[:600].decode(errors="replace"), [src, dst],
                                  {"host": host, "ua": ua, "method": method, "uri": uri, "referer": referer, "frame": frame,
                                   "body_bytes": len(req_body)})
                        continue
                    if src == http_server.get(key, key[1]):  # server -> client
                        if payload.startswith(b"HTTP/1."):
                            if key in pending:
                                yield from finish(key, frame)
                            head, _, rest = payload.partition(b"\r\n\r\n")
                            status_line, hdrs = _parse_headers(head)
                            parts = status_line.decode(errors="replace").split(" ", 2)
                            try:
                                status = int(parts[1])
                            except (IndexError, ValueError):
                                status = 0
                            cl = hdrs.get("content-length")
                            r = _Response(first_frame=frame, ts=t, status=status, reason=parts[2] if len(parts) > 2 else "",
                                          headers=hdrs, body=bytearray(), content_length=int(cl) if cl and cl.isdigit() else None,
                                          chunked="chunked" in hdrs.get("transfer-encoding", "").lower(),
                                          request=last_request.get(key), server=src, client=dst, port=sport)
                            pending[key] = r
                            if rest:
                                r.body += rest[:_MAX_BODY]
                                r.seen += len(rest)
                            if r.complete():
                                yield from finish(key, frame)
                            continue
                        if key in pending:
                            r = pending[key]
                            if len(r.body) < _MAX_BODY:
                                r.body += payload[:_MAX_BODY - len(r.body)]
                            r.seen += len(payload)
                            if r.complete():
                                yield from finish(key, frame)
                            continue

                # --- protocol events ---
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0 and _first(pkt[DNS].qd) is not None:
                    qname = _qname(_first(pkt[DNS].qd))
                    series_add("dns_query", src, qname, t)
                    d = dom_stats(qname, t)
                    d.queries += 1
                    d.clients.add(src)
                    d.fqdns.add(qname)
                    yield _mk(ctx, path, f"frame {frame}", _ts(t), Category.NETWORK, "dns_query",
                              f"DNS query {qname} from {src} to {dst}", pkt.summary(), [src, dst], {"qname": qname})
                elif pkt.haslayer(DNS) and pkt[DNS].qr == 1 and _first(pkt[DNS].qd) is not None and int(pkt[DNS].rcode) == 3:
                    qname = _qname(_first(pkt[DNS].qd))
                    d = dom_stats(qname, t)
                    d.nxdomain += 1
                    d.fqdns.add(qname)
                    yield _mk(ctx, path, f"frame {frame}", _ts(t), Category.NETWORK, "dns_response",
                              f"DNS response NXDOMAIN for {qname} to {dst}", pkt.summary(), [dst], {"qname": qname, "answers": [], "rcode": 3})
                elif pkt.haslayer(DNS) and pkt[DNS].qr == 1 and _first(pkt[DNS].an) is not None:
                    answers = []
                    for rr in _rrs(pkt[DNS].an):
                        rd = getattr(rr, "rdata", None)
                        if rd is not None:
                            answers.append(rd.decode(errors="replace").rstrip(".") if isinstance(rd, bytes) else str(rd))
                        if len(answers) >= 8:
                            break
                    q = _first(pkt[DNS].qd)
                    qname = _qname(q) if q is not None else "?"
                    if q is not None:
                        d = dom_stats(qname, t)
                        d.fqdns.add(qname)
                        d.answers.update(a for a in answers if a.replace(".", "").isdigit())
                    yield _mk(ctx, path, f"frame {frame}", _ts(t), Category.NETWORK, "dns_response",
                              f"DNS response {qname} -> {', '.join(answers)} to {dst}", pkt.summary(), [dst] + [a for a in answers if a.replace('.', '').isdigit()], {"qname": qname, "answers": answers})
                if proto == "tcp" and pkt.haslayer(Raw) and key in pending:
                    continue  # part of a response being reassembled
                if tls_ok and proto == "tcp" and pkt.haslayer(TLSClientHello):
                    sni = None
                    for ext in getattr(pkt[TLSClientHello], "ext", None) or []:
                        if ext.name == "TLS Extension - Server Name" and getattr(ext, "servernames", None):
                            sni = ext.servernames[0].servername.decode(errors="replace")
                    series_add("tls_client_hello", src, sni or f"{dst}:{dport}", t)
                    yield _mk(ctx, path, f"frame {frame}", _ts(t), Category.NETWORK, "tls_client_hello",
                              f"TLS ClientHello SNI={sni or '?'} from {src} to {dst}:{dport}", pkt.summary(), [src, dst], {"sni": sni})
                elif krb_ok and pkt.haslayer(Kerberos):
                    info = ad.decode_kerberos(pkt[Kerberos])
                    if info is None:
                        continue
                    client = dst if info.kind in ("AS-REP", "TGS-REP", "ERROR") else src
                    if info.user:
                        krb_user[client] = info.user
                    user = info.user or krb_user.get(client, "")
                    summary = ad.krb_summary(info, src, dst, frame)
                    if not info.user and user and info.kind in ("TGS-REQ", "AP-REQ"):
                        summary += f" (client last authenticated as {user})"
                    ev = _mk(ctx, path, f"frame {frame}", _ts(t), Category.AUTHENTICATION, info.action, summary, pkt.summary(), [src, dst],
                             {"kind": info.kind, "user": info.user, "realm": info.realm, "service": info.service, "etypes": info.etypes,
                              "ticket_etype": info.ticket_etype, "padata": info.padata, "error_code": info.error_code,
                              "error_name": info.error_name, "flags": info.flags, "client": client, "kdc": src if client == dst else dst})
                    ev.user = user or None
                    if user and user not in ev.ioc.user:
                        ev.ioc.user.append(user)
                    yield ev
                elif ldap_ok and (pkt.haslayer(LDAP) or pkt.haslayer(CLDAP)):
                    layer = pkt[LDAP] if pkt.haslayer(LDAP) else pkt[CLDAP]
                    for msg in ad.iter_ldap_messages(layer):
                        info = ad.decode_ldap(msg)
                        if info is None:
                            continue
                        bound = ldap_bound.get(key, "")
                        if info.op == "bind":
                            ldap_binding[key] = info.user
                        elif info.op == "bind_result":
                            bound = ldap_binding.get(key, bound)
                            if info.result_code == 0:
                                ldap_bound[key] = bound
                        elif info.op == "search":
                            ldap_searches[(key, info.message_id)] = {"info": info, "entries": 0, "sample": [], "frame": frame}
                            if len(ldap_searches) > 5000:
                                ldap_searches.pop(next(iter(ldap_searches)))
                        elif info.op == "search_entry":
                            s_ = ldap_searches.get((key, info.message_id))
                            if s_ is not None:
                                s_["entries"] += 1
                                if len(s_["sample"]) < 5 and info.object:
                                    s_["sample"].append(info.object)
                            continue  # counted on the search result, not one event per entry
                        elif info.op == "search_done":
                            s_ = ldap_searches.pop((key, info.message_id), None)
                            if s_ is not None:
                                req = s_["info"]
                                info.base, info.filter = req.base, req.filter
                                info.flags = list(req.flags) + info.flags
                                info.changes = [f"entries={s_['entries']}"] + ([f"e.g. {'; '.join(s_['sample'])}"] if s_["sample"] else [])
                                info.attributes = [f"request_frame={s_['frame']}"]
                        summary = ad.ldap_summary(info, src, dst, frame, bound)
                        cat = Category.AUTHENTICATION if info.op in ("bind", "bind_result") else (
                            Category.USER_MGMT if info.op in ("modify", "add", "delete", "modify_dn") else Category.NETWORK)
                        user = info.user if info.op == "bind" else bound
                        ev = _mk(ctx, path, f"frame {frame}", _ts(t), cat, info.action, summary, pkt.summary(), [src, dst],
                                 {"op": info.op, "message_id": info.message_id, "bind_dn": info.user, "auth": info.auth,
                                  "base": info.base, "scope": info.scope, "filter": info.filter, "attributes": info.attributes,
                                  "object": info.object, "changes": info.changes, "result_code": info.result_code,
                                  "result_name": info.result_name, "flags": info.flags, "bound_as": bound})
                        ev.user = user or None
                        if user and user not in ev.ioc.user:
                            ev.ioc.user.append(user)
                        yield ev
                elif pkt.haslayer(Raw) and proto == "tcp" and dport == 445 and b"\xfeSMB" in bytes(pkt[Raw].load[:8]):
                    cmd = bytes(pkt[Raw].load)[16:18] if len(pkt[Raw].load) > 18 else b""
                    yield _mk(ctx, path, f"frame {frame}", _ts(t), Category.NETWORK, "smb_request",
                              f"SMB2 request cmd=0x{cmd.hex()} from {src} to {dst}", pkt.summary(), [src, dst])
                elif pkt.haslayer(Raw) and proto in ("tcp", "udp") and not pkt.haslayer(DNS) and not (tls_ok and pkt.haslayer(TLSClientHello)):
                    # Unclaimed payload ("Data" in Wireshark): index its content, capped per flow.
                    if data_count.get(key, 0) >= _DATA_PER_FLOW:
                        continue
                    payload = bytes(pkt[Raw].load)
                    if _is_text(payload, ""):
                        content = re.sub(r"\s+", " ", payload[:3000].decode(errors="replace")).strip()[:600]
                        kind = "text"
                    else:
                        strs = _notable_first(_strings(payload))
                        content = " | ".join(strs)[:600]
                        kind = "binary"
                    if len(content) < _MIN_STRING:
                        continue
                    data_count[key] = data_count.get(key, 0) + 1
                    svc = _PORT_NAMES.get(key[2], str(key[2]))
                    yield _mk(ctx, path, f"frame {frame}", _ts(t), Category.NETWORK, f"{proto}_data",
                              f"{proto.upper()} data (packet {frame}) {src}:{sport} -> {dst}:{dport} ({svc}) {len(payload)} bytes, {kind}: {content}",
                              payload[:1500].decode(errors="replace"), [src, dst],
                              {"bytes": len(payload), "kind": kind, "service": svc, "server": key[1], "server_port": key[2]})

        for key in list(pending):  # responses still open at the end of the capture
            yield from finish(key, frame)

        # --- traffic patterns: beaconing and rare domains ---
        for i, b in enumerate(ad.find_beacons(series), 1):
            target_ip = b.target.rsplit(":", 1)[0] if b.kind == "tcp_connect" else ""
            summary = (f"Possible beaconing: {b.client} -> {b.target} {b.label}: {b.count} {b.kind.replace('_', ' ')}s over "
                       f"{ad._human(b.span)}, median interval {b.median:.1f}s, jitter {b.jitter * 100:.0f}%, "
                       f"first {_ts(b.times[0]).isoformat()} last {_ts(b.times[-1]).isoformat()}")
            yield _mk(ctx, path, f"beacon {i}", _ts(b.times[0]), Category.NETWORK, "beacon_candidate", summary, summary,
                      [b.client] + ([target_ip] if target_ip else []),
                      {"kind": b.kind, "client": b.client, "target": b.target, "count": b.count, "median_interval_s": round(b.median, 2),
                       "jitter": round(b.jitter, 3), "span_s": round(b.span, 1), "score": round(b.score, 2),
                       "last_seen": _ts(b.times[-1]).isoformat()})
        all_clients = {c for d in domains.values() for c in d.clients}
        for i, (d, flags, score) in enumerate(ad.domain_report(domains, len(all_clients)), 1):
            names = sorted(d.fqdns)
            summary = (f"Domain {d.domain} [{' '.join(flags)}]: {d.queries} DNS quer{'y' if d.queries == 1 else 'ies'}"
                       + (f", {d.nxdomain} NXDOMAIN" if d.nxdomain else "")
                       + f" from {', '.join(sorted(d.clients)[:5])}" + (f" and {len(d.clients) - 5} more" if len(d.clients) > 5 else "")
                       + f", {len(names)} name{'s' if len(names) != 1 else ''} ({', '.join(names[:5])}{', ...' if len(names) > 5 else ''})"
                       + (f", resolved to {', '.join(sorted(d.answers)[:5])}" if d.answers else "")
                       + f", first {_ts(d.first).isoformat()} last {_ts(d.last).isoformat()}")
            yield _mk(ctx, path, f"domain {i}", _ts(d.first), Category.NETWORK, "rare_domain", summary, summary,
                      sorted(d.clients)[:5] + sorted(d.answers)[:5],
                      {"domain": d.domain, "flags": flags, "queries": d.queries, "nxdomain": d.nxdomain, "clients": sorted(d.clients)[:20],
                       "names": names[:50], "answers": sorted(d.answers)[:20], "score": score, "last_seen": _ts(d.last).isoformat()})

        # --- flow summaries ---
        for i, (key, fl) in enumerate(sorted(flows.items(), key=lambda kv: kv[1].first)):
            proto, server, sport, client, cport = key
            svc = _PORT_NAMES.get(sport, str(sport))
            dur = fl.last - fl.first
            flags = ",".join(sorted(fl.flags))
            summary = (f"Flow {proto} {client}:{cport} -> {server}:{sport} ({svc}) packets={fl.packets} bytes={fl.bytes} "
                       f"duration={dur:.1f}s" + (f" flags={flags}" if flags else ""))
            yield _mk(ctx, path, f"flow {i}", _ts(fl.first), Category.NETWORK, "flow", summary, summary, [client, server],
                      {"proto": proto, "server": server, "server_port": sport, "client": client, "packets": fl.packets,
                       "bytes": fl.bytes, "duration_s": round(dur, 3), "last_seen": _ts(fl.last).isoformat()})


register(PcapParser())
