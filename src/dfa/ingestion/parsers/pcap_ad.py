"""Active Directory protocols and traffic-pattern helpers for the PCAP parser.

- Kerberos (port 88, UDP and TCP): AS-REQ / AS-REP / TGS-REQ / TGS-REP / AP-REQ /
  KRB-ERROR decoded to who asked for what, with which encryption types and
  pre-authentication; flags for the classic abuses (no pre-auth, RC4-only
  service-ticket requests, RC4 service tickets, bad-password / unknown-user
  errors).
- LDAP (389 / 3268, CLDAP 389 UDP): binds (simple binds carry a clear-text
  password), searches with the filter rendered in LDAP syntax and flags for
  well-known reconnaissance filters, result counts, modify / add / delete
  requests with the attributes touched.
- Beaconing: connection, HTTP request, TLS and DNS time series per
  (client, destination) with a regular interval.
- Rare domains: DNS names seen from a single client only a few times,
  DGA-looking names and DNS-tunnelling-shaped names.

Only scapy objects are touched here; the caller (``pcap.py``) owns the packet
loop, flow keys and event construction.
"""

from __future__ import annotations

import itertools
import math
import re
import statistics
from collections import defaultdict
from dataclasses import dataclass, field

# --- Kerberos ---------------------------------------------------------------

KRB_ERRORS = {
    0: "KDC_ERR_NONE", 1: "KDC_ERR_NAME_EXP", 2: "KDC_ERR_SERVICE_EXP", 3: "KDC_ERR_BAD_PVNO", 6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN", 8: "KDC_ERR_PRINCIPAL_NOT_UNIQUE", 9: "KDC_ERR_NULL_KEY", 12: "KDC_ERR_POLICY",
    13: "KDC_ERR_BADOPTION", 14: "KDC_ERR_ETYPE_NOSUPP", 16: "KDC_ERR_PADATA_TYPE_NOSUPP", 18: "KDC_ERR_CLIENT_REVOKED",
    19: "KDC_ERR_SERVICE_REVOKED", 20: "KDC_ERR_TGT_REVOKED", 23: "KDC_ERR_KEY_EXPIRED", 24: "KDC_ERR_PREAUTH_FAILED",
    25: "KDC_ERR_PREAUTH_REQUIRED", 26: "KDC_ERR_SERVER_NOMATCH", 31: "KRB_AP_ERR_BAD_INTEGRITY", 32: "KRB_AP_ERR_TKT_EXPIRED",
    33: "KRB_AP_ERR_TKT_NYV", 34: "KRB_AP_ERR_REPEAT", 36: "KRB_AP_ERR_BADMATCH", 37: "KRB_AP_ERR_SKEW", 41: "KRB_AP_ERR_MODIFIED",
    52: "KRB_ERR_RESPONSE_TOO_BIG", 60: "KRB_ERR_GENERIC", 68: "KDC_ERR_WRONG_REALM",
}
# error code -> what an analyst reads into it
KRB_ERROR_FLAGS = {6: "unknown_user", 18: "account_disabled_or_locked", 23: "password_expired", 24: "bad_password",
                   25: "preauth_required", 37: "clock_skew", 68: "wrong_realm"}
ETYPES = {1: "DES-CBC-CRC", 3: "DES-CBC-MD5", 16: "DES3-CBC-SHA1", 17: "AES128", 18: "AES256", 19: "AES128-SHA256",
          20: "AES256-SHA384", 23: "RC4-HMAC", 24: "RC4-HMAC-EXP", 25: "CAMELLIA128", 26: "CAMELLIA256"}
PADATA = {1: "PA-TGS-REQ", 2: "PA-ENC-TIMESTAMP", 3: "PA-PW-SALT", 11: "PA-ETYPE-INFO", 16: "PA-PK-AS-REQ", 17: "PA-PK-AS-REP",
          19: "PA-ETYPE-INFO2", 128: "PA-PAC-REQUEST", 133: "PA-FX-COOKIE", 136: "PA-FX-FAST", 147: "PA-PAC-OPTIONS",
          149: "PA-KEY-LIST-REQ", 150: "PA-KEY-LIST-REP"}
_RC4 = {23, 24}
_WEAK = {1, 2, 3, 23, 24}


def _s(v) -> str:
    """ASN.1 string / int -> str."""
    if v is None:
        return ""
    v = getattr(v, "val", v)
    if isinstance(v, bytes):
        return v.decode(errors="replace")
    return str(v)


def _i(v) -> int | None:
    if v is None:
        return None
    v = getattr(v, "val", v)
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _principal(p) -> str:
    if p is None:
        return ""
    parts = [_s(x) for x in (getattr(p, "nameString", None) or [])]
    return "/".join(parts)


def _etype_names(etypes) -> list[str]:
    out = []
    for e in etypes or []:
        n = _i(e)
        out.append(ETYPES.get(n, str(n)))
    return out


@dataclass
class KrbInfo:
    kind: str  # AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ, ERROR, ?
    action: str
    user: str = ""  # client principal (cname), when the message carries one
    realm: str = ""
    service: str = ""  # sname of the request or of the ticket
    etypes: list[str] = field(default_factory=list)  # requested or used
    ticket_etype: str = ""
    padata: list[str] = field(default_factory=list)
    error_code: int | None = None
    error_name: str = ""
    error_text: str = ""
    flags: list[str] = field(default_factory=list)


def decode_kerberos(krb) -> KrbInfo | None:
    """Turn a scapy ``Kerberos`` layer into a KrbInfo, or None when unrecognised."""
    root = getattr(krb, "root", None)
    if root is None:
        return None
    name = type(root).__name__
    info: KrbInfo
    if name == "KRB_AS_REQ" or name == "KRB_TGS_REQ":
        body = getattr(root, "reqBody", None)
        kind = "AS-REQ" if name == "KRB_AS_REQ" else "TGS-REQ"
        info = KrbInfo(kind=kind, action="krb_as_req" if kind == "AS-REQ" else "krb_tgs_req")
        if body is not None:
            info.user = _principal(getattr(body, "cname", None))
            info.realm = _s(getattr(body, "realm", None))
            info.service = _principal(getattr(body, "sname", None))
            raw_etypes = [_i(e) for e in (getattr(body, "etype", None) or [])]
            info.etypes = _etype_names(raw_etypes)
        else:
            raw_etypes = []
        info.padata = [PADATA.get(_i(p.padataType), f"PA-{_i(p.padataType)}") for p in (getattr(root, "padata", None) or [])]
        if kind == "AS-REQ":
            if "PA-ENC-TIMESTAMP" not in info.padata and "PA-PK-AS-REQ" not in info.padata and "PA-FX-FAST" not in info.padata:
                info.flags.append("no_preauth")  # first probe of a normal logon, or an AS-REP roasting attempt
            if raw_etypes and all(e in _RC4 for e in raw_etypes):
                info.flags.append("rc4_only")
        else:
            svc_first = info.service.split("/", 1)[0].lower()
            if raw_etypes and all(e in _RC4 for e in raw_etypes) and svc_first != "krbtgt":
                info.flags.append("rc4_only_service_request")  # Kerberoasting tools ask for RC4 to get a crackable ticket
        return info
    if name == "KRB_AS_REP" or name == "KRB_TGS_REP":
        kind = "AS-REP" if name == "KRB_AS_REP" else "TGS-REP"
        info = KrbInfo(kind=kind, action="krb_as_rep" if kind == "AS-REP" else "krb_tgs_rep")
        info.user = _principal(getattr(root, "cname", None))
        info.realm = _s(getattr(root, "crealm", None))
        tkt = getattr(root, "ticket", None)
        if tkt is not None:
            info.service = _principal(getattr(tkt, "sname", None))
            enc = getattr(tkt, "encPart", None)
            te = _i(getattr(enc, "etype", None)) if enc is not None else None
            info.ticket_etype = ETYPES.get(te, str(te)) if te is not None else ""
            if te in _WEAK:
                info.flags.append("weak_ticket_etype" if kind == "AS-REP" else "rc4_service_ticket")
        enc = getattr(root, "encPart", None)
        se = _i(getattr(enc, "etype", None)) if enc is not None else None
        if se is not None:
            info.etypes = [ETYPES.get(se, str(se))]
        return info
    if name == "KRB_ERROR":
        info = KrbInfo(kind="ERROR", action="krb_error")
        info.error_code = _i(getattr(root, "errorCode", None))
        info.error_name = KRB_ERRORS.get(info.error_code, f"KRB_ERR_{info.error_code}")
        info.user = _principal(getattr(root, "cname", None))
        info.realm = _s(getattr(root, "crealm", None)) or _s(getattr(root, "realm", None))
        info.service = _principal(getattr(root, "sname", None))
        info.error_text = _s(getattr(root, "eText", None))
        fl = KRB_ERROR_FLAGS.get(info.error_code)
        if fl:
            info.flags.append(fl)
        return info
    if name == "KRB_AP_REQ":
        info = KrbInfo(kind="AP-REQ", action="krb_ap_req")
        tkt = getattr(root, "ticket", None)
        if tkt is not None:
            info.service = _principal(getattr(tkt, "sname", None))
            info.realm = _s(getattr(tkt, "realm", None))
            enc = getattr(tkt, "encPart", None)
            te = _i(getattr(enc, "etype", None)) if enc is not None else None
            info.ticket_etype = ETYPES.get(te, str(te)) if te is not None else ""
        return info
    return KrbInfo(kind=name.replace("KRB_", "").replace("_", "-"), action="krb_other")


def krb_summary(info: KrbInfo, src: str, dst: str, frame: int) -> str:
    who = f"{info.user}@{info.realm}" if info.user and info.realm else (info.user or info.realm or "?")
    if info.kind == "ERROR":
        head = f"Kerberos error {info.error_name} ({info.error_code}) for {who}"
        if info.service:
            head += f" service {info.service}"
        if info.error_text:
            head += f" text=\"{info.error_text[:120]}\""
    elif info.kind in ("AS-REQ", "TGS-REQ"):
        head = f"Kerberos {info.kind} {'from user ' + who if info.user else ('realm ' + info.realm if info.realm else '')}".rstrip()
        if info.service:
            head += f" for service {info.service}"
        if info.etypes:
            head += f" etypes={','.join(info.etypes)}"
        if info.padata:
            head += f" preauth={','.join(info.padata)}"
    elif info.kind in ("AS-REP", "TGS-REP"):
        head = f"Kerberos {info.kind} for {who}"
        if info.service:
            head += f" ticket for {info.service}"
        if info.ticket_etype:
            head += f" ticket_etype={info.ticket_etype}"
        if info.etypes:
            head += f" session_etype={info.etypes[0]}"
    elif info.kind == "AP-REQ":
        head = f"Kerberos AP-REQ presenting a ticket for {info.service or '?'}" + (f" ({info.ticket_etype})" if info.ticket_etype else "")
    else:
        head = f"Kerberos {info.kind}"
    tail = f" (packet {frame}) from {src} to {dst}"
    if info.flags:
        tail += f" [{' '.join(info.flags)}]"
    return head + tail


# --- LDAP -------------------------------------------------------------------

LDAP_RESULTS = {
    0: "success", 1: "operationsError", 2: "protocolError", 3: "timeLimitExceeded", 4: "sizeLimitExceeded", 7: "authMethodNotSupported",
    8: "strongerAuthRequired", 10: "referral", 11: "adminLimitExceeded", 14: "saslBindInProgress", 16: "noSuchAttribute",
    17: "undefinedAttributeType", 19: "constraintViolation", 20: "attributeOrValueExists", 32: "noSuchObject", 34: "invalidDNSyntax",
    48: "inappropriateAuthentication", 49: "invalidCredentials", 50: "insufficientAccessRights", 51: "busy", 52: "unavailable",
    53: "unwillingToPerform", 64: "namingViolation", 65: "objectClassViolation", 68: "entryAlreadyExists", 80: "other",
}
LDAP_SCOPES = {0: "base", 1: "one", 2: "sub"}
# "data NNN" inside an AD bind diagnostic message
_AD_BIND_DATA = {"525": "user_not_found", "52e": "bad_password", "530": "logon_time_restriction", "531": "workstation_restriction",
                 "532": "password_expired", "533": "account_disabled", "701": "account_expired", "773": "must_change_password",
                 "775": "account_locked"}
_AD_DATA_RE = re.compile(r"\bdata ([0-9a-f]{3})\b")
# reconnaissance filters an analyst wants pointed out (matched on the lower-cased rendered filter)
_RECON = [
    ("kerberoast_enum", re.compile(r"serviceprincipalname=\*")),
    ("asrep_roast_enum", re.compile(r"useraccountcontrol:1\.2\.840\.113556\.1\.4\.803:=4194304")),
    ("all_users_enum", re.compile(r"\(objectclass=user\)|\(objectcategory=person\)|\(samaccounttype=805306368\)")),
    ("all_computers_enum", re.compile(r"\(objectclass=computer\)|\(objectcategory=computer\)|\(samaccounttype=805306369\)")),
    ("groups_enum", re.compile(r"\(objectclass=group\)|\(objectcategory=group\)|\(samaccounttype=268435456\)")),
    ("admin_enum", re.compile(r"admincount=1")),
    ("trust_enum", re.compile(r"objectclass=trusteddomain|objectcategory=trusteddomain")),
    ("gpo_enum", re.compile(r"objectcategory=grouppolicycontainer|objectclass=grouppolicycontainer")),
    ("delegation_enum", re.compile(r"msds-allowedtodelegateto|useraccountcontrol:1\.2\.840\.113556\.1\.4\.803:=524288|msds-allowedtoactonbehalfofotheridentity")),
    ("laps_enum", re.compile(r"ms-mcs-admpwd|mslaps-password")),
    ("gmsa_enum", re.compile(r"msds-managedpassword|msds-groupmsamembership")),
    ("adcs_enum", re.compile(r"pkicertificatetemplate|pkienrollmentservice|objectclass=certificationauthority")),
    ("sid_history_enum", re.compile(r"sidhistory=\*")),
    ("password_attr_enum", re.compile(r"unixuserpassword|userpassword=\*|unicodepwd")),
]
_SENSITIVE_ATTRS = {"member", "msds-allowedtoactonbehalfofotheridentity", "msds-allowedtodelegateto", "serviceprincipalname",
                    "useraccountcontrol", "unicodepwd", "ntsecuritydescriptor", "scriptpath", "gplink", "msds-keycredentiallink",
                    "primarygroupid", "sidhistory", "altsecurityidentities", "adminsdholder"}


def render_filter(f) -> str:
    """LDAP_Filter / LDAP_Filter* -> "(objectClass=user)" style string."""
    if f is None:
        return ""
    name = type(f).__name__
    if name == "LDAP_Filter":
        return render_filter(getattr(f, "filter", None))
    if name == "LDAP_FilterAnd":
        return "(&" + "".join(render_filter(v) for v in (getattr(f, "vals", None) or [])) + ")"
    if name == "LDAP_FilterOr":
        return "(|" + "".join(render_filter(v) for v in (getattr(f, "vals", None) or [])) + ")"
    if name == "LDAP_FilterNot":
        return "(!" + render_filter(getattr(f, "val", None)) + ")"
    if name == "LDAP_FilterPresent":
        return f"({_s(getattr(f, 'present', None))}=*)"
    ops = {"LDAP_FilterEqual": "=", "LDAP_FilterGreaterOrEqual": ">=", "LDAP_FilterLessOrEqual": "<=", "LDAP_FilterApproxMatch": "~="}
    if name in ops:
        val = _s(getattr(f, "attributeValue", None))
        if not val.isprintable():
            val = "<binary>"
        return f"({_s(getattr(f, 'attributeType', None))}{ops[name]}{val[:200]})"
    if name == "LDAP_SubstringFilter":
        parts = []
        for sub in getattr(f, "filters", None) or []:
            inner = getattr(sub, "str", sub)
            kind = type(inner).__name__
            v = _s(getattr(inner, "val", None))
            if kind.endswith("Initial"):
                parts.append(v + "*")
            elif kind.endswith("Final"):
                parts.append("*" + v)
            else:
                parts.append("*" + v + "*")
        return f"({_s(getattr(f, 'type', None))}={''.join(parts).replace('**', '*') or '*'})"
    if name == "LDAP_FilterExtensibleMatch":
        rule = _s(getattr(f, "matchingRule", None))
        typ = _s(getattr(f, "type", None))
        val = _s(getattr(f, "matchValue", None))
        return f"({typ}{':' + rule if rule else ''}:={val})"
    return f"({name})"


@dataclass
class LdapInfo:
    op: str  # bind, bind_result, search, search_entry, search_done, modify, add, delete, modify_dn, unbind, extended, other
    action: str
    message_id: int | None = None
    user: str = ""  # bind DN / account
    auth: str = ""  # simple, sasl:<mech>, ntlm (sicily), ...
    password_length: int | None = None
    base: str = ""
    scope: str = ""
    filter: str = ""
    attributes: list[str] = field(default_factory=list)
    object: str = ""
    changes: list[str] = field(default_factory=list)  # "replace member", "add servicePrincipalName"
    result_code: int | None = None
    result_name: str = ""
    diagnostic: str = ""
    flags: list[str] = field(default_factory=list)


def decode_ldap(msg) -> LdapInfo | None:
    """One scapy ``LDAP`` message -> LdapInfo, or None for what we do not describe."""
    op = getattr(msg, "protocolOp", None)
    if op is None:
        return None
    name = type(op).__name__
    mid = _i(getattr(msg, "messageID", None))
    if name == "LDAP_BindRequest":
        info = LdapInfo(op="bind", action="ldap_bind", message_id=mid, user=_s(getattr(op, "bind_name", None)))
        auth = getattr(op, "authentication", None)
        an = type(auth).__name__
        if an == "LDAP_Authentication_simple":
            pw = getattr(auth, "val", b"") or b""
            info.auth = "simple"
            info.password_length = len(pw)
            if pw:
                info.flags.append("cleartext_password")
            elif info.user:
                info.flags.append("unauthenticated_bind")
            else:
                info.flags.append("anonymous_bind")
        elif an == "LDAP_Authentication_SaslCredentials":
            info.auth = "sasl:" + _s(getattr(auth, "mechanism", None))
        elif an.startswith("LDAP_Authentication_sicily"):
            info.auth = "ntlm"
        else:
            info.auth = an.replace("LDAP_Authentication_", "").lower() or "?"
        return info
    if name in ("LDAP_BindResponse", "LDAP_SearchResponseResultDone", "LDAP_ModifyResponse", "LDAP_AddResponse", "LDAP_DelResponse",
                "LDAP_ModifyDNResponse", "LDAP_ExtendedResponse"):
        opn = {"LDAP_BindResponse": "bind_result", "LDAP_SearchResponseResultDone": "search_done", "LDAP_ModifyResponse": "modify_result",
               "LDAP_AddResponse": "add_result", "LDAP_DelResponse": "delete_result", "LDAP_ModifyDNResponse": "modify_dn_result",
               "LDAP_ExtendedResponse": "extended_result"}[name]
        info = LdapInfo(op=opn, action="ldap_" + opn, message_id=mid)
        info.result_code = _i(getattr(op, "resultCode", None))
        info.result_name = LDAP_RESULTS.get(info.result_code, str(info.result_code))
        info.diagnostic = _s(getattr(op, "diagnosticMessage", None))
        m = _AD_DATA_RE.search(info.diagnostic)
        if m and m.group(1) in _AD_BIND_DATA:
            info.flags.append(_AD_BIND_DATA[m.group(1)])
        elif info.result_code == 49:
            info.flags.append("invalid_credentials")
        if name == "LDAP_ExtendedResponse":
            info.object = _s(getattr(op, "responseName", None))
        return info
    if name == "LDAP_SearchRequest":
        info = LdapInfo(op="search", action="ldap_search", message_id=mid, base=_s(getattr(op, "baseObject", None)))
        info.scope = LDAP_SCOPES.get(_i(getattr(op, "scope", None)), "?")
        try:
            info.filter = render_filter(getattr(op, "filter", None))
        except Exception:  # noqa: BLE001
            info.filter = "(?)"
        info.attributes = [_s(getattr(a, "type", a)) for a in (getattr(op, "attributes", None) or [])][:40]
        low = info.filter.lower()
        for flag, rx in _RECON:
            if rx.search(low):
                info.flags.append(flag)
        if not info.base and info.scope == "base":
            info.flags.append("rootdse")
        lattrs = {a.lower() for a in info.attributes}
        if lattrs & {"ms-mcs-admpwd", "mslaps-password", "msds-managedpassword", "unicodepwd", "userpassword"}:
            info.flags.append("secret_attribute_read")
        return info
    if name == "LDAP_SearchResponseEntry":
        return LdapInfo(op="search_entry", action="ldap_search_entry", message_id=mid, object=_s(getattr(op, "objectName", None)),
                        attributes=[_s(getattr(a, "type", a)) for a in (getattr(op, "attributes", None) or [])][:40])
    if name == "LDAP_ModifyRequest":
        info = LdapInfo(op="modify", action="ldap_modify", message_id=mid, object=_s(getattr(op, "object", None)))
        opnames = {0: "add", 1: "delete", 2: "replace", 3: "increment"}
        for ch in getattr(op, "changes", None) or []:
            mod = getattr(ch, "modification", None)
            attr = _s(getattr(mod, "type", None)) if mod is not None else "?"
            info.changes.append(f"{opnames.get(_i(getattr(ch, 'operation', None)), '?')} {attr}")
            if attr.lower() in _SENSITIVE_ATTRS:
                info.flags.append(f"sensitive_attribute:{attr}")
        return info
    if name == "LDAP_AddRequest":
        info = LdapInfo(op="add", action="ldap_add", message_id=mid, object=_s(getattr(op, "entry", None)))
        info.attributes = [_s(getattr(a, "type", a)) for a in (getattr(op, "attributes", None) or [])][:40]
        low = {a.lower() for a in info.attributes}
        if "objectclass" in low and any(a.lower() in ("samaccountname", "unicodepwd", "useraccountcontrol") for a in info.attributes):
            info.flags.append("account_or_computer_created")
        return info
    if name == "LDAP_DelRequest":
        return LdapInfo(op="delete", action="ldap_delete", message_id=mid, object=_s(getattr(op, "entry", None)))
    if name == "LDAP_ModifyDNRequest":
        info = LdapInfo(op="modify_dn", action="ldap_modify_dn", message_id=mid, object=_s(getattr(op, "entry", None)))
        info.changes = [f"newrdn {_s(getattr(op, 'newrdn', None))}"]
        sup = _s(getattr(op, "newSuperior", None))
        if sup:
            info.changes.append(f"newSuperior {sup}")
        return info
    if name == "LDAP_UnbindRequest":
        return LdapInfo(op="unbind", action="ldap_unbind", message_id=mid)
    if name == "LDAP_ExtendedRequest":
        info = LdapInfo(op="extended", action="ldap_extended", message_id=mid, object=_s(getattr(op, "requestName", None)))
        if info.object == "1.3.6.1.4.1.1466.20037":
            info.flags.append("starttls")
        return info
    return None


def iter_ldap_messages(layer):
    """scapy chains several LDAP messages of one segment as payloads; walk them."""
    seen = 0
    while layer is not None and type(layer).__name__ == "LDAP" and seen < 64:
        yield layer
        layer = layer.payload if type(getattr(layer, "payload", None)).__name__ == "LDAP" else None
        seen += 1


def ldap_summary(info: LdapInfo, src: str, dst: str, frame: int, bound_user: str = "") -> str:
    who = f" by {bound_user}" if bound_user and info.op not in ("bind", "bind_result") else ""
    if info.op == "bind":
        head = f"LDAP bind as \"{info.user or '(anonymous)'}\" auth={info.auth}"
        if info.password_length:
            head += f" (clear-text password, {info.password_length} chars)"
    elif info.op == "bind_result":
        head = f"LDAP bind result {info.result_name} ({info.result_code})" + (f" for \"{bound_user}\"" if bound_user else "")
        if info.diagnostic:
            head += f" diag=\"{info.diagnostic[:160]}\""
    elif info.op == "search":
        head = f"LDAP search{who} base=\"{info.base or '(root DSE)'}\" scope={info.scope} filter={info.filter or '(*)'}"
        if info.attributes:
            head += f" attrs={','.join(info.attributes[:15])}" + (",..." if len(info.attributes) > 15 else "")
    elif info.op == "search_done":
        head = f"LDAP search result {info.result_name} ({info.result_code})" + (f" for search{who}" if who else "")
        if info.base or info.filter:
            head += f" base=\"{info.base}\" filter={info.filter}"
        if info.changes:  # reused: entry count and sample DNs
            head += " " + " ".join(info.changes)
        if info.diagnostic:
            head += f" diag=\"{info.diagnostic[:160]}\""
    elif info.op == "modify":
        head = f"LDAP modify{who} object=\"{info.object}\" changes: {'; '.join(info.changes) or '?'}"
    elif info.op == "add":
        head = f"LDAP add{who} entry=\"{info.object}\"" + (f" attrs={','.join(info.attributes[:15])}" if info.attributes else "")
    elif info.op == "delete":
        head = f"LDAP delete{who} entry=\"{info.object}\""
    elif info.op == "modify_dn":
        head = f"LDAP rename{who} entry=\"{info.object}\" {' '.join(info.changes)}"
    elif info.op == "extended":
        head = f"LDAP extended request{who} {info.object}"
    elif info.op.endswith("_result"):
        head = f"LDAP {info.op.replace('_result', '')} result {info.result_name} ({info.result_code})" + (f" diag=\"{info.diagnostic[:160]}\"" if info.diagnostic else "")
    else:
        head = f"LDAP {info.op}{who}"
    tail = f" (packet {frame}) from {src} to {dst}"
    if info.flags:
        tail += f" [{' '.join(info.flags)}]"
    return head + tail


# --- Beaconing --------------------------------------------------------------

BEACON_MIN_EVENTS = 8  # a series shorter than this cannot be called regular
BEACON_MIN_INTERVAL = 2.0  # seconds; faster than that is a burst, not a beacon
BEACON_MAX_JITTER = 0.35  # coefficient of variation of the intervals (MAD / median)
BEACON_MAX_SERIES = 200  # most regular series reported


@dataclass
class Beacon:
    kind: str  # tcp_connect, http_request, tls_client_hello, dns_query
    client: str
    target: str  # "203.0.113.5:443" / "host" / SNI / qname
    times: list[float]
    count: int = 0
    median: float = 0.0
    jitter: float = 0.0  # 0..1, relative MAD
    span: float = 0.0
    score: float = 0.0
    label: str = ""


def _regularity(times: list[float]) -> tuple[float, float] | None:
    """(median interval, relative MAD) of the gaps between sorted timestamps."""
    ts = sorted(times)
    gaps = [b - a for a, b in itertools.pairwise(ts) if b - a > 0]
    if len(gaps) < BEACON_MIN_EVENTS - 1:
        return None
    med = statistics.median(gaps)
    if med < BEACON_MIN_INTERVAL:
        return None
    mad = statistics.median(abs(g - med) for g in gaps)
    return med, mad / med if med else 1.0


def find_beacons(series: dict[tuple[str, str, str], list[float]]) -> list[Beacon]:
    """series: (kind, client, target) -> timestamps.  Returns regular ones, most regular first."""
    out: list[Beacon] = []
    for (kind, client, target), times in series.items():
        if len(times) < BEACON_MIN_EVENTS:
            continue
        reg = _regularity(times)
        if reg is None:
            continue
        med, jitter = reg
        if jitter > BEACON_MAX_JITTER:
            continue
        ts = sorted(times)
        b = Beacon(kind=kind, client=client, target=target, times=ts, count=len(ts), median=med, jitter=jitter, span=ts[-1] - ts[0])
        # more events and less jitter -> higher score; long spans matter more than a two-minute burst
        b.score = (1 - jitter) * math.log2(b.count) * min(1.0, b.span / 600)
        b.label = ("regular" if jitter <= 0.1 else "jittered") + f" {kind.replace('_', ' ')} every ~{_human(med)}"
        out.append(b)
    out.sort(key=lambda x: -x.score)
    return out[:BEACON_MAX_SERIES]


def _human(sec: float) -> str:
    if sec < 90:
        return f"{sec:.0f}s"
    if sec < 5400:
        return f"{sec / 60:.1f}min"
    return f"{sec / 3600:.1f}h"


# --- Rare / suspicious domains ----------------------------------------------

RARE_MAX_QUERIES = 3  # at most this many queries from a single client counts as rare
RARE_MAX_DOMAINS = 300
_SECOND_LEVEL = {"co", "com", "net", "org", "gov", "ac", "edu", "or", "ne", "mil", "gob"}
_LOCAL_SUFFIX = {"local", "localdomain", "lan", "internal", "home", "arpa", "corp", "intranet", "localhost", "test", "invalid", "example"}
_VOWELS = set("aeiou")


def registered_domain(fqdn: str) -> str:
    labels = fqdn.lower().rstrip(".").split(".")
    if len(labels) <= 2:
        return ".".join(labels)
    if len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = defaultdict(int)
    for ch in s:
        freq[ch] += 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in freq.values())


def name_flags(fqdn: str, subdomains: set[str]) -> list[str]:
    """Shape-based flags: DGA-like labels, tunnelling-shaped names, raw-IP-like names."""
    flags: list[str] = []
    labels = fqdn.lower().rstrip(".").split(".")
    reg = registered_domain(fqdn)
    core = reg.split(".")[0]
    if len(core) >= 10:
        ent = _entropy(core)
        vowel_ratio = sum(c in _VOWELS for c in core) / len(core)
        digit_ratio = sum(c.isdigit() for c in core) / len(core)
        consonant_run = max((len(m) for m in re.findall(r"[b-df-hj-np-tv-z]+", core)), default=0)
        if (ent >= 3.3 and vowel_ratio < 0.25) or consonant_run >= 6 or (digit_ratio >= 0.3 and ent >= 3.0):
            flags.append("dga_like")
    host_part = ".".join(labels[:-len(reg.split("."))]) if len(labels) > len(reg.split(".")) else ""
    if host_part:
        longest = max(len(x) for x in host_part.split("."))
        if longest >= 40 or len(host_part) >= 60:
            flags.append("long_labels")
        if re.fullmatch(r"[0-9a-f.]{32,}", host_part) or re.fullmatch(r"[a-z2-7.]{40,}", host_part):
            flags.append("encoded_labels")
    if len(subdomains) >= 20:
        flags.append("many_subdomains")
    if len(labels) >= 6:
        flags.append("deep_name")
    return flags


@dataclass
class DomainStats:
    domain: str
    queries: int = 0
    clients: set[str] = field(default_factory=set)
    fqdns: set[str] = field(default_factory=set)
    answers: set[str] = field(default_factory=set)
    first: float = 0.0
    last: float = 0.0
    nxdomain: int = 0


def domain_report(stats: dict[str, DomainStats], total_clients: int) -> list[tuple[DomainStats, list[str], float]]:
    """Domains worth an event: (stats, flags, score), most suspicious first.

    "rare" needs a population to be rare against: with a single DNS client in
    the capture every domain would qualify, so only the shape-based flags apply.
    """
    out = []
    for d in stats.values():
        if not d.domain or d.domain.split(".")[-1] in _LOCAL_SUFFIX:
            continue
        flags: list[str] = []
        if total_clients >= 2 and len(d.clients) == 1 and d.queries <= RARE_MAX_QUERIES:
            flags.append("rare")
        if d.nxdomain and d.nxdomain >= max(1, d.queries // 2):
            flags.append("mostly_nxdomain")
        shape: list[str] = []
        for f in d.fqdns:
            for fl in name_flags(f, d.fqdns):
                if fl not in shape:
                    shape.append(fl)
        flags += shape
        if len(d.fqdns) >= 20 and len(d.clients) <= 2:
            flags.append("tunnelling_shape")
        if not flags:
            continue
        score = (2.0 if "dga_like" in flags else 0) + (2.0 if "tunnelling_shape" in flags else 0) + (1.0 if "encoded_labels" in flags else 0) \
            + (1.0 if "rare" in flags else 0) + (0.5 if "mostly_nxdomain" in flags else 0) + (0.5 if "long_labels" in flags else 0) \
            + (0.3 if "many_subdomains" in flags else 0)
        out.append((d, flags, score))
    out.sort(key=lambda x: (-x[2], x[0].first))
    return out[:RARE_MAX_DOMAINS]
