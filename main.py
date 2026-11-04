"""
DigDNS API — DNS, email-authentication, SMTP and TLS diagnostics.

Deployment: Vercel. Vercel finds the FastAPI object named `app` in this file
(main.py at the repo root) and runs it as a serverless function. Files in
public/ (the frontend) are served by Vercel's CDN on the same domain, so the
browser never makes a cross-origin request and no CORS setup is needed.

Run locally (for learning / testing):
    pip install -r requirements.txt
    uvicorn main:app --reload --port 8000
    then open http://127.0.0.1:8000/api/v1/analyze?domain=example.com

SMTP handshake: Vercel blocks outbound port 25, so the SMTP probe is OFF by
default (ENABLE_SMTP=false). The code is kept so you can switch it on if you
ever run this file on a VPS that allows port 25.

How this file is organised (read top to bottom):
    1. Configuration      – everything tunable comes from environment variables
    2. Helpers            – domain validation, DNS wrapper, IP safety check, cache
    3. Diagnostic modules – DNS records, SPF, DMARC, rDNS, SMTP handshake, TLS
    4. FastAPI app        – CORS + the two HTTP routes

Design rules worth learning from:
    * Every network operation has a timeout. Nothing can hang forever.
    * Each diagnostic section is isolated: if TLS crashes, DNS/SPF still return.
    * We never connect to private/internal IPs (SSRF protection).
    * The SMTP probe only ever asks about postmaster@<domain> and never sends
      DATA, so this API can't be abused to verify arbitrary email addresses.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
import re
import smtplib
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import Any

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
import dns.reversename
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("digdns")


# =============================================================================
# 1. CONFIGURATION (all values come from /etc/digdns-api.env in production)
# =============================================================================
def _env_list(name: str, default: str = "") -> list[str]:
    """Read a comma-separated env var into a clean list."""
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


def _env_float(name: str, default: float) -> float:
    """Read a numeric env var, falling back to the default if missing/invalid."""
    raw = os.getenv(name)
    try:
        return float(raw) if raw else default
    except ValueError:
        return default


# Exact origins allowed to call this API from a browser (your Pages URL, custom domain).
ALLOWED_ORIGINS = _env_list("ALLOWED_ORIGINS", "http://localhost:8080,http://127.0.0.1:8080")

# Optional: your Cloudflare Pages project name (e.g. "digdns"). When set, preview
# deployments like https://abc123.digdns.pages.dev are allowed too.
PAGES_PROJECT = os.getenv("PAGES_PROJECT", "").strip().lower()
ALLOWED_ORIGIN_REGEX = (
    rf"^https://([a-z0-9-]+\.)?{re.escape(PAGES_PROJECT)}\.pages\.dev$" if PAGES_PROJECT else None
)

# DNS resolvers. Public resolvers by default so results are consistent wherever this runs.
# Override with the DNS_NAMESERVERS environment variable, e.g. "9.9.9.9,1.0.0.1".
DNS_NAMESERVERS = _env_list("DNS_NAMESERVERS", "1.1.1.1,8.8.8.8")

# SMTP probe on/off. Must stay false on Vercel (port 25 is blocked there).
ENABLE_SMTP = os.getenv("ENABLE_SMTP", "false").lower() == "true"
DNS_TIMEOUT = _env_float("DNS_TIMEOUT", 3.0)    # seconds to wait for one nameserver
DNS_LIFETIME = _env_float("DNS_LIFETIME", 6.0)  # seconds total for one query (all retries)

SMTP_TIMEOUT = _env_float("SMTP_TIMEOUT", 15.0)  # per SMTP command; some MX servers delay the banner on purpose
TLS_TIMEOUT = _env_float("TLS_TIMEOUT", 8.0)
CACHE_TTL = _env_float("CACHE_TTL", 300.0)       # seconds to cache a full result per domain

# Identity used in the SMTP probe. MUST be a real hostname whose PTR matches your
# server IP, or many mail servers will reject/tarpit you.
SMTP_HELO_NAME = os.getenv("SMTP_HELO_NAME") or socket.getfqdn()
SMTP_MAIL_FROM = os.getenv("SMTP_MAIL_FROM") or f"postmaster@{SMTP_HELO_NAME}"

ENABLE_DOCS = os.getenv("ENABLE_DOCS", "true").lower() == "true"


# =============================================================================
# 2. HELPERS
# =============================================================================

# ---- 2a. DNS wrapper ---------------------------------------------------------
_resolver = dns.asyncresolver.Resolver()
if DNS_NAMESERVERS:
    _resolver.nameservers = DNS_NAMESERVERS
_resolver.timeout = DNS_TIMEOUT
_resolver.lifetime = DNS_LIFETIME


class DNSLookupError(Exception):
    """Raised when DNS itself failed (timeout, SERVFAIL) — as opposed to 'no record'."""


async def resolve(name: str, rtype: str) -> list:
    """
    Query DNS and return the list of answers.

    Returns [] when the record simply doesn't exist (NXDOMAIN / no answer).
    Raises DNSLookupError when the lookup itself failed, so callers can tell
    "this domain has no MX" apart from "we couldn't find out".
    """
    try:
        answer = await _resolver.resolve(name, rtype, raise_on_no_answer=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.resolver.NoNameservers as exc:
        raise DNSLookupError(f"{rtype} lookup for {name} failed: all nameservers returned an error (SERVFAIL/REFUSED)") from exc
    except dns.exception.Timeout as exc:
        raise DNSLookupError(f"{rtype} lookup for {name} timed out") from exc
    except dns.exception.DNSException as exc:
        raise DNSLookupError(f"{rtype} lookup for {name} failed: {exc}") from exc
    return list(answer) if answer.rrset is not None else []


async def get_txt(name: str) -> list[str]:
    """TXT records can be split into several 255-byte strings; join them back together."""
    records = await resolve(name, "TXT")
    return [b"".join(r.strings).decode("utf-8", errors="replace") for r in records]


# ---- 2b. Input validation ------------------------------------------------------
_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


def normalize_domain(raw: str) -> str:
    """
    Turn whatever the user typed into a clean, ASCII domain name, or raise ValueError.

    Accepts things like "Example.com", "https://example.com/path", "bücher.de".
    Rejects IP addresses, single-label names ("localhost") and junk.
    """
    d = raw.strip().lower()
    d = re.sub(r"^[a-z][a-z0-9+.-]*://", "", d)  # drop "https://"
    d = d.split("/")[0].split("?")[0].split("#")[0]  # drop path/query
    d = d.split("@")[-1]  # "user@example.com" -> "example.com"
    d = d.split(":")[0].rstrip(".")  # drop ":443" and trailing dot

    try:
        d = d.encode("idna").decode("ascii")  # unicode domains -> punycode (xn--...)
    except UnicodeError as exc:
        raise ValueError("Domain contains invalid characters.") from exc

    if not d or len(d) > 253 or "." not in d:
        raise ValueError("Enter a full domain name such as example.com.")
    labels = d.split(".")
    if not all(_LABEL_RE.match(label) for label in labels):
        raise ValueError("Domain contains an invalid label (letters, digits and hyphens only).")
    if labels[-1].isdigit():
        raise ValueError("IP addresses are not accepted — enter a domain name.")
    return d


# ---- 2c. SSRF protection -------------------------------------------------------
def is_public_ip(ip: str) -> bool:
    """
    True only for globally routable unicast addresses.

    Without this, someone could point evil.com at 127.0.0.1 or 10.0.0.5 and use
    our server to probe its own internal network. We always resolve the IP
    ourselves, check it here, and then connect to *that exact IP* — so DNS
    rebinding tricks can't swap it out between check and connect.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_global and not addr.is_multicast


# ---- 2d. Tiny in-memory cache ----------------------------------------------------
# Stops one user hammering the same MX server by mashing the button.
# (Per worker process; that's fine for this purpose.)
_cache: dict[str, tuple[float, dict]] = {}
_CACHE_MAX = 1000


def _cache_get(key: str) -> dict | None:
    hit = _cache.get(key)
    if hit and time.monotonic() - hit[0] < CACHE_TTL:
        return hit[1]
    return None


def _cache_set(key: str, value: dict) -> None:
    now = time.monotonic()
    if len(_cache) >= _CACHE_MAX:  # evict expired, then oldest
        for k in [k for k, (t, _) in _cache.items() if now - t >= CACHE_TTL]:
            _cache.pop(k, None)
        while len(_cache) >= _CACHE_MAX:
            _cache.pop(min(_cache, key=lambda k: _cache[k][0]))
    _cache[key] = (now, value)


def _status(errors: list, warnings: list) -> str:
    """Collapse a section's findings into one traffic-light status."""
    return "fail" if errors else ("warn" if warnings else "pass")


# =============================================================================
# 3. DIAGNOSTIC MODULES
# =============================================================================

# ---- 3a. Plain DNS record lookup ---------------------------------------------------
RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA")

# SRV records never live at the bare domain; they live at _service._proto.domain.
# So "look up SRV for example.com" really means "check the common service names".
COMMON_SRV = (
    "_autodiscover._tcp", "_submission._tcp", "_submissions._tcp", "_imaps._tcp",
    "_pop3s._tcp", "_caldavs._tcp", "_carddavs._tcp", "_sip._tls",
    "_sipfederationtls._tcp", "_xmpp-client._tcp", "_xmpp-server._tcp",
)


def _format_rdata(rtype: str, r: Any) -> Any:
    """Convert a dnspython record object into plain JSON-friendly data."""
    if rtype == "MX":
        return {"preference": r.preference, "exchange": r.exchange.to_text(omit_final_dot=True)}
    if rtype == "TXT":
        return b"".join(r.strings).decode("utf-8", errors="replace")
    if rtype in ("CNAME", "NS"):
        return r.target.to_text(omit_final_dot=True)
    if rtype == "SOA":
        return {
            "mname": r.mname.to_text(omit_final_dot=True),
            "rname": r.rname.to_text(omit_final_dot=True),
            "serial": r.serial, "refresh": r.refresh, "retry": r.retry,
            "expire": r.expire, "minimum": r.minimum,
        }
    if rtype == "SRV":
        return {"priority": r.priority, "weight": r.weight, "port": r.port,
                "target": r.target.to_text(omit_final_dot=True)}
    return r.to_text()  # A / AAAA


async def _lookup_type(name: str, rtype: str) -> dict:
    try:
        return {"records": [_format_rdata(rtype, r) for r in await resolve(name, rtype)], "error": None}
    except DNSLookupError as exc:
        return {"records": [], "error": str(exc)}


async def lookup_dns_records(domain: str) -> dict:
    """Look up every record type in parallel."""
    results = await asyncio.gather(*(_lookup_type(domain, t) for t in RECORD_TYPES))
    records = dict(zip(RECORD_TYPES, results))

    srv_results = await asyncio.gather(*(_lookup_type(f"{p}.{domain}", "SRV") for p in COMMON_SRV))
    records["SRV"] = {
        "records": [{"name": f"{p}.{domain}", **rec}
                    for p, res in zip(COMMON_SRV, srv_results) for rec in res["records"]],
        "error": None,
        "note": f"Checked {len(COMMON_SRV)} common _service._proto names.",
    }

    errors, warnings = [], []
    if not records["NS"]["records"] and not records["A"]["records"] and not records["AAAA"]["records"]:
        errors.append("Domain has no NS, A or AAAA records — it may not exist or its DNS is broken.")
    if any(v["error"] for v in records.values()):
        warnings.append("Some lookups failed (timeouts or SERVFAIL). Results may be incomplete.")
    return {"status": _status(errors, warnings), "records": records, "errors": errors, "warnings": warnings}


# ---- 3b. SPF analysis -------------------------------------------------------------------
SPF_LOOKUP_LIMIT = 10   # RFC 7208 §4.6.4: more than 10 DNS-querying terms = PermError
SPF_VOID_LIMIT = 2      # RFC 7208 §4.6.4: more than 2 lookups returning nothing = PermError
SPF_MECHANISMS = {"all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"}
SPF_LOOKUP_MECHS = {"include", "a", "mx", "ptr", "exists"}  # these cost a DNS lookup
SPF_HARD_STOP = 40      # protect our server from deliberately huge include trees


def _pick_spf(txts: list[str]) -> list[str]:
    return [t for t in txts if t.lower() == "v=spf1" or t.lower().startswith("v=spf1 ")]


async def _follow_spf(target: str, kind: str, state: dict, res: dict, depth: int, path: tuple) -> str | None:
    """Fetch the SPF record of an include:/redirect= target and walk it recursively."""
    if "%" in target:
        res["warnings"].append(f"{kind}:{target} uses SPF macros, which can't be evaluated without a real sender IP; not followed.")
        return None
    target = target.lower().rstrip(".")
    if state["lookups"] > SPF_HARD_STOP or depth >= 10:
        res["warnings"].append("SPF tree is too large/deep; stopped walking it.")
        return None
    if target in path:
        res["errors"].append(f"SPF loop detected: {' -> '.join(path + (target,))}")
        return None

    entry = {"domain": target, "via": kind, "depth": depth + 1, "record": None}
    res["includes"].append(entry)
    try:
        txts = await get_txt(target)
    except DNSLookupError as exc:
        res["errors"].append(f"{kind}:{target} — {exc} (receivers return TempError).")
        return None
    if not txts:
        state["void"] += 1
    records = _pick_spf(txts)
    if not records:
        res["errors"].append(f"{kind}:{target} has no SPF record — this makes the whole SPF check PermError.")
        return None
    if len(records) > 1:
        res["errors"].append(f"{target} publishes {len(records)} SPF records (must be exactly one).")
    entry["record"] = records[0]
    return await _walk_spf(target, records[0], state, res, depth + 1, path + (target,))


async def _walk_spf(domain: str, record: str, state: dict, res: dict, depth: int, path: tuple) -> str | None:
    """
    Parse one SPF record term by term, counting DNS lookups and recursing into includes.
    Returns the qualifier of its 'all' mechanism ('-', '~', '?', '+') or None.
    """
    all_qualifier = None
    redirect = None

    for term in record.split()[1:]:  # skip "v=spf1"
        qualifier, body = "+", term
        if body[0] in "+-~?":
            qualifier, body = body[0], body[1:]
        if not body:
            res["errors"].append(f"Empty SPF term '{term}' in record for {domain}.")
            continue

        # Modifiers look like name=value (redirect=, exp=, or unknown ones).
        left = body.split("=", 1)[0]
        if "=" in body and re.fullmatch(r"[A-Za-z][A-Za-z0-9_.-]*", left):
            mod, value = left.lower(), body.split("=", 1)[1]
            if mod == "redirect":
                redirect = value
            elif mod != "exp":
                res["warnings"].append(f"Unknown modifier '{term}' in SPF for {domain} (ignored by receivers).")
            continue

        mech = re.split(r"[:/]", body, maxsplit=1)[0].lower()
        arg = body.split(":", 1)[1] if ":" in body else ""

        if mech not in SPF_MECHANISMS:
            res["errors"].append(f"Invalid SPF term '{term}' in record for {domain} (syntax error → PermError).")
            continue
        if mech in SPF_LOOKUP_MECHS:
            state["lookups"] += 1

        if mech == "all":
            all_qualifier = qualifier
        elif mech == "ptr":
            res["warnings"].append(f"'ptr' in {domain}'s SPF is deprecated (RFC 7208) and slow; many receivers ignore it.")
        elif mech in ("ip4", "ip6"):
            try:
                net = ipaddress.ip_network(arg, strict=False)
                if (mech == "ip4") != (net.version == 4):
                    raise ValueError
            except ValueError:
                res["errors"].append(f"Invalid network '{term}' in SPF for {domain}.")
        elif mech in ("include", "exists") and not arg:
            res["errors"].append(f"'{term}' in SPF for {domain} is missing a domain.")
        elif mech == "include":
            await _follow_spf(arg, "include", state, res, depth, path)

    # redirect= only applies when the record has no 'all' mechanism.
    if redirect and all_qualifier is None:
        state["lookups"] += 1
        all_qualifier = await _follow_spf(redirect, "redirect", state, res, depth, path)
    return all_qualifier


async def analyze_spf(domain: str) -> dict:
    res: dict[str, Any] = {
        "found": False, "record": None, "lookup_count": 0, "lookup_limit": SPF_LOOKUP_LIMIT,
        "void_lookups": 0, "all_qualifier": None, "includes": [], "errors": [], "warnings": [],
    }
    try:
        records = _pick_spf(await get_txt(domain))
    except DNSLookupError as exc:
        res["errors"].append(str(exc))
        res["status"] = "fail"
        return res

    if not records:
        res["errors"].append("No SPF record found. Receivers can't tell which servers may send mail for this domain.")
        res["status"] = "fail"
        return res

    res["found"], res["record"] = True, records[0]
    if len(records) > 1:
        res["errors"].append(f"{len(records)} SPF records found. RFC 7208 requires exactly one — receivers return PermError.")

    state = {"lookups": 0, "void": 0}
    all_q = await _walk_spf(domain, records[0], state, res, depth=0, path=(domain,))
    res["lookup_count"], res["void_lookups"], res["all_qualifier"] = state["lookups"], state["void"], all_q

    if state["lookups"] > SPF_LOOKUP_LIMIT:
        res["errors"].append(
            f"{state['lookups']} DNS lookups — over the hard limit of {SPF_LOOKUP_LIMIT}. "
            "Receivers return PermError, so SPF effectively fails for ALL your mail. Flatten or remove includes."
        )
    elif state["lookups"] >= 8:
        res["warnings"].append(f"{state['lookups']}/{SPF_LOOKUP_LIMIT} DNS lookups — one more vendor include could break SPF.")
    if state["void"] > SPF_VOID_LIMIT:
        res["errors"].append(f"{state['void']} void lookups (limit {SPF_VOID_LIMIT}) — receivers may return PermError.")

    if all_q == "+":
        res["errors"].append("'+all' authorises the entire internet to send as this domain. Use '-all' or '~all'.")
    elif all_q == "?":
        res["warnings"].append("'?all' (neutral) gives no protection. Use '~all' or '-all'.")
    elif all_q is None:
        res["warnings"].append("No 'all' mechanism — unlisted senders get a neutral result. End the record with '~all' or '-all'.")

    res["status"] = _status(res["errors"], res["warnings"])
    return res


# ---- 3c. DMARC analysis ---------------------------------------------------------------------
def _mailto_targets(value: str) -> tuple[list[str], list[str]]:
    """Split a rua/ruf value into addresses; return (valid_addresses, bad_entries)."""
    good, bad = [], []
    for item in filter(None, (v.strip() for v in value.split(","))):
        if item.lower().startswith("mailto:") and "@" in item:
            good.append(item[7:].split("!")[0])  # strip size limit suffix like "!10m"
        else:
            bad.append(item)
    return good, bad


async def analyze_dmarc(domain: str) -> dict:
    res: dict[str, Any] = {
        "found": False, "record": None, "policy": None, "subdomain_policy": None, "pct": 100,
        "adkim": "r", "aspf": "r", "rua": [], "ruf": [], "tags": {}, "errors": [], "warnings": [],
    }
    try:
        txts = await get_txt(f"_dmarc.{domain}")
    except DNSLookupError as exc:
        res["errors"].append(str(exc))
        res["status"] = "fail"
        return res

    records = [t for t in txts if re.match(r"^\s*v\s*=\s*DMARC1\s*(;|$)", t, re.I)]
    if not records:
        res["errors"].append(f"No DMARC record at _dmarc.{domain}. Anyone can spoof this domain's From: address.")
        if domain.count(".") >= 2:
            res["warnings"].append("This may be a subdomain; receivers then fall back to the parent domain's DMARC record, which this check doesn't evaluate.")
        res["status"] = "fail"
        return res
    if len(records) > 1:
        res["errors"].append(f"{len(records)} DMARC records found — receivers ignore DMARC entirely when there is more than one.")

    res["found"], res["record"] = True, records[0]

    tags: dict[str, str] = {}
    for part in filter(None, (p.strip() for p in records[0].split(";"))):
        if "=" not in part:
            res["errors"].append(f"Malformed DMARC tag '{part}'.")
            continue
        key, value = part.split("=", 1)
        tags[key.strip().lower()] = value.strip()
    res["tags"] = tags

    # p= (required)
    policy = tags.get("p", "").lower()
    if policy not in ("none", "quarantine", "reject"):
        res["errors"].append("Missing or invalid p= tag. It must be none, quarantine or reject — without it the record is invalid.")
    else:
        res["policy"] = policy
        if policy == "none":
            res["warnings"].append("p=none is monitor-only: spoofed mail is still delivered. Move to quarantine, then reject, once reports look clean.")

    # sp= (subdomain policy, optional)
    if "sp" in tags:
        sp = tags["sp"].lower()
        if sp in ("none", "quarantine", "reject"):
            res["subdomain_policy"] = sp
        else:
            res["errors"].append(f"Invalid sp= value '{tags['sp']}'.")

    # pct= (percentage the policy applies to)
    if "pct" in tags:
        try:
            pct = int(tags["pct"])
            if not 0 <= pct <= 100:
                raise ValueError
            res["pct"] = pct
            if pct < 100:
                res["warnings"].append(f"pct={pct}: the policy only applies to {pct}% of failing mail.")
        except ValueError:
            res["errors"].append(f"Invalid pct= value '{tags['pct']}' (must be 0-100).")

    # Alignment modes
    for key in ("adkim", "aspf"):
        if key in tags:
            if tags[key].lower() in ("r", "s"):
                res[key] = tags[key].lower()
            else:
                res["errors"].append(f"Invalid {key}= value '{tags[key]}' (must be r or s).")

    # Reporting addresses
    for key in ("rua", "ruf"):
        if key in tags:
            good, bad = _mailto_targets(tags[key])
            res[key] = good
            for b in bad:
                res["errors"].append(f"{key}= entry '{b}' is invalid (must be mailto:address).")
    if not res["rua"]:
        res["warnings"].append("No rua= address: you get no aggregate reports, so you can't see who is sending mail as you.")

    # External report destinations must opt in via <domain>._report._dmarc.<dest> (RFC 7489 §7.1).
    external = {addr.split("@")[-1].lower() for addr in res["rua"] + res["ruf"]}
    external = {d for d in external if d != domain and not d.endswith("." + domain) and not domain.endswith("." + d)}
    for dest in list(external)[:4]:
        try:
            ok = any(t.lower().startswith("v=dmarc1") for t in await get_txt(f"{domain}._report._dmarc.{dest}"))
        except DNSLookupError:
            ok = False
        if not ok:
            res["warnings"].append(f"Reports go to {dest}, which hasn't authorised it ({domain}._report._dmarc.{dest}). Reports may be dropped.")

    res["status"] = _status(res["errors"], res["warnings"])
    return res


# ---- 3d. Reverse DNS (PTR + forward confirmation) ------------------------------------------------
async def check_rdns(ip: str) -> dict:
    """
    PTR lookup plus 'forward-confirmed' check (FCrDNS):
    IP -> PTR hostname -> A/AAAA must contain the same IP.
    """
    out: dict[str, Any] = {"ip": ip, "ptr": [], "forward_confirmed": False, "matched_host": None, "error": None}
    try:
        out["ptr"] = [r.target.to_text(omit_final_dot=True)
                      for r in await resolve(dns.reversename.from_address(ip).to_text(), "PTR")]
        rtype = "AAAA" if ":" in ip else "A"
        for host in out["ptr"][:3]:
            if ip in [r.address for r in await resolve(host, rtype)]:
                out["forward_confirmed"], out["matched_host"] = True, host
                break
    except DNSLookupError as exc:
        out["error"] = str(exc)
    return out


# ---- 3e. SMTP handshake (blocking code — runs in a worker thread) -----------------------------------
def _decode(msg: Any) -> str:
    return msg.decode("utf-8", errors="replace") if isinstance(msg, bytes) else str(msg)


def smtp_handshake(mx_host: str, ip: str, domain: str) -> dict:
    """
    Talk to the MX server on port 25: banner -> EHLO -> STARTTLS -> MAIL FROM -> RCPT TO -> QUIT.

    We never send DATA, so no email is ever delivered. RCPT TO is always
    postmaster@<domain> (RFC 5321 says every mail domain must accept it), so
    this can't be turned into an address-verification service.
    """
    steps: list[dict] = []
    out: dict[str, Any] = {
        "host": mx_host, "ip": ip, "port": 25, "steps": steps, "starttls": None,
        "accepts_mail": None, "verdict": "", "error": None, "duration_ms": None,
    }

    def record(step: str, code: int, msg: Any) -> None:
        steps.append({"step": step, "code": code, "message": _decode(msg)[:300], "ok": 200 <= code < 400})

    started = time.monotonic()
    client = smtplib.SMTP(timeout=SMTP_TIMEOUT, local_hostname=SMTP_HELO_NAME)
    try:
        code, msg = client.connect(ip, 25)
        record("Connect (banner)", code, msg)
        if code != 220:
            out["accepts_mail"] = False
            out["verdict"] = f"Server answered the connection with {code} instead of 220."
            return out

        code, msg = client.ehlo()
        record(f"EHLO {SMTP_HELO_NAME}", code, msg)
        if code != 250:  # very old servers: fall back to HELO
            code, msg = client.helo()
            record("HELO", code, msg)
            if code != 250:
                out["accepts_mail"] = False
                out["verdict"] = "Server rejected our greeting."
                return out

        out["starttls"] = client.has_extn("starttls")
        if out["starttls"]:
            # We don't verify the MX certificate here: most MX certs don't match the
            # MX hostname and real senders accept that. We only test that TLS works.
            tls_ctx = ssl.create_default_context()
            tls_ctx.check_hostname = False
            tls_ctx.verify_mode = ssl.CERT_NONE
            code, msg = client.starttls(context=tls_ctx)
            record("STARTTLS", code, msg)
            client.ehlo()  # RFC 3207: must greet again after TLS starts

        code, msg = client.mail(SMTP_MAIL_FROM)
        record(f"MAIL FROM:<{SMTP_MAIL_FROM}>", code, msg)
        if code != 250:
            out["accepts_mail"] = None
            out["verdict"] = "Server rejected our probe sender. Often caused by OUR server's IP reputation or missing PTR, not the target's config."
            return out

        rcpt = f"postmaster@{domain}"
        code, msg = client.rcpt(rcpt)
        record(f"RCPT TO:<{rcpt}>", code, msg)
        if 200 <= code < 300:
            out["accepts_mail"] = True
            out["verdict"] = "Server accepts mail for this domain."
        elif 400 <= code < 500:
            out["accepts_mail"] = None
            out["verdict"] = "Temporary rejection (4xx) — usually greylisting. Real senders retry and succeed."
        else:
            out["accepts_mail"] = False
            out["verdict"] = "Server permanently rejected mail for postmaster@ — inbound mail for this domain is likely broken."
        try:
            client.rset()
        except smtplib.SMTPException:
            pass

    except (socket.timeout, TimeoutError):
        out["error"] = ("Timed out talking to port 25. The most common cause is that YOUR server's hosting "
                        "provider blocks outbound port 25; otherwise the MX is firewalled or tarpitting.")
    except ConnectionRefusedError:
        out["error"] = "Connection refused on port 25 — nothing is listening for mail on this MX host."
        out["accepts_mail"] = False
    except smtplib.SMTPServerDisconnected as exc:
        out["error"] = f"Server closed the connection unexpectedly: {exc or 'no reason given'}."
    except smtplib.SMTPNotSupportedError as exc:
        out["error"] = f"Command not supported by server: {exc}"
    except smtplib.SMTPResponseException as exc:
        out["error"] = f"Server error {exc.smtp_code}: {_decode(exc.smtp_error)[:300]}"
    except smtplib.SMTPException as exc:
        out["error"] = f"SMTP error: {exc}"
    except ssl.SSLError as exc:
        out["error"] = f"STARTTLS negotiation failed: {exc.reason or exc}"
    except OSError as exc:
        out["error"] = f"Network error: {exc.strerror or exc}"
    finally:
        try:
            client.quit()
        except Exception:
            client.close()
        out["duration_ms"] = int((time.monotonic() - started) * 1000)
    return out


async def _ips_of(host: str) -> list[str]:
    """All A and AAAA addresses for a hostname (empty list on failure)."""
    ips: list[str] = []
    for rtype in ("A", "AAAA"):
        try:
            ips += [r.address for r in await resolve(host, rtype)]
        except DNSLookupError:
            pass
    return ips


async def analyze_mail(domain: str) -> dict:
    """MX discovery, rDNS of MX IPs, and the SMTP handshake against the primary MX."""
    res: dict[str, Any] = {"mx": [], "null_mx": False, "implicit_mx": False, "rdns": [],
                           "smtp": None, "errors": [], "warnings": [], "notes": []}
    try:
        mx = await resolve(domain, "MX")
    except DNSLookupError as exc:
        res["errors"].append(str(exc))
        res["status"] = "fail"
        return res

    # RFC 7505 "null MX" (MX 0 .) = this domain explicitly accepts no mail.
    if any(r.exchange == dns.name.root for r in mx):
        res["null_mx"] = True
        res["notes"].append("Domain publishes a null MX (RFC 7505): it intentionally accepts no email.")
        res["status"] = "info"
        return res

    hosts = sorted((r.preference, r.exchange.to_text(omit_final_dot=True).lower()) for r in mx)
    if not hosts:
        # No MX at all. RFC 5321 says senders then try the domain's own A/AAAA record.
        if not await _ips_of(domain):
            res["errors"].append("This domain cannot receive email: it has no MX record and no A/AAAA record to fall back to.")
            res["status"] = "fail"
            return res
        res["implicit_mx"] = True
        hosts = [(0, domain)]
        res["warnings"].append("No MX record. Senders fall back to the domain's own A record (implicit MX) — almost always a mistake.")
    res["mx"] = [{"preference": p, "host": h, "ips": [], "implicit": res["implicit_mx"]} for p, h in hosts]

    # Resolve IPs for up to 3 MX hosts in parallel.
    host_ips = await asyncio.gather(*(_ips_of(h) for _, h in hosts[:3]))
    for entry, ips in zip(res["mx"], host_ips):
        entry["ips"] = ips

    # rDNS for up to 6 MX IPs.
    all_ips = [ip for ips in host_ips for ip in ips][:6]
    res["rdns"] = list(await asyncio.gather(*(check_rdns(ip) for ip in all_ips)))
    if any(not r["forward_confirmed"] for r in res["rdns"]):
        res["warnings"].append("At least one MX IP lacks forward-confirmed reverse DNS. If these servers also SEND mail, receivers will penalise them.")
    res["notes"].append("rDNS is checked on MX (inbound) IPs. If you send through a different service (Google, Microsoft, SES), its outbound IPs are what matter.")

    # SMTP probe against the primary (lowest preference) MX, IPv4 only.
    primary_host = hosts[0][1]
    primary_ips = host_ips[0] if host_ips else []
    v4_public = [ip for ip in primary_ips if ":" not in ip and is_public_ip(ip)]
    if not primary_ips:
        res["errors"].append(f"Primary MX {primary_host} does not resolve to any IP address.")
    elif not ENABLE_SMTP:
        # Not an error with the target domain — this deployment simply can't reach port 25.
        res["smtp"] = {"host": primary_host, "skipped": True, "disabled": True,
                       "reason": "SMTP handshake is unavailable on this deployment: the hosting platform blocks outbound port 25."}
    elif not v4_public:
        res["smtp"] = {"host": primary_host, "skipped": True,
                       "error": "Primary MX has no public IPv4 address (private/reserved IPs are blocked for safety)."}
    else:
        try:
            res["smtp"] = await asyncio.wait_for(
                run_in_threadpool(smtp_handshake, primary_host, v4_public[0], domain),
                timeout=SMTP_TIMEOUT * 2 + 5,
            )
        except asyncio.TimeoutError:
            res["smtp"] = {"host": primary_host, "ip": v4_public[0], "steps": [],
                           "error": "SMTP conversation took too long and was abandoned (tarpitting server?)."}

    smtp = res["smtp"] or {}
    if smtp.get("accepts_mail") is False:
        res["errors"].append(smtp.get("verdict") or smtp.get("error") or "Primary MX does not accept mail.")
    elif smtp.get("error") and not smtp.get("skipped"):
        res["warnings"].append("SMTP handshake was inconclusive — see details.")
    if smtp.get("starttls") is False:
        res["warnings"].append("Primary MX does not offer STARTTLS — inbound mail travels unencrypted.")

    res["status"] = _status(res["errors"], res["warnings"])
    return res


# ---- 3f. TLS certificate inspector (blocking code — runs in a worker thread) ----------------------------
def _fetch_peer_cert(ip: str, server_name: str, ctx: ssl.SSLContext) -> tuple[bytes, str, str]:
    """Open TCP to ip:443, do the TLS handshake with SNI=server_name, return the raw cert."""
    with socket.create_connection((ip, 443), timeout=TLS_TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            cipher = tls.cipher()
            return tls.getpeercert(binary_form=True), tls.version() or "", cipher[0] if cipher else ""


def _first_attr(name: x509.Name, oid: Any) -> str | None:
    values = name.get_attributes_for_oid(oid)
    return str(values[0].value) if values else None


def inspect_tls(domain: str, ip: str) -> dict:
    """
    Two-pass approach:
      1. Strict handshake (system CA store + hostname check) -> tells us if browsers trust it.
      2. If that fails, connect again WITHOUT verification just to read the cert,
         so we can still show the user *why* it's broken (expired, wrong name...).
    """
    out: dict[str, Any] = {"host": domain, "ip": ip, "port": 443, "verified": False,
                           "verify_error": None, "errors": [], "warnings": []}
    try:
        der, version, cipher = _fetch_peer_cert(ip, domain, ssl.create_default_context())
        out["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        out["verify_error"] = exc.verify_message or str(exc)
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        der, version, cipher = _fetch_peer_cert(ip, domain, insecure)

    cert = x509.load_der_x509_certificate(der)
    not_after = cert.not_valid_after_utc
    days_remaining = int((not_after - datetime.now(timezone.utc)).total_seconds() // 86400)

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        sans = san_ext.get_values_for_type(x509.DNSName) + [str(i) for i in san_ext.get_values_for_type(x509.IPAddress)]
    except x509.ExtensionNotFound:
        sans = []

    out.update({
        "subject_cn": _first_attr(cert.subject, NameOID.COMMON_NAME),
        "issuer_cn": _first_attr(cert.issuer, NameOID.COMMON_NAME),
        "issuer_org": _first_attr(cert.issuer, NameOID.ORGANIZATION_NAME),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": days_remaining,
        "sans": sans,
        "serial": format(cert.serial_number, "X"),
        "self_signed": cert.issuer == cert.subject,
        "tls_version": version,
        "cipher": cipher,
    })

    if not out["verified"]:
        out["errors"].append(f"Certificate is NOT trusted: {out['verify_error']}")
    if days_remaining < 0:
        out["errors"].append(f"Certificate expired {-days_remaining} days ago.")
    elif days_remaining <= 14:
        out["warnings"].append(f"Certificate expires in {days_remaining} days — check that auto-renewal works.")
    if version in ("TLSv1", "TLSv1.1"):
        out["warnings"].append(f"Server negotiated obsolete {version}.")
    out["status"] = _status(out["errors"], out["warnings"])
    return out


async def analyze_tls(domain: str) -> dict:
    ips = await _ips_of(domain)
    if not ips:
        return {"status": "fail", "host": domain, "errors": ["Domain has no A/AAAA record — nothing to connect to on port 443."], "warnings": []}
    public = [ip for ip in ips if is_public_ip(ip)]
    if not public:
        return {"status": "fail", "host": domain, "errors": ["Domain resolves only to private/reserved IPs; refusing to connect."], "warnings": []}
    ip = next((i for i in public if ":" not in i), public[0])  # prefer IPv4

    try:
        return await asyncio.wait_for(run_in_threadpool(inspect_tls, domain, ip), timeout=TLS_TIMEOUT * 2 + 2)
    except (asyncio.TimeoutError, TimeoutError, socket.timeout):
        msg = f"Timed out connecting to {ip}:443."
    except ConnectionRefusedError:
        msg = f"Connection refused on {ip}:443 — no HTTPS service running."
    except ssl.SSLError as exc:
        msg = f"TLS handshake failed: {exc.reason or exc}"
    except OSError as exc:
        msg = f"Network error: {exc.strerror or exc}"
    return {"status": "fail", "host": domain, "ip": ip, "errors": [msg], "warnings": []}


# =============================================================================
# 4. FASTAPI APP
# =============================================================================
app = FastAPI(
    title="DigDNS API",
    version="1.0.0",
    description="Open-source DNS, email-auth, SMTP and TLS diagnostics.",
    docs_url="/api/v1/docs" if ENABLE_DOCS else None,
    openapi_url="/api/v1/openapi.json" if ENABLE_DOCS else None,
    redoc_url=None,
)

# CORS: only matters when the frontend is on a DIFFERENT origin (e.g. testing
# index.html from localhost). On Vercel the page and API share one domain, so
# browsers don't need CORS at all. CORS is not abuse protection either.
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=ALLOWED_ORIGIN_REGEX,
    allow_methods=["GET"],
    allow_headers=["*"],
    allow_credentials=False,
    max_age=86400,
)


async def _safe(section: str, coro: Any, timeout: float) -> dict:
    """Run one diagnostic section with its own deadline; never let it crash the request."""
    try:
        return await asyncio.wait_for(coro, timeout=timeout)
    except asyncio.TimeoutError:
        return {"status": "error", "errors": [f"{section} check exceeded {timeout:.0f}s and was abandoned."], "warnings": []}
    except Exception as exc:  # noqa: BLE001 — last-resort guard, logged for debugging
        log.exception("Unhandled error in %s check", section)
        return {"status": "error", "errors": [f"Internal error in {section} check ({type(exc).__name__})."], "warnings": []}


@app.get("/", include_in_schema=False)
async def root() -> RedirectResponse:
    """Normally Vercel's CDN serves public/index.html for "/"; this is just a safety net."""
    return RedirectResponse(url="/index.html")


@app.get("/api/v1/health")
async def health() -> dict:
    """Used by you (and uptime monitors) to confirm the API is alive."""
    return {"status": "ok", "smtp_enabled": ENABLE_SMTP, "time": datetime.now(timezone.utc).isoformat()}


@app.get("/api/v1/analyze")
async def analyze(domain: str = Query(..., min_length=1, max_length=300, description="Domain to analyse, e.g. example.com")) -> dict:
    try:
        clean = normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    cached = _cache_get(clean)
    if cached:
        return {**cached, "cached": True}

    started = time.monotonic()
    log.info("Analysing %s", clean)

    # All five sections run concurrently; total time ≈ the slowest one (usually SMTP).
    dns_res, spf_res, dmarc_res, mail_res, tls_res = await asyncio.gather(
        _safe("DNS", lookup_dns_records(clean), 15),
        _safe("SPF", analyze_spf(clean), 20),
        _safe("DMARC", analyze_dmarc(clean), 15),
        _safe("Mail/SMTP", analyze_mail(clean), 45),
        _safe("TLS", analyze_tls(clean), 25),
    )

    result = {
        "domain": clean,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "cached": False,
        "dns": dns_res,
        "spf": spf_res,
        "dmarc": dmarc_res,
        "mail": mail_res,
        "tls": tls_res,
    }
    _cache_set(clean, result)
    return result
