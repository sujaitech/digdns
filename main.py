"""
VdigDNS API — DNS, domain registration, email-authentication, SMTP and TLS diagnostics.

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
import base64
import html
import http.client
import ipaddress
import json
import logging
import os
import re
import secrets
import smtplib
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import Counter
from datetime import datetime, timezone
from typing import Any

import dns.asyncquery
import dns.asyncresolver
import dns.exception
import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.reversename
from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import ExtensionOID, NameOID
from fastapi import FastAPI, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from starlette.concurrency import run_in_threadpool

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("vdigdns")


# =============================================================================
# 1. CONFIGURATION (environment variables; set them in Vercel → Settings → Environment Variables)
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
RECORD_TYPES = ("A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "CAA")

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
    if rtype == "CAA":
        return _caa_tuple(r)
    return r.to_text()  # A / AAAA


def _caa_tuple(r: Any) -> dict:
    """CAA rdata -> {"flags": 0, "tag": "issue", "value": "letsencrypt.org"}."""
    tag = r.tag.decode("ascii", errors="replace") if isinstance(r.tag, bytes) else str(r.tag)
    value = r.value.decode("utf-8", errors="replace") if isinstance(r.value, bytes) else str(r.value)
    return {"flags": int(r.flags), "tag": tag.lower(), "value": value}


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

    await _assess_spf(domain, records[0], res)
    return res


async def _assess_spf(domain: str, record: str, res: dict) -> None:
    """
    Walk one SPF record and fill in res: lookup count, includes, errors, warnings, status.
    Shared by the domain report and the SPF builder, so both always agree.
    """
    state = {"lookups": 0, "void": 0}
    all_q = await _walk_spf(domain, record, state, res, depth=0, path=(domain,))
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

    if len(record) > 255:
        res["notes"] = res.get("notes", []) + [
            f"The record is {len(record)} characters. DNS stores TXT text in 255-character pieces; "
            "most DNS panels split it for you, but some need it entered as several quoted strings."]

    res["status"] = _status(res["errors"], res["warnings"])


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


# ---- 3d-2. Hosting: who serves the website (PTR + IP owner) -----------------------------------------
# Reverse DNS alone often can't name "the server": CDN IPs (Cloudflare, Vercel...)
# rarely have a useful PTR, and shared hosting PTRs name the shared box. So we
# also ask Team Cymru's free IP-to-ASN service (plain DNS TXT queries) who owns
# the IP. Together that gives an honest "hosted on / hosted by" answer.

# Well-known networks, by AS number. cdn=True means the visible IP is an edge
# proxy and the real origin server is hidden behind it.
KNOWN_NETWORKS: dict[int, tuple[str, bool]] = {
    13335: ("Cloudflare", True), 209242: ("Cloudflare", True),
    54113: ("Fastly", True),
    20940: ("Akamai", True), 16625: ("Akamai", True),
    16509: ("Amazon Web Services", False), 14618: ("Amazon Web Services", False),
    15169: ("Google Cloud", False), 396982: ("Google Cloud", False),
    8075: ("Microsoft Azure", False),
    14061: ("DigitalOcean", False),
    24940: ("Hetzner", False),
    16276: ("OVHcloud", False),
    63949: ("Akamai Cloud (Linode)", False),
    20473: ("Vultr", False),
}


async def lookup_ip_owner(ip: str) -> dict | None:
    """
    Ask Team Cymru which network announces this IP.
      1.2.3.4  ->  TXT 4.3.2.1.origin.asn.cymru.com  -> "13335 | 104.16.0.0/13 | US | arin | 2010-07-14"
      AS13335  ->  TXT AS13335.asn.cymru.com          -> "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
    """
    rev = dns.reversename.from_address(ip).to_text(omit_final_dot=True)
    if rev.endswith(".in-addr.arpa"):
        query = rev[: -len(".in-addr.arpa")] + ".origin.asn.cymru.com"
    else:
        query = rev[: -len(".ip6.arpa")] + ".origin6.asn.cymru.com"
    try:
        txt = await get_txt(query)
        if not txt:
            return None
        parts = [p.strip() for p in txt[0].split("|")]
        asn = int(parts[0].split()[0])  # an IP can have several origin ASNs; take the first
        owner: dict[str, Any] = {"asn": asn, "prefix": parts[1] if len(parts) > 1 else None,
                                 "country": parts[2] if len(parts) > 2 else None, "as_name": None}
        name_txt = await get_txt(f"AS{asn}.asn.cymru.com")
        if name_txt:
            raw_name = name_txt[0].split("|")[-1].strip()           # "CLOUDFLARENET, US"
            owner["as_name"] = re.sub(r",\s*[A-Z]{2}$", "", raw_name)  # -> "CLOUDFLARENET"
        known = KNOWN_NETWORKS.get(asn)
        owner["provider"] = known[0] if known else None
        owner["cdn"] = known[1] if known else False
        return owner
    except (DNSLookupError, ValueError, IndexError):
        return None


async def _describe_ip(ip: str) -> dict:
    rdns, owner = await asyncio.gather(check_rdns(ip), lookup_ip_owner(ip))
    return {**rdns, "owner": owner}


async def analyze_hosting(domain: str) -> dict:
    """Where does the website live? PTR + owner for up to 3 IPv4 and 1 IPv6 addresses."""
    res: dict[str, Any] = {"status": "info", "ips": [], "headline": None, "detail": None,
                           "errors": [], "warnings": [], "notes": []}
    v4, v6 = [], []
    for rtype, bucket in (("A", v4), ("AAAA", v6)):
        try:
            bucket += [r.address for r in await resolve(domain, rtype)]
        except DNSLookupError as exc:
            res["warnings"].append(str(exc))
    targets = [ip for ip in v4[:3] + v6[:1] if is_public_ip(ip)]
    if not targets:
        res["headline"] = "No website address"
        res["detail"] = "This domain has no public A or AAAA record, so it isn't serving a website."
        return res

    res["ips"] = list(await asyncio.gather(*(_describe_ip(ip) for ip in targets)))

    first = res["ips"][0]
    owner = first.get("owner") or {}
    network = owner.get("provider") or owner.get("as_name")
    network_txt = f"{network} (AS{owner['asn']})" if network and owner.get("asn") else None

    if owner.get("cdn"):
        res["headline"] = f"Behind {owner['provider']}"
        res["detail"] = (f"{first['ip']} is a {owner['provider']} edge address. The real origin server is "
                         "hidden behind the CDN, so its name can't be read from DNS.")
    elif first["ptr"] and first["forward_confirmed"]:
        res["headline"] = f"Hosted on {first['matched_host']}"
        res["detail"] = f"{first['ip']} reverse-resolves to {first['matched_host']}" + (f", on {network_txt}." if network_txt else ".")
    elif first["ptr"]:
        res["headline"] = f"Hosted on {first['ptr'][0]}"
        res["detail"] = (f"{first['ip']} has PTR {first['ptr'][0]}, but that name doesn't resolve back to the IP, "
                         "so it may be a generic provider name" + (f". Network: {network_txt}." if network_txt else "."))
    elif network_txt:
        res["headline"] = f"Hosted by {network}"
        res["detail"] = f"{first['ip']} has no reverse DNS (PTR). The address belongs to {network_txt}."
    else:
        res["headline"] = f"Hosted at {first['ip']}"
        res["detail"] = "No reverse DNS and no network owner information was found for this address."

    providers = {(i.get("owner") or {}).get("asn") for i in res["ips"] if i.get("owner")}
    if len(providers) > 1:
        res["notes"].append("This domain's addresses belong to more than one network (multi-provider or load-balanced).")
    return res


# ---- 3d-3. DKIM ------------------------------------------------------------------------------------
# DKIM keys live at <selector>._domainkey.<domain>. The selector is chosen by the
# mail provider and isn't published anywhere, so we try the common ones. A key
# under a custom selector can only be found by reading a sent email's headers
# (DKIM-Signature: ... s=<selector>), which is why there's also a single-selector check.
DKIM_SELECTORS = (
    "google",                                   # Google Workspace
    "selector1", "selector2",                   # Microsoft 365
    "default", "dkim", "mail", "smtp", "email", # cPanel, Plesk and generic setups
    "k1", "k2", "k3",                           # Mailchimp / Mandrill
    "mandrill", "mte1", "mxvault",
    "s1", "s2",                                 # SendGrid
    "zmail", "zoho",                            # Zoho
    "protonmail", "protonmail2", "protonmail3", # Proton
    "fm1", "fm2", "fm3",                        # Fastmail
    "sig1",                                     # iCloud
    "pm",                                       # Postmark
    "mailjet", "resend", "cm", "everlytickey1",
)
_SELECTOR_RE = re.compile(r"^[a-z0-9](?:[a-z0-9_.-]{0,62})$", re.I)


def _parse_tag_list(record: str) -> dict[str, str]:
    """'v=DKIM1; k=rsa; p=MIIB...' -> {'v': 'DKIM1', 'k': 'rsa', 'p': 'MIIB...'}"""
    tags: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            key, value = part.split("=", 1)
            tags[key.strip().lower()] = value.strip()
    return tags


def _dkim_key_info(tags: dict[str, str]) -> dict:
    """Work out key type and strength from the p= (public key) tag."""
    key_type = tags.get("k", "rsa").lower() or "rsa"
    p = re.sub(r"\s+", "", tags.get("p", ""))
    if not p:
        return {"key_type": key_type, "bits": None, "revoked": True}
    if key_type == "ed25519":
        return {"key_type": "ed25519", "bits": 256, "revoked": False}
    try:
        raw = base64.b64decode(p + "=" * (-len(p) % 4))
        key = serialization.load_der_public_key(raw)  # DER public key (SubjectPublicKeyInfo)
        bits = getattr(key, "key_size", None)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        bits = None  # malformed or unusual key encoding — reported as "couldn't be read"
    return {"key_type": key_type, "bits": bits, "revoked": False}


async def check_dkim_selector(domain: str, selector: str) -> dict | None:
    """Look up one selector. Returns None when no DKIM key is published there."""
    name = f"{selector}._domainkey.{domain}"
    records = [t for t in await get_txt(name) if "p=" in t.replace(" ", "")]
    if not records:
        return None
    info = _dkim_key_info(_parse_tag_list(records[0]))
    if info["revoked"]:
        status, note = "info", "Key is revoked (empty p= tag), so it can't sign mail."
    elif info["key_type"] == "ed25519":
        status, note = "pass", "Ed25519 key."
    elif info["bits"] is None:
        status, note = "warn", "The key couldn't be read — check for a typo in the p= value."
    elif info["bits"] < 1024:
        status, note = "fail", f"{info['bits']}-bit RSA key is too weak; many receivers ignore it. Use 2048-bit."
    elif info["bits"] < 2048:
        status, note = "warn", f"{info['bits']}-bit RSA key works, but 2048-bit is the current recommendation."
    else:
        status, note = "pass", f"{info['bits']}-bit RSA key."
    return {"selector": selector, "name": name, "record": records[0], **info, "status": status, "note": note}


async def analyze_dkim(domain: str) -> dict:
    res: dict[str, Any] = {"status": "warn", "selectors": [], "checked": len(DKIM_SELECTORS),
                           "wildcard": False, "errors": [], "warnings": [], "notes": []}

    async def safe_check(sel: str) -> dict | None:
        try:
            return await check_dkim_selector(domain, sel)
        except DNSLookupError:
            return None

    # A random selector should never exist. If it does, the domain answers every
    # name (wildcard TXT) and the selector scan below would be meaningless.
    probe_sel = "vdigdns-probe-" + secrets.token_hex(4)
    probe, *found = await asyncio.gather(safe_check(probe_sel), *(safe_check(s) for s in DKIM_SELECTORS))
    if probe:
        res["wildcard"] = True
        res["warnings"].append("This domain answers every _domainkey name (wildcard record), so common-selector "
                               "scanning can't tell real keys apart. Check your real selector below.")
        return res

    res["selectors"] = [f for f in found if f]
    if not res["selectors"]:
        res["warnings"].append(f"No DKIM key found at {len(DKIM_SELECTORS)} common selectors. DKIM may still be set up under "
                               "a custom selector: find s= in the DKIM-Signature header of a sent email and check it below.")
        return res

    statuses = [s["status"] for s in res["selectors"] if s["status"] != "info"]
    if any(s == "fail" for s in statuses):
        res["status"] = "fail"
    elif any(s == "warn" for s in statuses) or not statuses:
        res["status"] = "warn"
    else:
        res["status"] = "pass"
    return res


# ---- 3d-4. CAA (which certificate authorities may issue SSL) ------------------------------------------
# CAA domain -> words that appear in that CA's certificate issuer name.
CAA_ISSUER_NAMES: dict[str, tuple[str, ...]] = {
    "letsencrypt.org": ("let's encrypt",),
    "pki.goog": ("google trust services",),
    "digicert.com": ("digicert",), "symantec.com": ("digicert", "symantec"),
    "sectigo.com": ("sectigo", "zerossl", "comodo"), "comodoca.com": ("sectigo", "comodo"),
    "amazon.com": ("amazon",), "amazontrust.com": ("amazon",), "amazonaws.com": ("amazon",),
    "globalsign.com": ("globalsign",),
    "godaddy.com": ("godaddy", "starfield"), "starfieldtech.com": ("starfield",),
    "ssl.com": ("ssl.com", "ssl corporation"),
    "entrust.net": ("entrust",), "buypass.com": ("buypass",),
    "microsoft.com": ("microsoft",), "certum.pl": ("certum", "asseco"),
}


async def analyze_caa(domain: str) -> dict:
    """
    RFC 8659: if the name has no CAA record, the parent's applies, and so on
    up the tree. We climb until we find one (stopping before the TLD).
    """
    res: dict[str, Any] = {"found": False, "found_at": None, "records": [], "issuers": [],
                           "wildcard_issuers": [], "iodef": [], "error": None}
    labels = domain.split(".")
    try:
        for i in range(len(labels) - 1):
            name = ".".join(labels[i:])
            recs = await resolve(name, "CAA")
            if recs:
                res["found"], res["found_at"] = True, name
                res["records"] = [_caa_tuple(r) for r in recs]
                break
    except DNSLookupError as exc:
        res["error"] = str(exc)
        return res

    for rec in res["records"]:
        ca = rec["value"].split(";")[0].strip().lower()   # "letsencrypt.org; validationmethods=..." -> CA domain
        if rec["tag"] == "issue":
            res["issuers"].append(ca or "(none)")          # an empty issue value means "no CA at all"
        elif rec["tag"] == "issuewild":
            res["wildcard_issuers"].append(ca or "(none)")
        elif rec["tag"] == "iodef":
            res["iodef"].append(rec["value"])
    return res


def caa_vs_certificate(caa: dict, tls: dict) -> str | None:
    """Warn when the CA that issued today's certificate isn't allowed to issue the next one."""
    if not caa.get("found") or not caa.get("issuers") or not tls.get("issuer"):
        return None
    issuer_text = f"{tls.get('issuer_org') or ''} {tls.get('issuer') or ''}".lower()
    current_ca = next((ca for ca, words in CAA_ISSUER_NAMES.items() if any(w in issuer_text for w in words)), None)
    if not current_ca:
        return None  # issuer we don't recognise: stay quiet rather than guess
    allowed_words = {w for ca in caa["issuers"] for w in CAA_ISSUER_NAMES.get(ca, ())}
    if any(w in issuer_text for w in allowed_words):
        return None
    allowed = ", ".join(caa["issuers"])
    return (f"The current certificate comes from {tls.get('issuer_org') or current_ca}, but CAA only allows {allowed}. "
            "The next renewal from the current issuer will be refused unless CAA is updated.")


# ---- 3d-5. Mail provider detection ---------------------------------------------------------------------
INBOUND_PROVIDERS: tuple[tuple[str, str], ...] = (
    (r"(^|\.)(google|googlemail)\.com$", "Google Workspace"),
    (r"\.mail\.protection\.outlook\.com$", "Microsoft 365"),
    (r"(^|\.)zoho(mail)?\.(com|in|eu|com\.au|jp|com\.cn)$", "Zoho Mail"),
    (r"(^|\.)protonmail\.ch$", "Proton Mail"),
    (r"(^|\.)messagingengine\.com$", "Fastmail"),
    (r"(^|\.)mail\.icloud\.com$", "iCloud Mail"),
    (r"(^|\.)yandex\.(net|ru)$", "Yandex 360"),
    (r"(^|\.)mimecast\.(com|co\.za)$", "Mimecast"),
    (r"(^|\.)(pphosted|ppe-hosted)\.com$", "Proofpoint"),
    (r"(^|\.)barracudanetworks\.com$", "Barracuda"),
    (r"(^|\.)iphmx\.com$", "Cisco Secure Email"),
    (r"(^|\.)amazonaws\.com$", "Amazon WorkMail / SES"),
    (r"(^|\.)secureserver\.net$", "GoDaddy Email"),
    (r"(^|\.)privateemail\.com$", "Namecheap Private Email"),
    (r"(^|\.)hostinger\.com$", "Hostinger Email"),
    (r"(^|\.)emailsrvr\.com$", "Rackspace Email"),
    (r"(^|\.)mailgun\.org$", "Mailgun"),
)
SENDER_INCLUDES: dict[str, str] = {
    "_spf.google.com": "Google Workspace", "spf.protection.outlook.com": "Microsoft 365",
    "zoho.com": "Zoho", "zoho.in": "Zoho", "zoho.eu": "Zoho", "zcsend.net": "Zoho Campaigns",
    "_spf.protonmail.ch": "Proton Mail", "spf.messagingengine.com": "Fastmail", "icloud.com": "iCloud Mail",
    "amazonses.com": "Amazon SES", "sendgrid.net": "SendGrid", "mailgun.org": "Mailgun",
    "servers.mcsv.net": "Mailchimp", "spf.mandrillapp.com": "Mailchimp Transactional",
    "spf.brevo.com": "Brevo", "spf.sendinblue.com": "Brevo", "spf.mtasv.net": "Postmark",
    "mail.zendesk.com": "Zendesk", "_spf.salesforce.com": "Salesforce", "sparkpostmail.com": "SparkPost",
    "spf.mailjet.com": "Mailjet", "helpscoutemail.com": "Help Scout", "_spf.elasticemail.com": "Elastic Email",
    "spf.smtp2go.com": "SMTP2GO", "email.freshdesk.com": "Freshdesk", "_spf.resend.com": "Resend",
}


def detect_providers(domain: str, mail: dict, spf: dict) -> dict:
    """Name the inbound mail service (from MX) and sending services (from SPF includes)."""
    inbound: list[str] = []
    for mx in (mail.get("mx") or []):
        if mx.get("implicit"):
            continue
        host = mx["host"].lower()
        name = next((label for pattern, label in INBOUND_PROVIDERS if re.search(pattern, host)), None)
        if not name:
            name = "Own mail server" if host == domain or host.endswith("." + domain) else f"Other ({host})"
        if name not in inbound:
            inbound.append(name)

    senders: list[str] = []
    for inc in (spf.get("includes") or []):
        if inc.get("depth") != 1:
            continue
        target = inc["domain"].lower()
        name = SENDER_INCLUDES.get(target) or next((v for k, v in SENDER_INCLUDES.items() if target.endswith("." + k)), None)
        if name and name not in senders and name not in inbound:
            senders.append(name)
    return {"inbound": inbound, "senders": senders}


# ---- 3d-6. Domain registration: RDAP first, classic WHOIS as fallback -------------------------------
# RDAP is WHOIS's modern replacement: the same registry data as JSON over HTTPS.
# ICANN dropped the port-43 WHOIS requirement for gTLDs (.com, .net, .stream...)
# in January 2025, so RDAP is the reliable path for those. Many country-code
# TLDs (.in, .uk, .de...) still only run port-43 WHOIS, hence the fallback.
# Registrant contact details are deliberately NOT returned: they're mostly
# redacted for privacy anyway, and a public tool shouldn't republish them.
RDAP_BOOTSTRAP_URL = "https://data.iana.org/rdap/dns.json"   # IANA's official TLD -> RDAP server list
REG_HTTP_TIMEOUT = 8.0
USER_AGENT = "VdigDNS/1.0 (+https://dig.sujaiprojects.stream)"
_rdap_bootstrap: dict[str, Any] = {"at": 0.0, "map": {}}


def _http_get_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"Accept": "application/rdap+json, application/json", "User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=REG_HTTP_TIMEOUT) as resp:
        return json.loads(resp.read(2_000_000).decode("utf-8", errors="replace"))


def _rdap_base_for(tld: str) -> str | None:
    """RDAP server for a TLD, from IANA's bootstrap file (cached for a day per instance)."""
    now = time.monotonic()
    if not _rdap_bootstrap["map"] or now - _rdap_bootstrap["at"] > 86400:
        data = _http_get_json(RDAP_BOOTSTRAP_URL)
        mapping: dict[str, list[str]] = {}
        for tlds, urls in data.get("services", []):
            for t in tlds:
                mapping[t.lower()] = urls
        _rdap_bootstrap.update(at=now, map=mapping)
    urls = _rdap_bootstrap["map"].get(tld.lower()) or []
    base = next((u for u in urls if u.startswith("https://")), urls[0] if urls else None)
    return (base if base.endswith("/") else base + "/") if base else None


def _candidates(domain: str) -> list[str]:
    """www.shop.example.com -> [www.shop.example.com, shop.example.com, example.com] (max 3 tries)."""
    labels = domain.split(".")
    return [".".join(labels[i:]) for i in range(len(labels) - 1)][:3]


def _vcard(entity: dict, field: str) -> str | None:
    """Pull one field (fn, email, tel) out of an RDAP entity's jCard."""
    try:
        for item in entity["vcardArray"][1]:
            if item[0] == field and isinstance(item[3], str):
                return item[3]
    except (KeyError, IndexError, TypeError):
        pass
    return None


_DATE_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%b-%Y", "%d-%b-%Y %H:%M:%S", "%Y.%m.%d", "%d.%m.%Y", "%Y/%m/%d", "%d/%m/%Y")


def _parse_date(raw: str | None) -> str | None:
    """Registries format dates a dozen ways; normalise to ISO 8601 (UTC) or None."""
    if not raw:
        return None
    s = raw.strip().split(" (")[0]
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        dt = None
        for candidate in (s, s.split()[0]):
            for fmt in _DATE_FORMATS:
                try:
                    dt = datetime.strptime(candidate, fmt)
                    break
                except ValueError:
                    continue
            if dt:
                break
    if not dt:
        return None
    return (dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).astimezone(timezone.utc).isoformat()


def _parse_rdap(name: str, d: dict, server: str) -> dict:
    events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", []) if isinstance(e, dict)}
    registrar = iana_id = abuse_email = None
    for ent in d.get("entities", []) or []:
        if "registrar" in (ent.get("roles") or []):
            registrar = _vcard(ent, "fn")
            iana_id = next((p.get("identifier") for p in ent.get("publicIds", []) or [] if "IANA" in str(p.get("type", ""))), None)
            for sub in ent.get("entities", []) or []:
                if "abuse" in (sub.get("roles") or []):
                    abuse_email = _vcard(sub, "email")
    return {
        "domain": (d.get("ldhName") or name).lower(),
        "registrar": registrar, "registrar_iana_id": iana_id, "abuse_email": abuse_email,
        "created": _parse_date(events.get("registration")),
        "updated": _parse_date(events.get("last changed")),
        "expires": _parse_date(events.get("expiration")),
        "statuses": [str(s) for s in d.get("status", []) or []],
        "nameservers": sorted({(n.get("ldhName") or "").lower().rstrip(".") for n in d.get("nameservers", []) or [] if n.get("ldhName")}),
        "dnssec": (d.get("secureDNS") or {}).get("delegationSigned"),
        "source": "RDAP", "server": server,
    }


def rdap_lookup(domain: str) -> dict | None:
    """Blocking. Returns parsed data, {'not_found': True}, or None if the TLD has no RDAP service."""
    base = _rdap_base_for(domain.rsplit(".", 1)[-1])
    if not base:
        return None
    for name in _candidates(domain):
        try:
            return _parse_rdap(name, _http_get_json(f"{base}domain/{name}"), base)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                continue  # e.g. a subdomain: try the parent name
            raise
    return {"not_found": True, "source": "RDAP", "server": base}


def _whois_query(server: str, query: str) -> str:
    """Classic WHOIS: open TCP port 43, send the query, read until the server closes."""
    with socket.create_connection((server, 43), timeout=REG_HTTP_TIMEOUT) as sock:
        sock.settimeout(REG_HTTP_TIMEOUT)
        sock.sendall((query + "\r\n").encode("idna" if not query.isascii() else "ascii"))
        chunks, total = [], 0
        while total < 200_000:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    return b"".join(chunks).decode("utf-8", errors="replace")


_WHOIS_NOT_FOUND = re.compile(r"no match|not found|no data found|no entries found|status:\s*(free|available)|is available for", re.I)


def _parse_whois_text(name: str, text: str, server: str) -> dict:
    def first(*labels: str) -> str | None:
        for label in labels:
            # [ \t]* (not \s*) so an empty field never swallows the next line
            m = re.search(rf"^[ \t]*{label}[ \t]*:[ \t]*(\S.*?)[ \t]*$", text, re.I | re.M)
            if m and m.group(1):
                return m.group(1)
        return None

    statuses = [s.split()[0] for s in re.findall(r"^[ \t]*(?:Domain Status|status)[ \t]*:[ \t]*(\S.*?)[ \t]*$", text, re.I | re.M)]
    nameservers = re.findall(r"^[ \t]*(?:Name Server|nserver|Nameservers?|Host Name)[ \t]*:[ \t]*(\S+)", text, re.I | re.M)
    dnssec = first("DNSSEC")
    return {
        "domain": name,
        "registrar": first("Registrar", "Registrar Name", "Sponsoring Registrar", "Registrar Organization",
                           "Registrar Organisation", "Sponsoring Registrar Organization"),
        "registrar_iana_id": first("Registrar IANA ID"),
        "abuse_email": first("Registrar Abuse Contact Email"),
        "created": _parse_date(first("Creation Date", "Created On", "Created Date", "Created", "Registered on", "Registered",
                                     "Registration Date", "Domain Registration Date", "Registration Time", "Record created")),
        "updated": _parse_date(first("Updated Date", "Last Modified", "Last Updated", "Last update", "Modified",
                                     "Record last updated", "changed")),
        "expires": _parse_date(first("Registry Expiry Date", "Registry Expiration Date", "Registrar Registration Expiration Date",
                                     "Expiry Date", "Expiration Date", "Domain Expiration Date", "Expires On", "Expires",
                                     "Expire Date", "Expiration Time", "Renewal Date", "Valid Until", "paid-till", "expire")),
        "statuses": statuses,
        "nameservers": sorted({n.lower().rstrip(".") for n in nameservers}),
        "dnssec": None if dnssec is None else not dnssec.lower().startswith("unsigned"),
        "source": "WHOIS", "server": server,
    }


class RegistryUnreachable(Exception):
    """The registry has a WHOIS server, but it didn't answer (down, overloaded or rate-limiting us)."""

    def __init__(self, server: str) -> None:
        super().__init__(server)
        self.server = server


_HOSTNAME = r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+"


def _iana_whois_server(tld: str) -> str | None:
    """
    IANA's own WHOIS says which server handles a TLD ("whois: whois.nic.xyz").
    When a registry runs no WHOIS server, that line is present but EMPTY, so the
    pattern must stay on one line ([ \t]*) and require a real hostname.
    """
    iana = _whois_query("whois.iana.org", tld)
    m = re.search(rf"^(?:refer|whois):[ \t]*({_HOSTNAME})[ \t]*$", iana, re.M | re.I)
    return m.group(1).lower() if m else None


def _whois_query_retry(server: str, query: str) -> str:
    """One retry after a short pause: small registries often drop the first connection."""
    try:
        return _whois_query(server, query)
    except OSError:
        time.sleep(0.6)
        return _whois_query(server, query)


def whois43_lookup(domain: str) -> dict | None:
    """
    Blocking. Returns parsed data, {'not_found': True}, or None when the registry has
    no WHOIS server at all. Raises RegistryUnreachable when its server won't answer;
    any other OSError means IANA itself couldn't be reached.
    """
    server = _iana_whois_server(domain.rsplit(".", 1)[-1])
    if not server:
        return None
    try:
        for name in _candidates(domain):
            text = _whois_query_retry(server, name)
            if _WHOIS_NOT_FOUND.search(text) or len(text.strip()) < 40:
                continue
            return _parse_whois_text(name, text, server)
    except OSError as exc:
        raise RegistryUnreachable(server) from exc
    return {"not_found": True, "source": "WHOIS", "server": server}


# Registry status codes -> plain English. "Bad" ones mean the domain is in trouble.
STATUS_MEANINGS: dict[str, tuple[str, str]] = {
    "clienttransferprohibited": ("Transfer locked", "ok"),
    "servertransferprohibited": ("Registry transfer lock", "ok"),
    "clientdeleteprohibited": ("Delete locked", "ok"),
    "serverdeleteprohibited": ("Registry delete lock", "ok"),
    "clientupdateprohibited": ("Update locked", "ok"),
    "serverupdateprohibited": ("Registry update lock", "ok"),
    "clientrenewprohibited": ("Renewal locked", "ok"),
    "active": ("Active", "ok"), "ok": ("Active", "ok"),
    "addperiod": ("Newly registered", "ok"), "autorenewperiod": ("Auto-renew grace period", "warn"),
    "renewperiod": ("Recently renewed", "ok"), "transferperiod": ("Recently transferred", "ok"),
    "pendingtransfer": ("Transfer in progress", "warn"),
    "inactive": ("No nameservers set", "bad"),
    "clienthold": ("On hold, not resolving", "bad"), "serverhold": ("Registry hold, not resolving", "bad"),
    "redemptionperiod": ("Expired, in redemption", "bad"), "pendingdelete": ("Pending deletion", "bad"),
    "pendingrestore": ("Restore in progress", "warn"),
}


def _status_key(s: str) -> str:
    return re.sub(r"[\s_\-]", "", s.split("http")[0]).lower()  # "client transfer prohibited" == "clientTransferProhibited"


async def analyze_registration(domain: str) -> dict:
    """
    Outcomes, so the report never blames the domain for a registry's limits:
      found        -> registrar, dates, locks          (pass / warn / fail)
      unavailable  -> registry publishes nothing online (info, not an error)
      unreachable  -> registry's server didn't answer   (warn: usually temporary)
      not found    -> registry has no such domain       (warn)
      error        -> our side couldn't reach IANA      (error)
    """
    tld = domain.rsplit(".", 1)[-1]
    res: dict[str, Any] = {"status": "info", "found": False, "summary": None, "errors": [], "warnings": [], "notes": []}
    data, rdap_failed = None, False
    try:
        data = await asyncio.wait_for(run_in_threadpool(rdap_lookup, domain), timeout=14)
    except Exception:  # network error, bad JSON, timeout: fall through to WHOIS
        rdap_failed = True
    if data is None:
        try:
            data = await asyncio.wait_for(run_in_threadpool(whois43_lookup, domain), timeout=16)
        except RegistryUnreachable as exc:
            res.update(status="warn", summary="Registry didn't respond", source="WHOIS", server=exc.server)
            res["warnings"].append(f"The .{tld} registry's WHOIS server ({exc.server}) didn't respond, so registration details "
                                   "couldn't be read. This is usually temporary. Try again later.")
            return res
        except Exception as exc:
            res.update(status="error", summary="Lookup failed")
            res["errors"].append(f"IANA's directory of registries couldn't be reached ({type(exc).__name__}). Try again in a minute.")
            return res
    if data is None:
        if rdap_failed:
            res.update(status="warn", summary="Registry didn't respond")
            res["warnings"].append(f"The .{tld} registry's RDAP service didn't respond, and it runs no WHOIS server to fall back to. Try again later.")
        else:
            res.update(status="info", summary="Not published by the registry", unavailable=True)
            res["notes"].append(f"The .{tld} registry doesn't publish registration details online (it runs neither RDAP nor WHOIS), "
                                "so the registrar and expiry date can't be looked up here. The domain's registrar can provide them.")
        return res
    if data.get("not_found"):
        res.update(source=data.get("source"), server=data.get("server"), status="warn", summary="No registry record")
        res["warnings"].append("The registry has no record for this domain. It may be unregistered, or a subdomain of a name we couldn't identify.")
        return res

    res.update(data, found=True)

    # Expiry
    if data.get("expires"):
        days = int((datetime.fromisoformat(data["expires"]) - datetime.now(timezone.utc)).total_seconds() // 86400)
        res["days_to_expiry"] = days
        if days < 0:
            res["errors"].append(f"The registration expired {-days} days ago. Renew it now, before the name is deleted and can be registered by someone else.")
        elif days <= 30:
            res["warnings"].append(f"The registration expires in {days} days. Check auto-renew and the payment method at the registrar.")
    else:
        res["notes"].append("The registry didn't publish an expiry date for this domain.")

    # Status codes
    readable, bad, transfer_locked = [], False, False
    for raw in data.get("statuses", []):
        key = _status_key(raw)
        label, level = STATUS_MEANINGS.get(key, (raw, "ok"))
        readable.append({"code": raw, "label": label, "level": level})
        bad = bad or level == "bad"
        transfer_locked = transfer_locked or key in ("clienttransferprohibited", "servertransferprohibited")
    res["status_labels"] = readable
    if bad:
        res["errors"].append("The registry status shows a problem: " + ", ".join(r["label"] for r in readable if r["level"] == "bad") + ".")
    if data.get("statuses") and not transfer_locked:
        res["notes"].append("No transfer lock is set. Turning on the registrar lock helps protect the domain from being moved without permission.")

    res["status"] = "fail" if res["errors"] else "warn" if res["warnings"] else "pass"
    return res


def nameserver_mismatch(registration: dict, dns_res: dict) -> str | None:
    """Compare the nameservers the registry delegates to with the NS records the zone itself publishes."""
    reg = {n.lower().rstrip(".") for n in registration.get("nameservers") or []}
    live = {str(n).lower().rstrip(".") for n in ((dns_res.get("records") or {}).get("NS") or {}).get("records") or []}
    if not reg or not live or reg == live:
        return None
    only_reg, only_live = sorted(reg - live), sorted(live - reg)
    parts = []
    if only_reg:
        parts.append(f"the registry lists {', '.join(only_reg)} but the zone doesn't")
    if only_live:
        parts.append(f"the zone lists {', '.join(only_live)} but the registry doesn't")
    return ("Nameservers don't match: " + "; ".join(parts) +
            ". This usually means a DNS migration wasn't finished. Update the nameservers at the registrar or in the zone so both agree.")


# ---- 3d-7. Direct DNS queries (to a specific server, not through our resolver) ---------------------
async def ask_server(ip: str, qname: str, rtype: str, recursive: bool = True, timeout: float = 4.0) -> tuple[Any, int]:
    """
    Send one DNS query straight to `ip` and return (response, round-trip ms).
    recursive=False is how you talk to an authoritative nameserver: it must answer
    from its own zone data. Falls back to TCP if the UDP answer was truncated.
    """
    query = dns.message.make_query(qname, rtype)
    if not recursive:
        query.flags &= ~dns.flags.RD
    started = time.monotonic()
    resp = await dns.asyncquery.udp(query, ip, timeout=timeout)
    if resp.flags & dns.flags.TC:
        resp = await dns.asyncquery.tcp(query, ip, timeout=timeout)
    return resp, int((time.monotonic() - started) * 1000)


def rdata_text(rtype: str, r: Any) -> str:
    """One record as a single comparable string (trailing dots removed)."""
    f = _format_rdata(rtype, r)
    if isinstance(f, str):
        return f
    if rtype == "MX":
        return f"{f['preference']} {f['exchange']}"
    if rtype == "CAA":
        return f'{f["flags"]} {f["tag"]} "{f["value"]}"'
    if rtype == "SOA":
        return f"{f['mname']} {f['rname']} {f['serial']}"
    return r.to_text()


def answer_values(resp: Any, rtype: str) -> tuple[list[str], int | None]:
    """Sorted record strings of the requested type from a response, plus the lowest TTL."""
    wanted = dns.rdatatype.from_text(rtype)
    values: set[str] = set()
    ttl = None
    for rrset in resp.answer:
        if rrset.rdtype == wanted:
            ttl = rrset.ttl if ttl is None else min(ttl, rrset.ttl)
            values.update(rdata_text(rtype, r) for r in rrset)
    return sorted(values), ttl


async def find_zone(domain: str) -> tuple[str | None, list[str]]:
    """NS records live at the zone apex: www.shop.example.com -> ('example.com', [ns hosts])."""
    for name in _candidates(domain):
        try:
            ns = await resolve(name, "NS")
        except DNSLookupError:
            continue
        if ns:
            return name, sorted({r.target.to_text(omit_final_dot=True).lower() for r in ns})
    return None, []


# ---- 3d-8. Nameserver health ----------------------------------------------------------------------------
async def _probe_nameserver(host: str, zone: str) -> dict:
    out: dict[str, Any] = {"host": host, "ip": None, "reachable": False, "authoritative": False,
                           "serial": None, "rtt_ms": None, "error": None}
    ips = [ip for ip in await _ips_of(host) if ":" not in ip and is_public_ip(ip)]
    if not ips:
        out["error"] = "Hostname doesn't resolve to a public IPv4 address."
        return out
    out["ip"] = ips[0]
    try:
        resp, rtt = await ask_server(ips[0], zone, "SOA", recursive=False, timeout=4)
    except dns.exception.Timeout:
        out["error"] = "No answer within 4 seconds."
        return out
    except OSError as exc:
        out["error"] = f"Network error: {exc.strerror or exc}"
        return out
    out["reachable"], out["rtt_ms"] = True, rtt
    rcode = dns.rcode.to_text(resp.rcode())
    out["authoritative"] = bool(resp.flags & dns.flags.AA) and rcode == "NOERROR"
    soa = [r for rrset in resp.answer if rrset.rdtype == dns.rdatatype.SOA for r in rrset]
    if soa:
        out["serial"] = soa[0].serial
    if not out["authoritative"]:
        out["error"] = f"Answered {rcode} without authority. It doesn't serve this zone (lame delegation)."
    return out


async def analyze_nameservers(domain: str) -> dict:
    res: dict[str, Any] = {"status": "pass", "zone": None, "servers": [], "errors": [], "warnings": [], "notes": []}
    zone, hosts = await find_zone(domain)
    if not zone:
        res["status"] = "fail"
        res["errors"].append("No NS records were found for this domain or its parents.")
        return res
    res["zone"] = zone
    res["servers"] = list(await asyncio.gather(*(_probe_nameserver(h, zone) for h in hosts[:8])))

    if len(hosts) < 2:
        res["errors"].append("Only one nameserver is listed. Use at least two, on separate networks, so the domain stays up if one fails.")
    dead = [s["host"] for s in res["servers"] if not s["reachable"]]
    lame = [s["host"] for s in res["servers"] if s["reachable"] and not s["authoritative"]]
    if dead:
        res["errors"].append(f"Not answering: {', '.join(dead)}. Resolvers that try these servers will see slow or failed lookups.")
    if lame:
        res["errors"].append(f"Not authoritative for {zone}: {', '.join(lame)}. Remove them from the NS records or add the zone to them.")
    serials = {s["serial"] for s in res["servers"] if s["serial"] is not None}
    if len(serials) > 1:
        detail = ", ".join(f"{s['host']} = {s['serial']}" for s in res["servers"] if s["serial"] is not None)
        res["warnings"].append(f"SOA serials differ ({detail}). Some nameservers haven't picked up the latest zone changes yet.")
    v4 = [s["ip"] for s in res["servers"] if s["ip"]]
    if len(v4) >= 2 and len({ip.rsplit(".", 1)[0] for ip in v4}) == 1:
        res["warnings"].append("All nameservers share one /24 network. A single network problem could take them all down.")
    slow = [s for s in res["servers"] if s["rtt_ms"] and s["rtt_ms"] > 500]
    if slow:
        res["notes"].append("Slow to answer (over 500 ms from our server): " + ", ".join(s["host"] for s in slow) + ".")
    res["notes"].append("Checked over IPv4 from our server's region.")
    res["status"] = _status(res["errors"], res["warnings"])
    return res


# ---- 3d-9. Propagation: what do public resolvers currently answer? ----------------------------------
PROPAGATION_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "CAA")
PUBLIC_RESOLVERS: tuple[tuple[str, str, str], ...] = (
    ("Cloudflare", "1.1.1.1", "Anycast"),
    ("Google", "8.8.8.8", "Anycast"),
    ("Quad9", "9.9.9.9", "Anycast"),
    ("OpenDNS", "208.67.222.222", "Anycast"),
    ("AdGuard", "94.140.14.14", "Anycast"),
    ("Control D", "76.76.2.0", "Anycast"),
    ("Lumen (Level 3)", "4.2.2.1", "United States"),
    ("DNS.Watch", "84.200.69.80", "Germany"),
)


async def _ask_for_row(name: str, ip: str, place: str, qname: str, rtype: str, recursive: bool) -> dict:
    row: dict[str, Any] = {"name": name, "ip": ip, "location": place, "values": [], "ttl": None,
                           "rcode": None, "rtt_ms": None, "error": None}
    try:
        resp, rtt = await ask_server(ip, qname, rtype, recursive=recursive, timeout=4)
        row["rtt_ms"], row["rcode"] = rtt, dns.rcode.to_text(resp.rcode())
        row["values"], row["ttl"] = answer_values(resp, rtype)
    except dns.exception.Timeout:
        row["error"] = "No answer within 4 seconds"
    except OSError as exc:
        row["error"] = f"Network error: {exc.strerror or exc}"
    return row


def _answer_key(row: dict) -> tuple:
    """What a row 'says', for comparison. Errors never count towards the consensus."""
    if row["error"]:
        return ("ERROR",)
    if row["rcode"] != "NOERROR":
        return (row["rcode"],)
    return tuple(row["values"]) or ("NO RECORDS",)


async def check_propagation(domain: str, rtype: str) -> dict:
    zone, ns_hosts = await find_zone(domain)
    tasks = [_ask_for_row(n, ip, place, domain, rtype, True) for n, ip, place in PUBLIC_RESOLVERS]
    auth_task = None
    if ns_hosts:
        ns_ips = [ip for ip in await _ips_of(ns_hosts[0]) if ":" not in ip and is_public_ip(ip)]
        if ns_ips:
            auth_task = _ask_for_row(ns_hosts[0], ns_ips[0], "Authoritative", domain, rtype, False)
    rows = list(await asyncio.gather(*tasks, *( [auth_task] if auth_task else [] )))
    authoritative = rows.pop() if auth_task else None

    answered = [r for r in rows if not r["error"]]
    counts = Counter(_answer_key(r) for r in answered)
    consensus = counts.most_common(1)[0][0] if counts else None
    for r in rows:
        r["matches"] = None if r["error"] else _answer_key(r) == consensus

    differing = [r["name"] for r in rows if r["matches"] is False]
    failed = [r["name"] for r in rows if r["error"]]
    auth_key = _answer_key(authoritative) if authoritative else None
    if authoritative:
        authoritative["matches"] = None if authoritative["error"] else auth_key == consensus

    if not answered:
        status, summary = "error", "None of the resolvers answered. Try again in a minute."
    elif differing:
        status = "warn"
        summary = (f"{len(differing)} of {len(answered)} resolvers show a different answer. "
                   "They're still serving a cached older record; this clears as their copies expire (see TTL).")
    elif authoritative and not authoritative["error"] and authoritative["matches"] is False and auth_key != ("NO RECORDS",):
        status = "warn"
        summary = "Every public resolver agrees, but the authoritative nameserver now says something different. The change hasn't reached these caches yet."
    else:
        status, summary = "pass", f"All {len(answered)} resolvers that answered return the same result."
    return {"domain": domain, "type": rtype, "zone": zone, "status": status, "summary": summary,
            "consensus": list(consensus) if consensus else [], "authoritative": authoritative, "resolvers": rows,
            "failed": failed,
            "note": "Anycast resolvers answer from their site nearest to our server, so this shows how the change looks from that region."}


# ---- 3d-10. MTA-STS, TLS-RPT and BIMI (optional email security records) -----------------------------
def _fetch_text(url: str, limit: int = 65536) -> tuple[int, str]:
    """HTTPS GET with full certificate checks. Returns (status code, body text)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=REG_HTTP_TIMEOUT, context=ssl.create_default_context()) as resp:
        return resp.status, resp.read(limit).decode("utf-8", errors="replace")


def _mx_pattern_matches(pattern: str, host: str) -> bool:
    """MTA-STS mx patterns: exact host, or '*.example.com' matching exactly one extra label."""
    pattern, host = pattern.lower().rstrip("."), host.lower().rstrip(".")
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host.count(".") == pattern.count(".")
    return pattern == host


async def analyze_mail_security(domain: str) -> dict:
    res: dict[str, Any] = {"status": "info", "mta_sts": {"found": False}, "tls_rpt": {"found": False},
                           "bimi": {"found": False}, "errors": [], "warnings": [], "notes": []}
    mta_txt, rpt_txt, bimi_txt = await asyncio.gather(
        get_txt(f"_mta-sts.{domain}"), get_txt(f"_smtp._tls.{domain}"), get_txt(f"default._bimi.{domain}"))

    # --- MTA-STS: a TXT record announces a policy; the policy itself is a file served over HTTPS
    mta = [t for t in mta_txt if t.lower().replace(" ", "").startswith("v=stsv1")]
    if mta:
        sts: dict[str, Any] = {"found": True, "record": mta[0], "id": _parse_tag_list(mta[0]).get("id"),
                               "policy_url": f"https://mta-sts.{domain}/.well-known/mta-sts.txt", "policy": None}
        res["mta_sts"] = sts
        host_ips = await _ips_of(f"mta-sts.{domain}")
        if not host_ips:
            res["errors"].append(f"MTA-STS is announced but mta-sts.{domain} doesn't resolve, so senders can't fetch the policy.")
        elif not all(is_public_ip(ip) for ip in host_ips):
            res["errors"].append(f"mta-sts.{domain} points to a private address, so senders can't fetch the policy.")
        else:
            try:
                code, body = await asyncio.wait_for(run_in_threadpool(_fetch_text, sts["policy_url"]), timeout=12)
                policy: dict[str, Any] = {"mx": []}
                for line in body.splitlines():
                    if ":" in line:
                        k, v = (x.strip() for x in line.split(":", 1))
                        if k.lower() == "mx":
                            policy["mx"].append(v)
                        else:
                            policy[k.lower()] = v
                sts["policy"] = policy
                if policy.get("version") != "STSv1":
                    res["errors"].append("The MTA-STS policy file doesn't start with 'version: STSv1'.")
                mode = policy.get("mode", "").lower()
                if mode not in ("enforce", "testing", "none"):
                    res["errors"].append("The MTA-STS policy has no valid mode (enforce, testing or none).")
                elif mode == "testing":
                    res["notes"].append("MTA-STS is in testing mode: failures are reported but mail is still delivered. Switch to enforce once TLS reports look clean.")
                elif mode == "none":
                    res["warnings"].append("MTA-STS mode is 'none', so the policy isn't protecting anything.")
                try:
                    if int(policy.get("max_age", "0")) < 86400:
                        res["warnings"].append("MTA-STS max_age is under 1 day. Senders will re-fetch the policy too often; a week or more is typical.")
                except ValueError:
                    res["errors"].append("MTA-STS max_age isn't a number.")
                if not policy["mx"]:
                    res["errors"].append("The MTA-STS policy lists no mx: lines, so no mail server is allowed.")
            except urllib.error.HTTPError as exc:
                res["errors"].append(f"The MTA-STS policy URL returned HTTP {exc.code}. It must serve the policy file at {sts['policy_url']}.")
            except (ssl.SSLError, ssl.CertificateError) as exc:
                res["errors"].append(f"The MTA-STS policy host has an invalid certificate ({getattr(exc, 'reason', None) or exc}). Senders will ignore the policy.")
            except Exception as exc:  # timeout, connection refused, etc.
                res["errors"].append(f"The MTA-STS policy couldn't be fetched ({type(exc).__name__}).")

    # --- TLS-RPT: where to send reports about TLS failures
    rpt = [t for t in rpt_txt if t.lower().replace(" ", "").startswith("v=tlsrptv1")]
    if rpt:
        rua = [x.strip() for x in _parse_tag_list(rpt[0]).get("rua", "").split(",") if x.strip()]
        res["tls_rpt"] = {"found": True, "record": rpt[0], "rua": rua}
        if not rua or not all(x.lower().startswith(("mailto:", "https://")) for x in rua):
            res["errors"].append("TLS-RPT needs rua= with mailto: or https:// destinations.")
    elif mta:
        res["warnings"].append(f"MTA-STS is set up without TLS-RPT. Add a TXT record at _smtp._tls.{domain} so you hear about delivery failures.")

    # --- BIMI: brand logo shown next to your mail in supporting inboxes
    bimi = [t for t in bimi_txt if t.lower().replace(" ", "").startswith("v=bimi1")]
    if bimi:
        tags = _parse_tag_list(bimi[0])
        logo, vmc = tags.get("l", ""), tags.get("a", "")
        res["bimi"] = {"found": True, "record": bimi[0], "logo_url": logo or None, "certificate_url": vmc or None}
        if logo and not (logo.lower().startswith("https://") and logo.lower().endswith(".svg")):
            res["errors"].append("BIMI l= must be an https:// URL ending in .svg (SVG Tiny PS format).")
        if not vmc:
            res["notes"].append("BIMI has no a= certificate (VMC or CMC). Gmail and Apple Mail only show the logo with one.")

    if not (mta or rpt or bimi):
        res["notes"].append("None of these optional protections are set up. MTA-STS with TLS-RPT is worth adding if you receive sensitive mail.")
        return res
    res["status"] = _status(res["errors"], res["warnings"])
    return res


def cross_check_mail_security(sec: dict, mail: dict, dmarc: dict) -> None:
    """Checks that need other sections: MTA-STS must cover every MX; BIMI needs an enforcing DMARC policy."""
    policy = (sec.get("mta_sts") or {}).get("policy") or {}
    if policy.get("mx"):
        uncovered = [m["host"] for m in (mail.get("mx") or []) if not m.get("implicit")
                     and not any(_mx_pattern_matches(p, m["host"]) for p in policy["mx"])]
        if uncovered:
            sec["errors"].append(f"These MX hosts aren't in the MTA-STS policy, so enforcing senders will refuse to deliver to them: {', '.join(uncovered)}.")
    if (sec.get("bimi") or {}).get("found"):
        if dmarc.get("policy") not in ("quarantine", "reject") or dmarc.get("pct", 100) < 100:
            sec["errors"].append("BIMI only works with DMARC at p=quarantine or p=reject and pct=100. The logo won't show yet.")
    if sec.get("status") != "info":
        sec["status"] = _status(sec["errors"], sec["warnings"])


# ---- 3d-12. Website: is it up, redirects, response headers, security headers, technologies ----------
# We write our own small HTTP client (instead of urllib's automatic redirects) for safety:
# every hop's hostname is resolved by us, checked with is_public_ip(), and the
# connection goes to THAT exact IP. A redirect to an internal address is refused.
HTTP_TIMEOUT = 8.0
MAX_REDIRECTS = 8
BODY_LIMIT = 600_000          # bytes of HTML read for technology detection
REDIRECT_CODES = {301, 302, 303, 307, 308}
HTTP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
           "Chrome/130.0 Safari/537.36 VdigDNS/1.0 (+https://dig.sujaiprojects.stream)")


class NoAddress(Exception):
    """The hostname has no A/AAAA record."""


class BlockedTarget(Exception):
    """The hostname points only to private/reserved addresses (SSRF protection)."""


def _resolve_public(host: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise NoAddress(host) from exc
    ips = list(dict.fromkeys(info[4][0] for info in infos))
    public = [ip for ip in ips if is_public_ip(ip)]
    if not public:
        raise BlockedTarget(host)
    return next((ip for ip in public if ":" not in ip), public[0])  # prefer IPv4


def _header(headers: list[tuple[str, str]], name: str) -> str | None:
    name = name.lower()
    return next((v for k, v in headers if k.lower() == name), None)


def _decode_body(raw: bytes, encoding: str | None) -> bytes:
    """Undo gzip/deflate. The body may be cut off at BODY_LIMIT, so decompress what's there."""
    enc = (encoding or "").lower().strip()
    try:
        if enc == "gzip":
            return zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(raw, BODY_LIMIT * 4)
        if enc == "deflate":
            try:
                return zlib.decompressobj().decompress(raw, BODY_LIMIT * 4)
            except zlib.error:
                return zlib.decompressobj(-zlib.MAX_WBITS).decompress(raw, BODY_LIMIT * 4)
    except zlib.error:
        return b""
    return raw if enc in ("", "identity") else b""


def _http_get(url: str, verify: bool = True) -> dict:
    """One GET request, no redirects followed. Blocking."""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    ip = _resolve_public(host, port)
    started = time.monotonic()
    sock = socket.create_connection((ip, port), timeout=HTTP_TIMEOUT)
    try:
        if scheme == "https":
            ctx = ssl.create_default_context()
            if not verify:
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
            ctx.set_alpn_protocols(["http/1.1"])  # http.client only speaks HTTP/1.1
            sock = ctx.wrap_socket(sock, server_hostname=host)
        conn = http.client.HTTPConnection(host, port, timeout=HTTP_TIMEOUT)
        conn.sock = sock  # already connected to the IP we checked
        conn.putrequest("GET", path, skip_host=True, skip_accept_encoding=True)
        for key, value in (("Host", host if parts.port in (None, 80, 443) else f"{host}:{port}"),
                           ("User-Agent", HTTP_UA),
                           ("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
                           ("Accept-Encoding", "gzip, deflate"), ("Accept-Language", "en"), ("Connection", "close")):
            conn.putheader(key, value)
        conn.endheaders()
        resp = conn.getresponse()
        first_byte_ms = int((time.monotonic() - started) * 1000)
        headers = resp.getheaders()
        body = b"" if resp.status in REDIRECT_CODES or resp.status in (204, 304) else resp.read(BODY_LIMIT)
        return {"url": url, "status": resp.status, "reason": resp.reason or "", "headers": headers, "raw_body": body,
                "ttfb_ms": first_byte_ms, "ip": ip}
    finally:
        sock.close()


def _follow(url: str, verify: bool = True) -> tuple[list[dict], dict]:
    """GET and follow redirects (max 8). Returns (hops, final response)."""
    hops: list[dict] = []
    seen: set[str] = set()
    resp: dict = {}
    for _ in range(MAX_REDIRECTS + 1):
        seen.add(url)
        resp = _http_get(url, verify)
        hops.append({"url": url, "status": resp["status"], "reason": resp["reason"], "ms": resp["ttfb_ms"]})
        location = _header(resp["headers"], "location")
        if resp["status"] in REDIRECT_CODES and location:
            nxt = urllib.parse.urljoin(url, location.strip())
            if urllib.parse.urlsplit(nxt).scheme.lower() not in ("http", "https"):
                return hops, resp
            if nxt in seen:
                resp["redirect_loop"] = True
                return hops, resp
            url = nxt
            continue
        return hops, resp
    resp["redirect_loop"] = True  # too many redirects
    return hops, resp


def _describe_failure(exc: Exception) -> str:
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return f"no answer within {HTTP_TIMEOUT:.0f} seconds"
    if isinstance(exc, ConnectionRefusedError):
        return "connection refused, nothing is listening"
    if isinstance(exc, ssl.SSLError):
        return f"the secure connection failed ({exc.reason or exc})"
    if isinstance(exc, http.client.HTTPException):
        return "the server sent an invalid HTTP response"
    if isinstance(exc, OSError):
        return f"network error ({exc.strerror or type(exc).__name__})"
    return type(exc).__name__


# ---- Technology detection (like Wappalyzer / BuiltWith, with our own signatures) ----
# (name, category, where to look, pattern). Where: "html" = page code, "gen" = <meta name="generator">,
# "cookie" = cookie names, "h:<name>" = a response header. A capture group, when present, is the version.
TECH_RULES: tuple[tuple[str, str, str, str], ...] = (
    # CMS
    ("WordPress", "CMS", "gen", r"WordPress\s*([\d.]+)?"),
    ("WordPress", "CMS", "html", r"/wp-(?:content|includes)/"),
    ("WordPress", "CMS", "h:link", r"api\.w\.org"),
    ("Joomla", "CMS", "gen", r"Joomla!?\s*([\d.]+)?"),
    ("Joomla", "CMS", "html", r"/media/(?:jui|system)/js/|/components/com_[a-z]+/"),
    ("Drupal", "CMS", "gen", r"Drupal\s*([\d.]+)?"),
    ("Drupal", "CMS", "h:x-generator", r"Drupal\s*([\d.]+)?"),
    ("Drupal", "CMS", "h:x-drupal-cache", r"."),
    ("Drupal", "CMS", "html", r"/sites/(?:default|all)/files/|drupal-settings-json"),
    ("Ghost", "CMS", "gen", r"Ghost\s*([\d.]+)?"),
    ("TYPO3", "CMS", "gen", r"TYPO3"),
    ("Umbraco", "CMS", "html", r"/umbraco/"),
    ("Craft CMS", "CMS", "h:x-powered-by", r"Craft CMS"),
    ("Blogger", "CMS", "gen", r"Blogger"),
    ("Hugo", "Static site generator", "gen", r"Hugo\s*([\d.]+)?"),
    ("Jekyll", "Static site generator", "gen", r"Jekyll\s*v?([\d.]+)?"),
    ("Docusaurus", "Static site generator", "gen", r"Docusaurus\s*v?([\d.]+)?"),
    # Website builders
    ("Wix", "Website builder", "h:x-wix-request-id", r"."),
    ("Wix", "Website builder", "html", r"static\.wixstatic\.com|static\.parastorage\.com"),
    ("Squarespace", "Website builder", "html", r"static1\.squarespace\.com|squarespace-cdn\.com"),
    ("Webflow", "Website builder", "html", r"data-wf-(?:page|site)=|website-files\.com"),
    ("Framer", "Website builder", "html", r"framerusercontent\.com"),
    ("Weebly", "Website builder", "html", r"editmysite\.com|weebly\.com/weebly/"),
    ("GoDaddy Website Builder", "Website builder", "gen", r"Go Daddy Website Builder|Starfield Technologies"),
    ("GoDaddy Website Builder", "Website builder", "html", r"img1\.wsimg\.com/blobby"),
    ("Duda", "Website builder", "html", r"multiscreensite\.com|dudaone\.com"),
    ("Carrd", "Website builder", "html", r"carrd\.co"),
    # E-commerce
    ("Shopify", "E-commerce", "h:x-shopid", r"."),
    ("Shopify", "E-commerce", "html", r"cdn\.shopify\.com|Shopify\.theme"),
    ("WooCommerce", "E-commerce", "html", r"woocommerce"),
    ("Magento", "E-commerce", "html", r"Mage\.Cookies|data-mage-init|/static/version\d+/frontend/"),
    ("PrestaShop", "E-commerce", "gen", r"PrestaShop"),
    ("PrestaShop", "E-commerce", "cookie", r"PrestaShop-"),
    ("OpenCart", "E-commerce", "html", r"catalog/view/theme/|index\.php\?route=common/"),
    ("BigCommerce", "E-commerce", "html", r"cdn\d*\.bigcommerce\.com"),
    # JavaScript frameworks
    ("Next.js", "JavaScript framework", "h:x-powered-by", r"Next\.js\s*([\d.]+)?"),
    ("Next.js", "JavaScript framework", "html", r"__NEXT_DATA__|/_next/static/"),
    ("Nuxt", "JavaScript framework", "html", r"__NUXT__|/_nuxt/"),
    ("Gatsby", "JavaScript framework", "html", r'id="___gatsby"'),
    ("Remix", "JavaScript framework", "html", r"__remixContext"),
    ("SvelteKit", "JavaScript framework", "html", r"__sveltekit|data-sveltekit"),
    ("Astro", "JavaScript framework", "html", r"<astro-island|/_astro/"),
    ("Angular", "JavaScript framework", "html", r'ng-version="([\d.]+)"'),
    ("React", "JavaScript framework", "html", r"data-reactroot|react-dom(?:\.production)?(?:\.min)?\.js"),
    ("Vue.js", "JavaScript framework", "html", r"data-v-[0-9a-f]{8}|vue(?:\.runtime)?(?:\.global)?(?:\.prod)?(?:\.min)?\.js"),
    # Back-end frameworks and languages
    ("Laravel", "Web framework", "cookie", r"laravel_session"),
    ("Django", "Web framework", "html", r"csrfmiddlewaretoken"),
    ("Ruby on Rails", "Web framework", "html", r'name="csrf-param" content="authenticity_token"'),
    ("Express", "Web framework", "h:x-powered-by", r"Express"),
    ("ASP.NET", "Web framework", "h:x-aspnet-version", r"([\d.]+)"),
    ("ASP.NET", "Web framework", "h:x-powered-by", r"ASP\.NET"),
    ("ASP.NET", "Web framework", "html", r"__VIEWSTATE"),
    ("ASP.NET", "Web framework", "cookie", r"ASP\.NET_SessionId"),
    ("PHP", "Programming language", "h:x-powered-by", r"PHP/?([\d.]+)?"),
    ("PHP", "Programming language", "cookie", r"PHPSESSID"),
    # Web servers
    ("Nginx", "Web server", "h:server", r"nginx(?:/([\d.]+))?"),
    ("Apache", "Web server", "h:server", r"Apache(?:/([\d.]+))?"),
    ("LiteSpeed", "Web server", "h:server", r"LiteSpeed"),
    ("Microsoft IIS", "Web server", "h:server", r"Microsoft-IIS(?:/([\d.]+))?"),
    ("Caddy", "Web server", "h:server", r"Caddy"),
    ("OpenResty", "Web server", "h:server", r"openresty(?:/([\d.]+))?"),
    ("Envoy", "Web server", "h:server", r"envoy"),
    # CDN and hosting
    ("Cloudflare", "CDN & hosting", "h:cf-ray", r"."),
    ("Amazon CloudFront", "CDN & hosting", "h:x-amz-cf-id", r"."),
    ("Fastly", "CDN & hosting", "h:x-fastly-request-id", r"."),
    ("Fastly", "CDN & hosting", "h:x-served-by", r"cache-[a-z]{3}"),
    ("Akamai", "CDN & hosting", "h:server", r"AkamaiGHost|AkamaiNetStorage"),
    ("Vercel", "CDN & hosting", "h:x-vercel-id", r"."),
    ("Netlify", "CDN & hosting", "h:x-nf-request-id", r"."),
    ("GitHub Pages", "CDN & hosting", "h:server", r"GitHub\.com"),
    ("Varnish", "CDN & hosting", "h:x-varnish", r"."),
    ("WP Engine", "CDN & hosting", "h:x-powered-by", r"WP Engine"),
    ("Kinsta", "CDN & hosting", "h:x-kinsta-cache", r"."),
    ("Bunny CDN", "CDN & hosting", "h:server", r"BunnyCDN"),
    ("Azure Front Door", "CDN & hosting", "h:x-azure-ref", r"."),
    ("Sucuri", "Security", "h:x-sucuri-id", r"."),
    # Analytics and marketing
    ("Google Analytics", "Analytics & marketing", "html", r"google-analytics\.com/(?:analytics|ga)\.js|gtag/js\?id=G-"),
    ("Google Tag Manager", "Analytics & marketing", "html", r"googletagmanager\.com/gtm\.js"),
    ("Meta Pixel", "Analytics & marketing", "html", r"connect\.facebook\.net/[^\"']*/fbevents\.js"),
    ("Hotjar", "Analytics & marketing", "html", r"static\.hotjar\.com"),
    ("HubSpot", "Analytics & marketing", "html", r"js\.hs-scripts\.com|js\.hsforms\.net"),
    ("Microsoft Clarity", "Analytics & marketing", "html", r"clarity\.ms/tag"),
    ("Matomo", "Analytics & marketing", "html", r"matomo\.js|piwik\.js"),
    ("Plausible", "Analytics & marketing", "html", r"plausible\.io/js"),
    # JavaScript libraries and widgets
    ("jQuery", "JavaScript library", "html", r"jquery[.-]?(\d+\.\d+(?:\.\d+)?)?(?:\.slim)?(?:\.min)?\.js"),
    ("Bootstrap", "JavaScript library", "html", r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)"),
    ("Font Awesome", "JavaScript library", "html", r"font-?awesome"),
    ("reCAPTCHA", "Security", "html", r"google\.com/recaptcha|recaptcha/api\.js"),
    ("Cloudflare Turnstile", "Security", "html", r"challenges\.cloudflare\.com/turnstile"),
)
TECH_IMPLIES: dict[str, tuple[str, ...]] = {
    "WordPress": ("PHP",), "WooCommerce": ("WordPress", "PHP"), "Joomla": ("PHP",), "Drupal": ("PHP",),
    "Magento": ("PHP",), "PrestaShop": ("PHP",), "OpenCart": ("PHP",), "Laravel": ("PHP",),
    "Next.js": ("React",), "Gatsby": ("React",), "Remix": ("React",), "Nuxt": ("Vue.js",),
}
TECH_CATEGORY_ORDER = ("CMS", "Website builder", "E-commerce", "Static site generator", "JavaScript framework",
                       "Web framework", "Programming language", "Web server", "CDN & hosting", "Security",
                       "Analytics & marketing", "JavaScript library")
_TECH_CATEGORY = {name: cat for name, cat, _, _ in TECH_RULES}
_EVIDENCE = {"html": "page code", "gen": "generator tag", "cookie": "cookie"}


def detect_technologies(headers: list[tuple[str, str]], page: str) -> list[dict]:
    values: dict[str, list[str]] = {}
    for key, value in headers:
        values.setdefault(key.lower(), []).append(value)
    joined = {key: " ".join(v) for key, v in values.items()}
    cookies = " ".join(c.split("=", 1)[0].strip() for c in values.get("set-cookie", []))
    generators = re.findall(r"<meta[^>]+name=[\"']generator[\"'][^>]*content=[\"']([^\"']+)", page, re.I)
    generators += re.findall(r"<meta[^>]+content=[\"']([^\"']+)[\"'][^>]*name=[\"']generator[\"']", page, re.I)
    sources = {"html": page, "gen": " | ".join(generators), "cookie": cookies}

    found: dict[str, dict] = {}
    for name, category, where, pattern in TECH_RULES:
        haystack = joined.get(where[2:], "") if where.startswith("h:") else sources.get(where, "")
        match = re.search(pattern, haystack, re.I) if haystack else None
        if not match:
            continue
        entry = found.setdefault(name, {"name": name, "category": category, "version": None, "evidence": []})
        version = next((g for g in match.groups() if g), None)
        if version and not entry["version"]:
            entry["version"] = version.strip(".")
        label = f"{where[2:].title()} header" if where.startswith("h:") else _EVIDENCE[where]
        if label not in entry["evidence"]:
            entry["evidence"].append(label)
    for name in list(found):
        for implied in TECH_IMPLIES.get(name, ()):
            found.setdefault(implied, {"name": implied, "category": _TECH_CATEGORY.get(implied, "Programming language"),
                                       "version": None, "evidence": [f"used by {name}"]})
    order = {cat: i for i, cat in enumerate(TECH_CATEGORY_ORDER)}
    return sorted(found.values(), key=lambda t: (order.get(t["category"], 99), t["name"]))


SECURITY_HEADERS: tuple[tuple[str, str, str], ...] = (
    ("strict-transport-security", "Strict-Transport-Security", "Makes browsers always use HTTPS for this site."),
    ("content-security-policy", "Content-Security-Policy", "Limits where scripts and other content can load from."),
    ("x-frame-options", "X-Frame-Options", "Stops other sites from embedding this one (clickjacking)."),
    ("x-content-type-options", "X-Content-Type-Options", "Stops browsers from guessing file types."),
    ("referrer-policy", "Referrer-Policy", "Controls what is shared when visitors follow a link away."),
    ("permissions-policy", "Permissions-Policy", "Limits access to the camera, location and similar features."),
)


def _security_headers(headers: list[tuple[str, str]], https: bool) -> list[dict]:
    out = []
    csp = _header(headers, "content-security-policy") or ""
    for key, name, explain in SECURITY_HEADERS:
        value = _header(headers, key)
        if key == "x-frame-options" and not value and "frame-ancestors" in csp.lower():
            value = "covered by Content-Security-Policy frame-ancestors"
        if key == "strict-transport-security" and not https:
            value = None  # HSTS only counts when sent over HTTPS
        note = None
        if key == "strict-transport-security" and value:
            m = re.search(r"max-age\s*=\s*(\d+)", value, re.I)
            if not m or int(m.group(1)) < 15552000:
                note = "max-age is under 6 months"
        out.append({"header": name, "present": bool(value), "value": (value or "")[:300], "explain": explain, "note": note})
    return out


_CHALLENGE = re.compile(r"Just a moment\.\.\.|cf-chl|cf_chl_|Attention Required! \| Cloudflare|_Incapsula_|sgcaptcha", re.I)


async def analyze_website(domain: str) -> dict:
    res: dict[str, Any] = {"status": "fail", "state": "down", "errors": [], "warnings": [], "notes": [],
                           "hops": [], "headers": [], "security": [], "technologies": []}

    def secure_chain() -> tuple[list[dict], dict, bool]:
        try:
            hops, final = _follow(f"https://{domain}/", verify=True)
            return hops, final, False
        except ssl.SSLCertVerificationError:
            hops, final = _follow(f"https://{domain}/", verify=False)  # still learn whether the site is up
            return hops, final, True

    https_try, http_try = await asyncio.gather(
        asyncio.wait_for(run_in_threadpool(secure_chain), timeout=24),
        asyncio.wait_for(run_in_threadpool(_http_get, f"http://{domain}/"), timeout=12),
        return_exceptions=True)

    # Does plain http:// send visitors to https://?
    if isinstance(http_try, dict):
        location = _header(http_try["headers"], "location") or ""
        res["https_redirect"] = http_try["status"] in REDIRECT_CODES and location.lower().startswith("https://")
        res["http_status"] = http_try["status"]
    else:
        res["https_redirect"] = None  # port 80 closed or unreachable: nothing to redirect

    cert_invalid = False
    if isinstance(https_try, tuple):
        hops, final, cert_invalid = https_try
    else:
        if isinstance(https_try, (NoAddress, BlockedTarget)):
            if isinstance(https_try, NoAddress):
                res.update(status="info", state="no_site", summary="No website address")
                res["notes"].append("The domain has no A or AAAA record, so there's no website to check.")
            else:
                res.update(status="info", state="blocked", summary="Not checked")
                res["notes"].append("The domain points to a private or reserved address, so it can't be reached from the internet.")
            return res
        https_reason = _describe_failure(https_try)
        try:  # HTTPS failed: is the site at least up over plain HTTP?
            hops, final = await asyncio.wait_for(run_in_threadpool(_follow, f"http://{domain}/"), timeout=20)
            res["warnings"].append(f"HTTPS doesn't work ({https_reason}). The site only loads over plain, unencrypted HTTP.")
        except Exception as exc:
            res["summary"] = "Down"
            http_reason = _describe_failure(exc)
            why = https_reason if http_reason == https_reason else f"HTTPS: {https_reason}; HTTP: {http_reason}"
            res["errors"].append(f"The website didn't respond over HTTPS or HTTP ({why}). Visitors can't open it.")
            return res

    headers = final["headers"]
    status = final["status"]
    content_type = (_header(headers, "content-type") or "").lower()
    body = _decode_body(final.get("raw_body", b""), _header(headers, "content-encoding"))
    page = body.decode("utf-8", errors="replace") if ("html" in content_type or body.lstrip()[:1] == b"<") else ""
    title_match = re.search(r"<title[^>]*>(.*?)</title>", page, re.S | re.I)
    final_https = final["url"].lower().startswith("https://")

    res.update({
        "status_code": status, "reason": final["reason"], "final_url": final["url"], "ip": final["ip"],
        "response_ms": final["ttfb_ms"], "hops": hops, "redirects": len(hops) - 1,
        "cert_invalid": cert_invalid, "server": _header(headers, "server"),
        "powered_by": _header(headers, "x-powered-by"), "compression": _header(headers, "content-encoding"),
        "content_type": _header(headers, "content-type"),
        "title": re.sub(r"\s+", " ", html.unescape(title_match.group(1))).strip()[:160] if title_match else None,
        "headers": [[k, v[:400]] for k, v in headers[:60]],
        "security": _security_headers(headers, final_https),
        "technologies": detect_technologies(headers, page),
    })

    challenged = status in (403, 429, 503) and (
        (_header(headers, "cf-mitigated") or "").lower() == "challenge" or bool(_CHALLENGE.search(page[:20000])))
    if final.get("redirect_loop"):
        res.update(state="redirect_loop", summary="Redirect loop")
        res["errors"].append("The site keeps redirecting (a loop, or more than 8 redirects). Browsers will show an error.")
    elif challenged:
        res.update(state="challenge", summary="Up, behind a bot check")
        res["notes"].append("A bot-protection page answered instead of the website. Real visitors probably see the site "
                            "normally, but technology detection is limited.")
    elif 200 <= status < 300:
        res.update(state="up", summary=f"Up, {status} {final['reason']} in {final['ttfb_ms']} ms".strip())
    elif status >= 500:
        res.update(state="server_error", summary=f"Server error {status}")
        res["errors"].append(f"The home page returns {status} {final['reason']}. The web server or application is failing.")
    else:
        res.update(state="client_error", summary=f"Returns {status}")
        res["warnings"].append(f"The home page returns {status} {final['reason']}."
                               + (" The server may be blocking automated checks like this one." if status in (401, 403, 429) else ""))

    if res["state"] in ("up", "challenge"):
        if cert_invalid:
            res["warnings"].append("The site only loaded after ignoring a certificate error. Browsers will show a security "
                                   "warning (see the SSL section).")
        if res["https_redirect"] is False and final_https:
            res["warnings"].append("http:// doesn't redirect to https://. Visitors who type the address without https stay "
                                   "on an unencrypted connection.")
        if final["ttfb_ms"] > 1500:
            res["warnings"].append(f"The first response took {final['ttfb_ms'] / 1000:.1f} s. Under 0.8 s is good; slow "
                                   "responses usually mean a slow server or no caching.")
        if final_https and not any(h["present"] for h in res["security"] if h["header"] == "Strict-Transport-Security"):
            res["notes"].append("No HSTS header. Adding Strict-Transport-Security makes browsers always use HTTPS.")
    if res["state"] == "challenge" and not res["errors"] and not res["warnings"]:
        res["status"] = "info"   # up as far as we can tell; the bot check isn't a fault
    else:
        res["status"] = _status(res["errors"], res["warnings"])
    return res


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
def _fetch_peer_cert(ip: str, server_name: str, ctx: ssl.SSLContext) -> tuple[bytes, str, str, str | None]:
    """
    Open TCP to ip:443, do the TLS handshake with SNI=server_name, return the raw cert,
    TLS version, cipher, and the ALPN protocol agreed ("h2" means the site supports HTTP/2).
    """
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    with socket.create_connection((ip, 443), timeout=TLS_TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=server_name) as tls:
            cipher = tls.cipher()
            return (tls.getpeercert(binary_form=True), tls.version() or "", cipher[0] if cipher else "",
                    tls.selected_alpn_protocol())


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
        der, version, cipher, alpn = _fetch_peer_cert(ip, domain, ssl.create_default_context())
        out["verified"] = True
    except ssl.SSLCertVerificationError as exc:
        out["verify_error"] = exc.verify_message or str(exc)
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        der, version, cipher, alpn = _fetch_peer_cert(ip, domain, insecure)

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
        "alpn": alpn,
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
    title="VdigDNS API",
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


def _set_cdn_cache(response: Response, seconds: int) -> None:
    """
    Let Vercel's CDN keep this exact response (same URL incl. ?domain=) for a while.
    Repeat checks are then answered from the edge: instant, and no function cost.
    max-age=0 keeps browsers themselves from holding stale copies.
    """
    response.headers["Cache-Control"] = f"public, max-age=0, s-maxage={seconds}, stale-while-revalidate=60"


def _clean_domain(domain: str) -> str:
    try:
        return normalize_domain(domain)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


@app.get("/api/v1/analyze")
async def analyze(response: Response,
                  domain: str = Query(..., min_length=1, max_length=300, description="Domain to analyse, e.g. example.com")) -> dict:
    clean = _clean_domain(domain)

    cached = _cache_get(clean)
    if cached:
        _set_cdn_cache(response, 300)
        return {**cached, "cached": True}

    started = time.monotonic()
    log.info("Analysing %s", clean)

    # All sections run concurrently; total time ≈ the slowest one.
    (dns_res, reg_res, web_res, ns_res, hosting_res, spf_res, dmarc_res, dkim_res,
     mail_res, mailsec_res, tls_res, caa_res) = await asyncio.gather(
        _safe("DNS", lookup_dns_records(clean), 15),
        _safe("Website", analyze_website(clean), 30),
        _safe("Registration", analyze_registration(clean), 30),
        _safe("Nameservers", analyze_nameservers(clean), 15),
        _safe("Hosting", analyze_hosting(clean), 15),
        _safe("SPF", analyze_spf(clean), 20),
        _safe("DMARC", analyze_dmarc(clean), 15),
        _safe("DKIM", analyze_dkim(clean), 15),
        _safe("Mail/SMTP", analyze_mail(clean), 45),
        _safe("Mail security", analyze_mail_security(clean), 20),
        _safe("TLS", analyze_tls(clean), 25),
        _safe("CAA", analyze_caa(clean), 10),
    )
    if mailsec_res.get("status") != "error":
        cross_check_mail_security(mailsec_res, mail_res, dmarc_res)
    if tls_res.get("alpn") is not None or tls_res.get("not_after"):
        web_res["http2"] = tls_res.get("alpn") == "h2"

    # CAA belongs with the certificate: show it in the SSL section and cross-check the issuer.
    tls_res["caa"] = caa_res
    mismatch = caa_vs_certificate(caa_res, tls_res)
    if mismatch:
        tls_res.setdefault("warnings", []).append(mismatch)
        if tls_res.get("status") == "pass":
            tls_res["status"] = "warn"

    # Registry nameservers vs. the zone's own NS records
    ns_issue = nameserver_mismatch(reg_res, dns_res) if reg_res.get("found") else None
    if ns_issue:
        reg_res.setdefault("warnings", []).append(ns_issue)
        if reg_res.get("status") == "pass":
            reg_res["status"] = "warn"

    result = {
        "domain": clean,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "cached": False,
        "registration": reg_res,
        "website": web_res,
        "dns": dns_res,
        "hosting": hosting_res,
        "providers": detect_providers(clean, mail_res, spf_res),
        "spf": spf_res,
        "dmarc": dmarc_res,
        "dkim": dkim_res,
        "mail": mail_res,
        "nameservers": ns_res,
        "mail_security": mailsec_res,
        "tls": tls_res,
    }
    _cache_set(clean, result)
    # A section that errored (timeout etc.) may succeed on retry, so cache those results briefly.
    had_error = any(isinstance(v, dict) and v.get("status") == "error" for v in result.values())
    _set_cdn_cache(response, 30 if had_error else 300)
    return result


@app.get("/api/v1/propagation")
async def propagation(response: Response,
                      domain: str = Query(..., min_length=1, max_length=300),
                      type: str = Query("A", alias="type", max_length=8)) -> dict:
    """Ask 8 public resolvers and the authoritative nameserver for one record type, and compare."""
    clean = _clean_domain(domain)
    rtype = type.upper()
    if rtype not in PROPAGATION_TYPES:
        raise HTTPException(status_code=400, detail=f"Record type must be one of {', '.join(PROPAGATION_TYPES)}.")
    try:
        res = await asyncio.wait_for(check_propagation(clean, rtype), timeout=20)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="The resolvers took too long to answer. Try again.") from exc
    _set_cdn_cache(response, 30)  # short: people re-run this while waiting for a change to spread
    return res


@app.get("/api/v1/whois")
async def whois(response: Response, domain: str = Query(..., min_length=1, max_length=300)) -> dict:
    """Registration details only (RDAP, falling back to classic WHOIS)."""
    clean = _clean_domain(domain)
    res = await _safe("Registration", analyze_registration(clean), 30)
    _set_cdn_cache(response, 30 if res.get("status") == "error" else 3600)  # registry data changes rarely
    return {"domain": clean, **res}


@app.get("/api/v1/dkim")
async def dkim_selector(response: Response,
                        domain: str = Query(..., min_length=1, max_length=300),
                        selector: str = Query(..., min_length=1, max_length=63)) -> dict:
    """Check one DKIM selector, e.g. the s= value from an email's DKIM-Signature header."""
    clean = _clean_domain(domain)
    selector = selector.strip().lower()
    if not _SELECTOR_RE.match(selector):
        raise HTTPException(status_code=400, detail="A selector is letters, digits, dots, hyphens or underscores, like 'selector1'.")
    try:
        found = await asyncio.wait_for(check_dkim_selector(clean, selector), timeout=10)
    except (DNSLookupError, asyncio.TimeoutError) as exc:
        raise HTTPException(status_code=502, detail=f"Lookup failed: {exc or 'timed out'}") from exc
    _set_cdn_cache(response, 300)
    return {"domain": clean, "selector": selector, "found": bool(found), "key": found}


@app.get("/api/v1/spf/evaluate")
async def spf_evaluate(response: Response,
                       record: str = Query(..., min_length=6, max_length=2000),
                       domain: str = Query("example.com", max_length=300)) -> dict:
    """
    Evaluate a draft SPF record (used by the SPF builder) without publishing it:
    follows every include and counts DNS lookups exactly like the domain report.
    """
    clean = _clean_domain(domain or "example.com")
    rec = " ".join(record.split())
    if not _pick_spf([rec]):
        raise HTTPException(status_code=400, detail="An SPF record starts with v=spf1.")
    res: dict[str, Any] = {"record": rec, "lookup_limit": SPF_LOOKUP_LIMIT, "includes": [],
                           "errors": [], "warnings": [], "notes": []}
    try:
        await asyncio.wait_for(_assess_spf(clean, rec, res), timeout=20)
    except asyncio.TimeoutError as exc:
        raise HTTPException(status_code=504, detail="Following the includes took too long. Try again.") from exc
    _set_cdn_cache(response, 300)
    return res
