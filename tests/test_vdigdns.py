"""VdigDNS tests. They run automatically before every Vercel deploy (see build.py);
if one fails, the deploy stops and the previous version stays live.

No network access is needed: every DNS, HTTP and database call is replaced with a stand-in.
Run them yourself with:  python -m unittest discover -s tests -v
"""
import asyncio
import importlib
import json
import os
import re
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


# --------------------------------------------------------------------------------------------
# If FastAPI / dnspython aren't installed (e.g. a bare laptop), use small stand-ins so the logic
# can still be tested. On Vercel the real libraries are installed and used.
# --------------------------------------------------------------------------------------------
def _have(module: str) -> bool:
    try:
        importlib.import_module(module)
        return True
    except ImportError:
        return False


if not _have("dns.asyncresolver"):
    for m in ["dns", "dns.asyncresolver", "dns.asyncquery", "dns.message", "dns.name", "dns.resolver",
              "dns.reversename", "dns.flags", "dns.rcode", "dns.rdatatype"]:
        sys.modules[m] = MagicMock()
    exc = types.ModuleType("dns.exception")
    exc.Timeout = type("Timeout", (Exception,), {})
    exc.DNSException = type("DNSException", (Exception,), {})
    sys.modules["dns.exception"] = exc
    sys.modules["dns"].exception = exc
    sys.modules["dns.resolver"].NXDOMAIN = type("NXDOMAIN", (Exception,), {})
    sys.modules["dns.resolver"].NoAnswer = type("NoAnswer", (Exception,), {})
    sys.modules["dns.resolver"].NoNameservers = type("NoNameservers", (Exception,), {})

if not _have("cryptography.x509"):
    for m in ["cryptography", "cryptography.x509", "cryptography.x509.oid", "cryptography.hazmat",
              "cryptography.hazmat.primitives", "cryptography.hazmat.primitives.serialization"]:
        sys.modules[m] = MagicMock()
    ce = types.ModuleType("cryptography.exceptions")
    ce.UnsupportedAlgorithm = type("UnsupportedAlgorithm", (Exception,), {})
    sys.modules["cryptography.exceptions"] = ce

if not _have("fastapi"):
    fa = types.ModuleType("fastapi")

    class _App:
        def __init__(self, *a, **k): pass
        def add_middleware(self, *a, **k): pass
        def get(self, *a, **k): return lambda f: f
        def post(self, *a, **k): return lambda f: f

    class _HTTPException(Exception):
        def __init__(self, status_code=None, detail=None):
            super().__init__(detail)
            self.status_code, self.detail = status_code, detail

    fa.FastAPI, fa.HTTPException = _App, _HTTPException
    fa.Query = lambda default=None, *a, **k: default
    fa.Request = object

    class _Response:
        def __init__(self, content=b"", media_type=None, headers=None, status_code=200):
            self.body, self.media_type, self.headers, self.status_code = content, media_type, dict(headers or {}), status_code
    fa.Response = _Response
    sys.modules["fastapi"] = fa
    enc = types.ModuleType("fastapi.encoders")
    enc.jsonable_encoder = lambda o: o
    sys.modules["fastapi.encoders"] = enc
    resp = types.ModuleType("fastapi.responses")

    class _Streaming:
        def __init__(self, content, media_type=None, headers=None):
            self.body_iterator, self.media_type, self.headers = content, media_type, headers or {}

    resp.StreamingResponse, resp.RedirectResponse = _Streaming, object
    sys.modules["fastapi.responses"] = resp
    sys.modules["fastapi.middleware"] = MagicMock()
    sys.modules["fastapi.middleware.cors"] = MagicMock()
    conc = types.ModuleType("starlette.concurrency")

    async def _run_in_threadpool(fn, *a, **k):
        return fn(*a, **k)

    conc.run_in_threadpool = _run_in_threadpool
    sys.modules["starlette"] = MagicMock()
    sys.modules["starlette.concurrency"] = conc

import main  # noqa: E402

run = asyncio.run


class FakeResponse:
    def __init__(self): self.headers = {}


class FakeRequest:
    def __init__(self, headers=None, host="10.0.0.9", body=b""):
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.client = types.SimpleNamespace(host=host)
        self._body = body

    async def body(self):
        return self._body


class FakeRedis:
    """Just enough of Redis (as Upstash's REST pipeline) for the tests."""
    def __init__(self):
        self.data, self.ttl = {}, {}

    def __call__(self, commands):
        out = []
        for c in commands:
            op, key, *rest = c[0].upper(), *c[1:]
            if op == "GET":
                out.append({"result": self.data.get(key)})
            elif op == "SET":
                if "NX" in rest and key in self.data:
                    out.append({"result": None}); continue
                self.data[key] = rest[0]
                if "EX" in rest:
                    self.ttl[key] = int(rest[rest.index("EX") + 1])
                out.append({"result": "OK"})
            elif op == "TTL":
                out.append({"result": self.ttl.get(key, -2)})
            elif op == "INCR":
                self.data[key] = str(int(self.data.get(key, 0)) + 1); out.append({"result": int(self.data[key])})
            else:
                out.append({"result": 1})
        return out


class FakeRecord:
    def __init__(self, address): self.address = address


def stub_check(tag, delay=0.0, **extra):
    async def check(domain):
        await asyncio.sleep(delay)
        return {"tag": tag, "status": "pass", "errors": [], "warnings": [], "notes": [], **extra}
    return check


class Patched(unittest.TestCase):
    """Replace module attributes for one test and put them back afterwards."""
    def patch(self, **attrs):
        for name, value in attrs.items():
            old = getattr(main, name)
            self.addCleanup(setattr, main, name, old)
            setattr(main, name, value)

    def stub_report_checks(self, delays=None):
        d = delays or {}
        self.patch(
            lookup_dns_records=stub_check("dns", d.get("dns", 0), records={"NS": {"records": ["ns1.live.net"]}}),
            analyze_website=stub_check("website", d.get("website", 0)),
            analyze_registration=stub_check("registration", d.get("registration", 0), found=True, nameservers=["ns1.old.net"]),
            analyze_nameservers=stub_check("nameservers", d.get("nameservers", 0)),
            analyze_hosting=stub_check("hosting", d.get("hosting", 0), ips=[]),
            analyze_spf=stub_check("spf", d.get("spf", 0), includes=[], record="v=spf1 -all"),
            analyze_dmarc=stub_check("dmarc", d.get("dmarc", 0)),
            analyze_dkim=stub_check("dkim", d.get("dkim", 0)),
            analyze_mail=stub_check("mail", d.get("mail", 0), mx=[]),
            analyze_mail_security=stub_check("mail_security", d.get("mail_security", 0), mta_sts={}, bimi={}),
            analyze_tls=stub_check("tls", d.get("tls", 0), alpn="h2", not_after="2030-01-01", issuer=None),
            analyze_caa=stub_check("caa", d.get("caa", 0), found=False),
        )

        async def no_blocklists(domain, targets):
            return {"status": "pass", "ips": [], "domain_lists": [], "errors": [], "warnings": [], "notes": []}
        self.patch(analyze_blocklists=no_blocklists)
        main._cache.clear()
        self.addCleanup(main._cache.clear)


# --------------------------------------------------------------------------------------------
class InputTests(unittest.TestCase):
    def test_domain_is_cleaned(self):
        self.assertEqual(main._clean_domain("  Example.COM. "), "example.com")

    def test_bad_domain_is_refused(self):
        for bad in ["", "not a domain", "a..b.com", "-bad-.com", "x" * 300]:
            with self.subTest(bad=bad), self.assertRaises(Exception):
                main._clean_domain(bad)

    def test_private_addresses_are_never_contacted(self):
        for ip in ["10.1.2.3", "127.0.0.1", "192.168.0.1", "172.16.5.4", "169.254.169.254", "::1", "fc00::1"]:
            with self.subTest(ip=ip):
                self.assertFalse(main.is_public_ip(ip))
        self.assertTrue(main.is_public_ip("1.1.1.1"))


class WhoisParsingTests(unittest.TestCase):
    def test_registry_text_is_read(self):
        text = ("Domain Name: EXAMPLE.ORG\nRegistrar: Example Registrar, Inc.\n"
                "Creation Date: 2001-02-03T04:05:06Z\nRegistry Expiry Date: 2030-02-03T04:05:06Z\n"
                "Name Server: NS1.EXAMPLE.NET\nName Server: NS2.EXAMPLE.NET\n")
        res = main._parse_whois_text("example.org", text, "whois.example")
        flat = json.dumps(res).lower()
        self.assertIn("example registrar", flat)
        self.assertIn("2030", flat)
        self.assertIn("ns1.example.net", flat)


class ReportTests(Patched):
    """Each section's result must land under its own name (this once went wrong: Website showed Registration)."""
    def test_sections_land_under_their_own_names(self):
        self.stub_report_checks()
        report = run(main.analyze(FakeRequest(), FakeResponse(), domain="example.com"))
        for key in ["dns", "website", "registration", "nameservers", "hosting", "spf", "dmarc", "dkim", "mail", "mail_security", "tls"]:
            with self.subTest(section=key):
                self.assertEqual(report[key]["tag"], key)
        self.assertTrue(report["website"]["http2"])
        self.assertEqual(report["tls"]["caa"]["tag"], "caa")
        self.assertTrue(any("Nameservers don't match" in w for w in report["registration"]["warnings"]))

    def test_second_request_comes_from_cache(self):
        self.stub_report_checks()
        run(main.analyze(FakeRequest(), FakeResponse(), domain="example.com"))
        again = run(main.analyze(FakeRequest(), FakeResponse(), domain="example.com"))
        self.assertTrue(again["cached"])


class StreamTests(Patched):
    def _events(self, domain, stop_after=None):
        async def go():
            res = await main.analyze_stream(FakeRequest(), domain=domain)
            out = []
            gen = res.body_iterator
            async for chunk in gen:
                out.append(json.loads(chunk))
                if stop_after and len(out) >= stop_after:
                    await gen.aclose()
                    break
            await asyncio.sleep(0.05)
            leftover = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            return out, leftover
        return run(go())

    def test_sections_arrive_as_they_finish_then_the_final_report(self):
        self.stub_report_checks({"dns": 0.01, "website": 0.15, "registration": 0.1})
        events, _ = self._events("example.com")
        self.assertEqual(events[0], {"type": "start", "domain": "example.com"})
        names = [e["name"] for e in events if e["type"] == "section"]
        self.assertLess(names.index("dns"), names.index("registration"))
        self.assertLess(names.index("registration"), names.index("website"))
        self.assertEqual(names[-1], "blocklists")
        self.assertEqual(events[-1]["type"], "report")
        self.assertEqual(events[-1]["report"]["website"]["tag"], "website")

    def test_leaving_mid_report_stops_the_checks(self):
        self.stub_report_checks({"website": 5})
        _, leftover = self._events("example.org", stop_after=2)
        self.assertEqual(leftover, [])


class BlocklistTests(Patched):
    def _fake_dns(self, listed):
        async def resolve(name, rtype):
            if name.startswith("2.0.0.127.") and "dead" not in name:
                return [FakeRecord("127.0.0.2")]   # every working list lists its test address
            return [FakeRecord(a) for a in listed.get(name, [])]

        async def get_txt(name):
            return ["Listed for spam"] if name in listed else []
        main._list_health.update(at=0.0, ok={})
        self.patch(resolve=resolve, get_txt=get_txt)

    def test_two_listings_on_a_sending_ip_fail(self):
        self._fake_dns({"7.20.33.45.bl.spamcop.net": ["127.0.0.2"], "7.20.33.45.psbl.surriel.com": ["127.0.0.2"]})
        res = run(main.analyze_blocklists("example.com", [("45.33.20.7", ["Mail server (MX)"])]))
        self.assertEqual(res["status"], "fail")

    def test_listing_on_a_website_only_ip_is_a_warning(self):
        self._fake_dns({"7.20.33.45.bl.spamcop.net": ["127.0.0.2"], "7.20.33.45.psbl.surriel.com": ["127.0.0.2"]})
        res = run(main.analyze_blocklists(None, [("45.33.20.7", ["Website"])]))
        self.assertEqual(res["status"], "warn")

    def test_a_refusal_answer_is_not_a_listing(self):
        self._fake_dns({"example.com.multi.uribl.com": ["127.0.0.1"], "7.20.33.45.bl.spamcop.net": ["127.255.255.254"]})
        res = run(main.analyze_blocklists("example.com", [("45.33.20.7", ["Mail server (MX)"])]))
        states = {l["list"]: l["state"] for e in res["ips"] for l in e["lists"]}
        self.assertEqual(states["SpamCop"], "unavailable")
        self.assertEqual(res["status"], "pass")

    def test_only_public_ipv4_addresses_are_checked(self):
        targets = main.blocklist_targets({"ips": [{"ip": "93.184.215.14"}, {"ip": "2001:db8::1"}]},
                                         {"mx": [{"ips": ["45.33.20.7", "10.0.0.1"]}]},
                                         {"record": "v=spf1 ip4:45.33.20.7 ip4:52.1.1.0/24 ~all"})
        ips = [ip for ip, _ in targets]
        self.assertEqual(ips[0], "45.33.20.7")          # the sending server comes first
        self.assertNotIn("10.0.0.1", ips)
        self.assertNotIn("2001:db8::1", ips)


class UsageLogTests(Patched):
    def test_visitor_details_come_from_vercel_headers(self):
        info = main.client_info(FakeRequest({"x-real-ip": "203.0.113.7", "x-vercel-ip-country": "IN",
                                             "x-vercel-ip-city": "New%20Delhi", "user-agent": "Test/1.0"}))
        self.assertEqual((info["ip"], info["country"], info["city"], info["ua"]), ("203.0.113.7", "IN", "New Delhi", "Test/1.0"))
        self.assertEqual(main.client_info(FakeRequest({"x-forwarded-for": "198.51.100.4, 10.0.0.1"}))["ip"], "198.51.100.4")

    def test_health_says_whether_the_log_is_set_up_without_revealing_secrets(self):
        self.patch(USAGE_DB_URL="https://db.example", USAGE_DB_TOKEN="secret-db-token", ADMIN_TOKEN="short")
        health = run(main.health())
        self.assertEqual((health["usage_log"], health["admin_ready"]), (True, False))
        self.assertNotIn("secret", json.dumps(health))

    def test_nothing_is_logged_without_a_database(self):
        self.patch(USAGE_DB_URL="", USAGE_DB_TOKEN="")
        self.assertIsNone(main.track(FakeRequest(), "report", "example.com"))

    def test_a_check_is_logged_with_its_retention(self):
        sent = []
        self.patch(USAGE_DB_URL="https://db.example", USAGE_DB_TOKEN="t", _redis_pipeline=lambda cmds: sent.append(cmds) or [])
        self.stub_report_checks()
        run(main.analyze(FakeRequest({"x-real-ip": "203.0.113.7"}), FakeResponse(), domain="example.com"))
        self.assertEqual(len(sent), 1)
        push, _trim, expire = sent[0]
        entry = json.loads(push[2])
        self.assertEqual((entry["tool"], entry["target"], entry["ip"]), ("report", "example.com", "203.0.113.7"))
        self.assertTrue(push[1].startswith("vdig:use:"))
        self.assertEqual(expire[2], str(main.LOG_RETENTION_DAYS * 86400))

    def test_a_broken_database_never_breaks_a_check(self):
        def broken(cmds): raise OSError("down")
        self.patch(USAGE_DB_URL="https://db.example", USAGE_DB_TOKEN="t", _redis_pipeline=broken)
        self.stub_report_checks()
        report = run(main.analyze(FakeRequest(), FakeResponse(), domain="example.com"))
        self.assertEqual(report["dns"]["tag"], "dns")

    def test_admin_log_needs_the_right_password(self):
        self.patch(ADMIN_TOKEN="", USAGE_DB_URL="https://db.example", USAGE_DB_TOKEN="t")
        with self.assertRaises(Exception) as hidden:
            run(main.admin_usage(FakeRequest(), FakeResponse(), days=7))
        self.assertEqual(hidden.exception.status_code, 503)       # not set up: says so, reveals nothing
        self.patch(ADMIN_TOKEN="correct-horse-battery-staple")
        with self.assertRaises(Exception) as wrong:
            run(main.admin_usage(FakeRequest({"authorization": "Bearer nope"}), FakeResponse(), days=7))
        self.assertEqual(wrong.exception.status_code, 401)
        row = json.dumps({"t": "2026-11-07T10:00:00+00:00", "tool": "report", "target": "example.com", "ip": "203.0.113.7"})
        self.patch(_redis_pipeline=lambda cmds: [{"result": [row]}] + [{"result": []}] * (len(cmds) - 1))
        ok = run(main.admin_usage(FakeRequest({"authorization": "Bearer correct-horse-battery-staple"}), FakeResponse(), days=7))
        self.assertEqual(ok["count"], 1)
        self.assertEqual(ok["entries"][0]["target"], "example.com")


class PropagationTests(Patched):
    CSV = (
        "ip_address,name,as_number,as_org,country_code,city,version,error,dnssec,reliability,checked_at,created_at\n"
        "8.8.8.8,dns.google.,15169,Google LLC,US,,,,true,1.00,2026-11-20T17:43:28Z,2020-07-16T14:19:04Z\n"          # anycast: out
        "2a01:4f8::1,x.de.,24940,Hetzner,DE,Falkenstein,,,true,1.00,2026-11-20T17:43:32Z,2020-07-17T22:21:13Z\n"    # IPv6: out
        "194.27.192.6,,15843,Uni,TR,,,,false,0.48,2026-11-20T17:43:29Z,2020-07-16T15:08:39Z\n"                      # unreliable: out
        "195.243.214.4,,3320,Deutsche Telekom AG,DE,Oberhausen,,,false,1.00,2026-11-01T17:43:30Z,2020-08-08T20:06:24Z\n"  # stale: out
        "10.1.1.1,,64512,Private,DE,,,,false,1.00,2026-11-20T17:43:30Z,2020-08-08T20:06:24Z\n"                      # private: out
        "45.90.28.1,dns.nextdns.io.,34939,NextDNS,DE,,,,false,1.00,2026-11-20T17:43:30Z,2020-08-08T20:06:24Z\n"     # anycast by name: out
        "61.1.1.1,,1111,BSNL,IN,Mumbai,,timeout,false,1.00,2026-11-20T17:43:30Z,2020-08-08T20:06:24Z\n"             # has error: out
        "103.1.1.1,ns1.isp-a.in.,2222,ISP A,IN,Mumbai,,,false,1.00,2026-11-20T17:43:30Z,2020-08-08T20:06:24Z\n"
        "103.1.1.2,ns2.isp-a.in.,2222,ISP A,IN,Mumbai,,,false,0.995,2026-11-20T17:43:30Z,2020-08-08T20:06:24Z\n"
        "117.1.1.1,,3333,ISP B,IN,Chennai,,,false,0.99,2026-11-20T17:43:30Z,2020-08-08T20:06:24Z\n"
        "212.1.1.1,ns.isp.de.,4444,ISP DE,DE,Berlin,,,false,1.00,2026-11-20T17:43:30Z,2020-08-08T20:06:24Z\n")
    NOW = main.datetime(2026, 11, 21, tzinfo=main.timezone.utc)

    def test_only_reliable_unicast_ipv4_resolvers_are_kept(self):
        pool = main.build_resolver_pool(self.CSV, now=self.NOW)
        kept = {r["ip"] for v in pool["countries"].values() for r in v}
        self.assertEqual(kept, {"103.1.1.1", "103.1.1.2", "117.1.1.1", "212.1.1.1"})
        self.assertEqual(pool["listed"], 11)

    def test_a_country_gets_different_networks_first(self):
        india = main.build_resolver_pool(self.CSV, now=self.NOW)["countries"]["IN"]
        self.assertEqual([r["asn"] for r in india], [2222, 3333, 2222])

    def test_worldwide_takes_one_per_country_and_country_mode_takes_several(self):
        pool = main.build_resolver_pool(self.CSV, now=self.NOW)
        world = main.pick_resolvers(pool, "world", None)
        self.assertEqual(sorted(r["country"] for r in world), ["DE", "IN"])
        self.assertEqual(len(main.pick_resolvers(pool, "country", "IN")), 3)
        self.assertEqual(main.pick_resolvers(pool, "country", "ZZ"), [])

    def _stub_dns(self, answers, pool):
        async def fake_row(name, ip, place, qname, rtype, recursive, timeout=4.0, **extra):
            vals = answers.get(ip)
            row = {"name": name, "ip": ip, "location": place, "values": vals or [], "ttl": 300, "rcode": "NOERROR",
                   "rtt_ms": 10, "error": None if vals is not None else "No answer", **extra}
            return row

        async def fake_zone(domain): return "example.com", ["ns1.example.net"]
        async def fake_ips(host): return ["198.18.0.53"]
        async def fake_pool(): return pool
        self.patch(_ask_for_row=fake_row, find_zone=fake_zone, _ips_of=fake_ips, resolver_pool=fake_pool,
                   is_public_ip=lambda ip: True)

    def test_resolvers_are_compared_with_the_authoritative_answer(self):
        pool = main.build_resolver_pool(self.CSV, now=self.NOW)
        new, old = ["203.0.113.2"], ["203.0.113.1"]
        answers = {ip: new for _, ip, _ in main.PUBLIC_RESOLVERS}
        answers.update({"198.18.0.53": new, "103.1.1.1": old, "212.1.1.1": new})
        self._stub_dns(answers, pool)
        res = run(main.check_propagation("www.example.com", "A", "world"))
        self.assertEqual(res["compared_with"], "authoritative")
        stale = [r["ip"] for r in res["resolvers"] if r["matches"] is False]
        self.assertEqual(stale, ["103.1.1.1"])
        self.assertEqual(res["status"], "warn")
        self.assertEqual(res["counts"]["matching"], len(main.PUBLIC_RESOLVERS) + 1)
        self.assertIn("Asia", res["by_region"])

    def test_location_specific_answers_are_explained_not_called_stale(self):
        pool = main.build_resolver_pool(self.CSV, now=self.NOW)
        answers = {ip: [f"203.0.113.{i}"] for i, (_, ip, _) in enumerate(main.PUBLIC_RESOLVERS)}
        answers.update({"198.18.0.53": ["203.0.113.200"], "103.1.1.1": ["198.51.100.1"], "212.1.1.1": ["198.51.100.2"]})
        self._stub_dns(answers, pool)
        res = run(main.check_propagation("cdn.example.com", "A", "world"))
        self.assertIn("GeoDNS", res["note"])

    def test_without_the_worldwide_list_the_big_resolvers_still_answer(self):
        self._stub_dns({ip: ["203.0.113.2"] for _, ip, _ in main.PUBLIC_RESOLVERS} | {"198.18.0.53": ["203.0.113.2"]}, None)
        res = run(main.check_propagation("www.example.com", "A", "world"))
        self.assertEqual(res["status"], "pass")
        self.assertIn("couldn't be loaded", res["note"])

    def test_bad_scope_or_missing_country_is_refused(self):
        for kwargs in ({"scope": "moon"}, {"scope": "country", "country": None}, {"scope": "country", "country": "1x"}):
            with self.subTest(**kwargs), self.assertRaises(Exception) as err:
                run(main.propagation(FakeRequest(), FakeResponse(), domain="example.com", type="A", **kwargs))
            self.assertEqual(err.exception.status_code, 400)


RAW_EMAIL = (b"Received: from mail.sender.example (mail.sender.example [45.33.20.7]) by mx.cloudflare.net with ESMTPS id x; Fri, 20 Nov 2026 10:00:00 +0000\r\n"
             b"From: Priya <priya@sender.example>\r\nTo: test+abc@check.example.com\r\nSubject: Quote\r\n"
             b"Message-ID: <1@sender.example>\r\nDate: Fri, 20 Nov 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n"
             b"Content-Type: text/html; charset=utf-8\r\n\r\n<p>Hello <a href=\"https://bit.ly/x\">here</a></p>\r\n")


class MailTestTests(Patched):
    def enable(self):
        self.db = FakeRedis()
        self.patch(USAGE_DB_URL="https://db.example", USAGE_DB_TOKEN="t", _redis_pipeline=self.db,
                   MAILTEST_ADDRESS="test@check.example.com", MAILTEST_SECRET="s" * 32)

    def test_switched_off_until_configured(self):
        self.patch(MAILTEST_ADDRESS="", MAILTEST_SECRET="")
        with self.assertRaises(Exception) as err:
            run(main.mailtest_new(FakeRequest(), FakeResponse()))
        self.assertEqual(err.exception.status_code, 503)

    def test_addresses_use_plus_tags_or_a_catch_all(self):
        self.patch(MAILTEST_ADDRESS="test@check.example.com")
        self.assertEqual(main.mailtest_address("abc12345"), "test+abc12345@check.example.com")
        self.patch(MAILTEST_ADDRESS="*@example.com")
        self.assertEqual(main.mailtest_address("abc12345"), "abc12345@example.com")

    def test_a_test_goes_from_waiting_to_a_report(self):
        self.enable()
        async def fake_analysis(raw, env_from):
            return {"score": 9.5, "from_domain": "sender.example", "env": env_from}
        self.patch(analyze_test_email=fake_analysis)
        new = run(main.mailtest_new(FakeRequest(), FakeResponse()))
        self.assertTrue(new["address"].startswith("test+") and new["address"].endswith("@check.example.com"))
        self.assertEqual(run(main.mailtest_result(new["id"], FakeResponse()))["state"], "waiting")
        with self.assertRaises(Exception) as bad:
            run(main.mailtest_inbound(FakeRequest({"x-vdig-secret": "wrong"}, body=RAW_EMAIL), id=new["id"]))
        self.assertEqual(bad.exception.status_code, 401)
        ok = run(main.mailtest_inbound(FakeRequest({"x-vdig-secret": "s" * 32, "x-envelope-from": "bounce@sender.example"}, body=RAW_EMAIL), id=new["id"]))
        self.assertTrue(ok["ok"])
        done = run(main.mailtest_result(new["id"], FakeResponse()))
        self.assertEqual((done["state"], done["report"]["score"], done["report"]["env"]), ("done", 9.5, "bounce@sender.example"))
        self.assertIn("From: Priya", done["report"]["raw_headers"])

    def test_an_expired_or_unknown_address_is_refused(self):
        self.enable()
        with self.assertRaises(Exception) as err:
            run(main.mailtest_inbound(FakeRequest({"x-vdig-secret": "s" * 32}, body=RAW_EMAIL), id="zzzzzzzzzzzz"))
        self.assertEqual(err.exception.status_code, 404)

    def test_visitors_are_limited_per_day(self):
        self.enable()
        self.patch(MAILTEST_PER_IP_DAY=2)
        run(main.mailtest_new(FakeRequest(), FakeResponse())); run(main.mailtest_new(FakeRequest(), FakeResponse()))
        with self.assertRaises(Exception) as err:
            run(main.mailtest_new(FakeRequest(), FakeResponse()))
        self.assertEqual(err.exception.status_code, 429)

    def test_the_report_explains_every_deduction(self):
        async def rdns(ip): return {"ptr": [], "forward_confirmed": False}
        async def bls(domain, targets):
            return {"status": "pass", "ips": [{"ip": t[0], "roles": t[1], "lists": [{"list": "SpamCop", "state": "listed"}]} for t in targets],
                    "domain_lists": [], "errors": [], "warnings": [], "notes": []}
        async def dmarc(domain): return {"found": True, "policy": "none", "adkim": "r", "aspf": "r", "record": "v=DMARC1; p=none"}
        self.patch(_spf_check=lambda ip, mf, helo: ("softfail", "not listed"), _dkim_check=lambda raw: [],
                   _spamassassin=lambda text: {"success": True, "score": 2.5, "rules": [{"score": "2.5", "description": "Short link"}]},
                   check_rdns=rdns, analyze_blocklists=bls, analyze_dmarc=dmarc)
        rep = run(main.analyze_test_email(RAW_EMAIL, "bounce@sender.example"))
        self.assertEqual((rep["sending_ip"], rep["helo"]), ("45.33.20.7", "mail.sender.example"))
        areas = {d["area"] for d in rep["deductions"]}
        self.assertTrue({"SPF", "DKIM", "DMARC", "Blocklists", "Reverse DNS", "SpamAssassin", "Content"} <= areas)
        self.assertAlmostEqual(rep["score"], max(0, 10 - sum(d["points"] for d in rep["deductions"])))
        self.assertEqual(rep["content"]["shorteners"], ["bit.ly"])
        self.assertEqual(rep["dmarc"]["result"], "fail")


class ScreenshotTests(Patched):
    def setUp(self):
        async def ips(host): return ["93.184.215.14"]
        self.patch(_ips_of=ips, BROWSERLESS_TOKEN="tok", USAGE_DB_URL="", USAGE_DB_TOKEN="")

    def test_switched_off_without_a_token(self):
        self.patch(BROWSERLESS_TOKEN="")
        with self.assertRaises(Exception) as err:
            run(main.screenshot(domain="example.com"))
        self.assertEqual(err.exception.status_code, 503)

    def test_a_screenshot_is_returned_and_cached_at_the_edge(self):
        calls = []
        def shot(url, with_viewport):
            calls.append(with_viewport)
            return (400, b"Unknown field viewport", "text/plain") if with_viewport else (200, b"JPEGDATA", "image/jpeg")
        self.patch(_browserless_shot=shot)
        res = run(main.screenshot(domain="Example.com"))
        self.assertEqual((res.body, res.media_type), (b"JPEGDATA", "image/jpeg"))
        self.assertIn("s-maxage", res.headers["Cache-Control"])
        self.assertEqual(calls, [True, False])     # retried without the viewport field

    def test_private_addresses_are_never_screenshotted(self):
        async def private(host): return ["10.0.0.5"]
        self.patch(_ips_of=private)
        with self.assertRaises(Exception) as err:
            run(main.screenshot(domain="intranet.example.com"))
        self.assertEqual(err.exception.status_code, 404)


class FrontendTests(unittest.TestCase):
    """Cheap checks on the page itself."""
    def setUp(self):
        self.html = (ROOT / "public" / "index.html").read_text(encoding="utf-8")

    def test_every_element_the_script_looks_up_exists(self):
        ids = set(re.findall(r'\bid="([\w-]+)"', self.html)) | set(re.findall(r'\.id\s*=\s*["`]([\w-]+)["`]', self.html))
        dynamic = {m for m in re.findall(r'\$\("([\w-]+)"\)', self.html)}
        missing = sorted(i for i in dynamic - ids if not i.startswith("slot-"))
        self.assertEqual(missing, [], f"the script looks up ids that don't exist: {missing}")

    def test_the_compiled_stylesheet_is_linked(self):
        self.assertIn('href="/app.css"', self.html)

    def test_theme_tokens_are_present_for_the_build(self):
        sys.path.insert(0, str(ROOT))
        import build
        theme = build.extract_theme(self.html)
        self.assertIn("--color-navy", theme)


if __name__ == "__main__":
    unittest.main()
