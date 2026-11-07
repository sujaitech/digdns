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

    class _HTTPException(Exception):
        def __init__(self, status_code=None, detail=None):
            super().__init__(detail)
            self.status_code, self.detail = status_code, detail

    fa.FastAPI, fa.HTTPException = _App, _HTTPException
    fa.Query = lambda default=None, *a, **k: default
    fa.Request = fa.Response = object
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
    def __init__(self, headers=None, host="10.0.0.9"):
        self.headers = {k.lower(): v for k, v in (headers or {}).items()}
        self.client = types.SimpleNamespace(host=host)


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
