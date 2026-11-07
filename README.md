# VdigDNS

VdigDNS is a domain diagnostics tool for sysadmins. Enter a domain and get one report covering:

- **Website:** whether it's up, response time, redirect path, HTTP/2, compression, security headers, and the software it's built with (CMS, framework, server, CDN, analytics).
- **Registration:** registrar, created and expiry dates, registry locks, DNSSEC, and registry nameservers checked against live DNS. Uses RDAP, with classic WHOIS as a fallback. Registries that publish nothing online (such as .zw) are reported as such, not as errors.
- **Hosting:** which server or network serves the website, from reverse DNS and IP ownership (AS number).
- **DNS records:** A, AAAA, MX, TXT, CNAME, NS, SOA, CAA and common SRV names.
- **Nameserver health:** each nameserver queried directly for reachability, authority (catches lame delegation), SOA serial agreement and response time.
- **SPF:** syntax, and the 10-lookup limit followed through every include.
- **DKIM:** keys at 30 common selectors and their strength, plus a single-selector check.
- **DMARC:** policy, reporting addresses and alignment.
- **Mail:** MX servers, their reverse DNS, and the email provider in use.
- **MTA-STS, TLS-RPT and BIMI:** records parsed, the MTA-STS policy fetched and checked against the MX hosts, and BIMI checked against the DMARC policy.
- **Blocklists:** the website, MX and SPF sending IPs checked against SpamCop, Mailspike, PSBL, UCEPROTECT L1, SpamRATS and DroneBL; the domain against SURBL and URIBL. Each list is tested first (RFC 5782 test points), so a list that refuses or ignores the lookup shows "Couldn't check" instead of a false "Listed".
- **SSL:** issuer, expiry, covered names, and the CAA records that say which authorities may issue.

The report opens with a **What needs attention** list of every problem, worst first, and can be copied as plain text for tickets or email.

Plus four tools:

- **Propagation:** compares 8 public resolvers with the authoritative nameserver.
- **SPF builder:** live lookup count.
- **DMARC builder:** includes a rollout guide.
- **Headers & bounces:** paste a bounce (non-delivery report) to get the cause in plain English, who has to fix it and how, per recipient. It reads Exim, Postfix, Sendmail, qmail, Gmail, Microsoft 365 and standard RFC 3464 reports, explains the SMTP and enhanced status codes and the stage at which the mail was refused, and spots when several unrelated providers were all refused by one server (your own outgoing filter). Or paste an email's headers for a plain-English verdict: SPF, DKIM, DMARC and ARC results, the real sending server, every hop with its delay and encryption, spam-filter scores (SpamAssassin, Microsoft SCL/BCL), and warning signs such as a mismatched Reply-To or a fake address in the display name. Parsed entirely in the browser; the headers are never uploaded.

Live at **https://dig.sujaiprojects.stream**

---

## How it's built

**A serverless Python API with a static frontend, on Vercel.**

```
Browser ──► Vercel edge (CDN) ──┬─► public/index.html            static page, served from the CDN
                                └─► main.py (FastAPI function)    the API
                                       ├─► Public DNS (1.1.1.1, 8.8.8.8)
                                       ├─► Team Cymru               who owns an IP
                                       ├─► RDAP / WHOIS registries  domain registration
                                       ├─► nameservers + 8 resolvers health and propagation
                                       └─► the checked site :80/443 website status, headers, SSL, MTA-STS policy
```

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI (async) |
| Libraries | `dnspython` for DNS, `cryptography` for certificates and DKIM keys, standard library for TLS, HTTP and WHOIS |
| Hosting | Vercel serverless function, plus Vercel CDN caching |
| Frontend | One HTML file: vanilla JavaScript and Tailwind CSS v4 (browser build), no build step |
| DNS | Cloudflare (`dig` CNAME → Vercel, DNS only) |
| Deploys | Push to GitHub `main` and Vercel deploys automatically |

### Design decisions

- **Everything runs in parallel.** The report's twelve checks start together with `asyncio.gather`, so a report takes about as long as the slowest check (usually 1–3 s).
- **Results stream in.** The page shows each section the moment its check finishes, with a live checklist of what's still running, instead of a blank wait for the slowest check. It's still one request per report, so the firewall rate limit is unaffected. If streaming fails, the page falls back to the plain endpoint. Closing the page mid-report stops the checks on the server.
- **Every check has its own deadline.** If one part times out, the rest of the report still returns and that section shows "Error".
- **"No record" is kept separate from "lookup failed".** A flaky resolver never shows up as a false "No SPF record".
- **SSRF protection.** The API never connects to private, loopback or reserved IPs. The website check follows redirects itself and re-checks every hop's address, so a redirect can't lead it into an internal network.
- **XSS protection.** DNS data is controlled by the domain owner, so the page inserts every value as text (`textContent`), never as HTML.
- **CDN caching.** Reports are cached at the edge for 5 minutes (30 s if a check errored). Registration-only lookups are cached for 1 hour.
- **Privacy.** Registrant contact details are never returned, even when a registry publishes them.
- **SMTP handshake is off.** Vercel blocks outbound port 25. The code is kept and can be switched on with `ENABLE_SMTP=true` on a host that allows port 25.

## API

All endpoints are `GET` and return JSON. Interactive docs are at `/api/v1/docs`.

| Endpoint | Purpose |
|---|---|
| `/api/v1/analyze?domain=example.com` | The full report, in one JSON document |
| `/api/v1/analyze/stream?domain=example.com` | The same report streamed as newline-delimited JSON: one `section` line per check as it finishes, then the final `report` line. The page uses this. |
| `/api/v1/whois?domain=example.com` | Registration only (RDAP, falling back to WHOIS) |
| `/api/v1/propagation?domain=www.example.com&type=A` | Compare 8 public resolvers and the authoritative nameserver |
| `/api/v1/dkim?domain=example.com&selector=selector1` | Check one DKIM selector |
| `/api/v1/blocklist?ip=203.0.113.5` | Check one IPv4 address against the IP blocklists |
| `/api/v1/spf/evaluate?record=v=spf1 include:_spf.google.com ~all&domain=example.com` | Count lookups for a draft SPF record |
| `/api/v1/health` | Liveness check |

## Files

| File | Purpose |
|---|---|
| `main.py` | The whole backend. Vercel finds the FastAPI `app` here. |
| `requirements.txt` | Python dependencies |
| `public/index.html` | The whole frontend |
| `vercel.json` | Allows the function to run for up to 60 s |
| `.python-version` | Python 3.12 |

## Run it locally

You need Python 3.10 or newer.

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

- **API:** open http://127.0.0.1:8000/api/v1/analyze?domain=example.com
- **Frontend:** set `const API_BASE = "http://127.0.0.1:8000";` near the top of the script in `public/index.html`, then open the file in a browser. Set it back to `""` before deploying.

## Configuration (optional environment variables)

Set these in Vercel under **Project → Settings → Environment Variables**.

| Variable | Default | Meaning |
|---|---|---|
| `DNS_NAMESERVERS` | `1.1.1.1,8.8.8.8` | Resolvers used for every lookup |
| `DNS_TIMEOUT` / `DNS_LIFETIME` | `3` / `6` | Seconds per server and per query |
| `TLS_TIMEOUT` | `8` | Seconds for the certificate check |
| `ENABLE_DOCS` | `true` | Serve `/api/v1/docs` |
| `ENABLE_SMTP` | `false` | SMTP handshake (needs outbound port 25, which Vercel blocks) |

## Deploying changes

1. Edit or upload the file on GitHub.
   - `main.py` goes at the top level.
   - `index.html` goes inside the `public` folder.
2. Commit. Vercel redeploys in about a minute.
3. If something breaks, go to **Vercel → Deployments**, pick the last good deployment, and click **Instant Rollback**.

## Known limitations

- **Tailwind runs as the browser build,** which generates CSS on each page load. A one-time compiled stylesheet would load faster.
- **DKIM under a custom selector** can only be found with the selector check, by reading `s=` from a sent email's `DKIM-Signature` header.
- **Technology detection** reads the home page only and uses signature matching. Sites can hide their software, and bot-protection pages (Cloudflare and similar) limit what's visible.
- **Hosting detection** names the network or CDN. Behind Cloudflare and similar CDNs, the real origin server can't be seen from DNS.
- **Spamhaus and Barracuda aren't queried.** Spamhaus refuses lookups from cloud platforms such as AWS, where Vercel runs, and Barracuda needs registration. The report links to Spamhaus's own checker instead. Spamhaus's free Data Query Service (a key) could be added later.
- **Blocklists cover IPv4 only;** almost no lists publish IPv6 data.
- **No deliverability (inbox placement) test.** That needs real seed mailboxes at Gmail, Outlook and others.
- **Propagation and nameserver checks run from Vercel's region.** Anycast resolvers answer from their nearest site, so this isn't a worldwide view. Nameservers are checked over IPv4 only.
