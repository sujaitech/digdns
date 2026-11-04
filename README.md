# DigDNS

Open-source DNS and email diagnostics in your browser. It runs on Vercel and checks:

- DNS records: A, AAAA, MX, TXT, CNAME, NS, SOA, SRV
- SPF: syntax, and the strict 10-lookup limit followed through every include
- DMARC: policy, reporting addresses, alignment
- Reverse DNS (PTR) of MX servers, with forward confirmation
- SSL/TLS certificate: issuer, expiry, days left, SANs
- SMTP handshake: the code is included but switched off on Vercel, because Vercel blocks outbound port 25

```
Browser ──► https://digdns.sujaiprojects.stream
              ├─ /              → public/index.html   (Vercel CDN)
              └─ /api/v1/...    → main.py (FastAPI)    (Vercel Function)
```

Because the page and the API live on the same domain, there is no CORS setup and no server to maintain.

## Files

| File | Purpose |
|---|---|
| `main.py` | The FastAPI backend. Vercel finds `app` here automatically. |
| `requirements.txt` | Python packages Vercel installs |
| `public/index.html` | The whole frontend (Tailwind + vanilla JS) |
| `vercel.json` | Lets the function run up to 60 s |
| `.python-version` | Asks Vercel for Python 3.12 |

---

## Step 1 — Put the code on GitHub (no Git install needed)

1. Unzip `digdns-vercel.zip` on your computer.
2. Go to https://github.com and sign up, or log in.
3. Click **+** (top right) → **New repository**.
   - **Repository name:** `digdns`
   - **Visibility:** Public
   - Leave every "Add …" box **unticked**.
   - Click **Create repository**.
4. On the next page, click the **uploading an existing file** link.
5. Open the unzipped `digdns-vercel` folder. Select **everything inside it**, not the folder itself, and drag it onto the GitHub page. That means:
   - `main.py`
   - `requirements.txt`
   - `vercel.json`
   - `README.md`
   - the `public` folder
   - `.python-version` and `.gitignore`
6. Make sure the hidden files come along:
   - **Windows:** in File Explorer, go to **View → Show → Hidden items**.
   - **Mac:** in Finder, press `Cmd + Shift + .`
   - If `.python-version` gets left out, the app still works on Vercel's default Python.
7. Scroll down and click **Commit changes**.

Check the result: the repo's main page should list `main.py` and a `public` folder at the top level. If you see a single `digdns-vercel` folder instead, you dragged the folder rather than its contents. Delete the repo and redo step 5.

## Step 2 — Create a Vercel account

1. Go to https://vercel.com/signup.
2. Choose the **Hobby** plan (free, for personal and non-commercial projects).
3. Click **Continue with GitHub** and authorise it. Using GitHub sign-in means Vercel can see your repos straight away.

## Step 3 — Deploy

1. In the Vercel dashboard, click **Add New… → Project**.
2. Find `digdns` in the list and click **Import**.
   - If it's missing, click **Adjust GitHub App Permissions** and give Vercel access to the repo.
3. On the configure screen:
   - **Framework Preset:** Vercel should detect **FastAPI** by itself. If it shows **Other**, leave it as is.
   - **Root Directory:** `./`
   - Leave the build and output settings and the environment variables empty.
4. Click **Deploy** and wait about a minute.

## Step 4 — Test the vercel.app address

Vercel gives you a URL like `https://digdns-xxxx.vercel.app`. Open these:

| URL | Expected result |
|---|---|
| `https://<your-url>.vercel.app/api/v1/health` | JSON with `"status":"ok"` |
| `https://<your-url>.vercel.app/` | The DigDNS page. Search `google.com`. |
| `https://<your-url>.vercel.app/api/v1/docs` | Interactive API docs |

If something fails, open the project in Vercel → **Logs** (or **Deployments → the latest one → Build Logs**) and send me the red lines.

## Step 5 — Use your own domain: digdns.sujaiprojects.stream

**In Vercel:**

1. Open the project → **Settings → Domains**.
2. Enter `digdns.sujaiprojects.stream` and click **Add**.
3. Vercel shows a **CNAME** record to create. Copy the **Value** exactly as shown, for example something ending in `vercel-dns.com`.

**In Cloudflare** (sujaiprojects.stream → **DNS → Records**):

1. Click **Add record** and fill in:

   | Type | Name | Target | Proxy status |
   |---|---|---|---|
   | CNAME | `digdns` | *the value Vercel showed you* | **DNS only (grey cloud)** |

2. Click **Save**.
3. Delete the old **`api`** A record (`192.245.157.101`). Nothing uses it anymore.

Back in Vercel, the domain changes to **Valid Configuration** within a few minutes, and Vercel issues the HTTPS certificate automatically. Then open https://digdns.sujaiprojects.stream.

> Keep the record grey (DNS only). If it's orange, Cloudflare and Vercel both try to handle HTTPS, and you get certificate errors or redirect loops.

## Updating the app later

Edit a file on GitHub: open it, click the ✏️ pencil, then **Commit changes**. Vercel redeploys automatically within about a minute. Every past deployment stays in **Deployments**, and **Promote / Instant Rollback** restores an old one.

## Optional — Rate limiting

Every lookup does real network work, so someone hammering it costs you function time.

To add a limit, go to the Vercel project → **Firewall** → **Configure** → add a **Rate Limit** rule:

- **If:** request path starts with `/api/v1/analyze`
- **Then:** allow 10 requests per 60 s per IP

How many rules you get depends on your plan.

## Run it on your own computer (optional)

This needs Python 3.10 or newer.

```bash
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

Then:

- **API:** http://127.0.0.1:8000/api/v1/analyze?domain=example.com
- **Frontend:** in `public/index.html`, temporarily set `const API_BASE = "http://127.0.0.1:8000";` and open the file in a browser.

## Turning the SMTP handshake back on

Only do this on a host that allows outbound port 25, such as a VPS where you've tested it. Set these environment variables:

- `ENABLE_SMTP=true`
- `SMTP_HELO_NAME=<hostname whose PTR matches the server IP>`
- `SMTP_MAIL_FROM=probe@yourdomain`

The probe only ever asks about `postmaster@<domain>` and never sends `DATA`, so no email is ever delivered. Keep it that way: letting users choose the recipient turns this into an address-harvesting tool and gets the server's IP blacklisted.
