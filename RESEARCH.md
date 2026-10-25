# CVE Alert – Zero-cost architecture options (research, 2026-10-25)

Goal: public site that lists CVEs with filters, lets users subscribe by email
(severity / vendor / keyword ...), verifies email (double opt-in), sends alerts. $0 budget.

## 1. Data sources (all free, no paid tier needed)

| Source | What it gives | Notes |
|---|---|---|
| NVD CVE API 2.0 `services.nvd.nist.gov/rest/json/cves/2.0` | CVE + CVSS + CPE + CWE | 5 req/30s without key, 50 req/30s with free key. Date-range queries max 120 days. Use `lastModStartDate` for incremental sync |
| CVE Program `CVEProject/cvelistV5` (GitHub) | Official CVE JSON 5 records, hourly delta releases, `cves/deltaLog.json` | No rate-limit worries; less enrichment (CVSS/CPE may be missing or from CNA/ADP only) |
| CISA KEV JSON feed | "Actively exploited" flag, due date, ransomware use | Free, no auth. Great filter: "KEV only" |
| FIRST EPSS (`api.first.org/data/v1/epss` or daily bulk CSV) | Exploit probability 0-1 | Free, daily. Bulk CSV preferred over per-CVE calls |

Recommended ingest: bootstrap once from NVD (or cvelistV5 baseline), then poll NVD
`lastModStartDate` every 1-2h, join KEV + EPSS daily.

## 2. Email (the real constraint for "free")

| Provider | Free tier (reports differ slightly, verify before building) | Notes |
|---|---|---|
| Brevo | 300/day (~9k/mo) | Biggest free tier; free plan adds Brevo branding; SMTP + API |
| Resend | 3,000/mo, 100/day | Best DX, runs on SES; daily cap bites |
| MailerSend | ~500-3,000/mo (sources conflict) | |
| Amazon SES | No permanent free tier any more (trial/credits) | Cheapest at scale, not free |
| SendGrid | Free tier removed May 2025 | Skip |

Design consequence: send ONE digest per subscriber per day (or per hour for
critical/KEV), not one email per CVE. Verification mails count against the cap too.
You need a sender domain with SPF/DKIM/DMARC (a domain is ~$10/yr - the only
unavoidable cost; sending from gmail/outlook addresses will not authenticate).

## 3. Hosting / compute / DB

- Cloudflare Workers Free: 100k req/day, 5 cron triggers per account, BUT only 10 ms CPU
  per cron run -> do NOT ingest/match CVEs inside a free Worker cron.
- Cloudflare D1 Free: 5M rows read/day, 100k rows written/day, 500 MB/db; limits are
  hard-enforced (queries fail) since 2026-09-01.
- GitHub Actions (public repo): free scheduled jobs, min 5 min interval, can be delayed
  30+ min under load, auto-disabled after 60 days of repo inactivity.
- Supabase Free: Postgres 500 MB, 2 projects, 50k MAU, Auth; pauses after 7 days idle.
- GitHub Pages / Cloudflare Pages: free static hosting.

## 4. Architecture options

### Option A (recommended) - Cloudflare edge + GitHub Actions worker
```
GitHub Actions (cron, public repo)           Cloudflare
  fetch NVD delta + KEV + EPSS  ---------->  D1 (cves, subscribers, filters)
  build static JSON snapshots   ---------->  Pages (dashboard, client-side filtering)
  match new CVEs vs subscribers              Worker API: /subscribe /verify /unsubscribe
  send digests via Brevo/Resend API  <-----  (Turnstile CAPTCHA, rate limit)
```
- Dashboard: static site (Astro/SvelteKit/plain Vite) + table lib (TanStack Table / Tabulator);
  filters run in browser on JSON shards, so D1 read quota is barely used.
- Subscribe flow: POST email+filters -> Worker stores row `pending` with hashed token
  (24h expiry) -> sends verification link -> GET /verify?token= flips to `active`
  -> every mail carries one-click unsubscribe link + List-Unsubscribe header.
- Heavy work (ingest, matching, mailing) lives in Actions, not Worker cron (10 ms CPU cap).
- Pros: truly $0, no servers, global CDN, fits free quotas for hundreds-low thousands of users.
- Cons: Actions scheduling jitter (fine for hourly/daily alerts); Cloudflare D1 quota is hard stop.

### Option B - Supabase-centric
- Postgres (CVEs + subscribers), Edge Functions for subscribe/verify, pg_cron or Actions for ingest,
  frontend on Cloudflare/GitHub Pages. Full SQL filtering/search, nicer dev experience.
- Cons: free project pauses after 7 idle days (a daily Actions job that queries it should keep it
  active - test this), 500 MB DB cap, Supabase built-in auth email is heavily throttled so wire
  custom SMTP (Brevo) anyway.

### Option C - Self-hosted (Windows PC or free VM)
- FastAPI/Node + SQLite/Postgres, or Listmonk (open-source, native double opt-in; model each
  severity/vendor as a list) + Brevo SMTP relay, cron/Task Scheduler for ingest.
- Pros: no vendor quotas, full control, open-source components throughout.
- Cons: you maintain uptime/security/backups; home PC is a poor public server. Free cloud VM
  offers (e.g. Oracle Always Free) exist but I did not verify current terms - check first.

### Option D - Static-only "RSS + client-side" fallback
- GitHub Pages dashboard + generated RSS/Atom per severity/vendor. No email, so doesn't meet
  the requirement, but a good free add-on for users who prefer feeds.

## 5. Suggested filters
severity (CVSS band), KEV-only, EPSS >= threshold, vendor/product (from CPE), keyword in
description, CWE class, published vs modified. ("domains" needs a decision: vendor/product?
CWE category? technology area?)

## 6. Risks / gotchas
- Free email caps are the ceiling on subscribers (100/day Resend, 300/day Brevo).
- Anti-abuse: Turnstile on signup form, per-IP/per-email rate limits, never reveal whether an
  email is already registered, expire unverified rows after 24-48h.
- Compliance: store minimum data, honor unsubscribe instantly, delete on request.
- NVD data has enrichment lag; label source and "last updated".
- Keep Actions alive (60-day inactivity rule) - data commits or a keepalive workflow.

## 7. Proposed MVP steps
1. Repo scaffold + ingest script (NVD delta -> JSON/D1), KEV + EPSS join.
2. Static dashboard with filters.
3. Worker API: subscribe/verify/unsubscribe + Turnstile.
4. Digest job in Actions + Brevo/Resend.
5. Domain + SPF/DKIM/DMARC, then soft launch.
