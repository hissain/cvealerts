# HANDOFF - cvealert (plain text/Markdown content, saved as HANDOFF.doc per global CLAUDE.md)

Last updated: 2026-10-25 (Sunday). Workspace: E:\hissain\github\cvealert (Windows, PowerShell, Node v25.2.1 locally).

## 1. Project overview
Zero-cost (open-source components, free tiers) website where users:
- register an email for CVE notifications with filters (severity, KEV, EPSS, vendor/product, keyword, CWE),
- verify the email via emailed link (double opt-in),
- browse a CVE list with descriptions and a basic filtering dashboard.
Owner decision: "domains" filter was never defined by the user; implemented as vendor/product + keyword + CWE (ASK user to confirm).

## 2. Current status (verified vs not)
Scaffold of the chosen architecture ("Option A": Cloudflare Worker + D1 + static site, GitHub Actions for ingest/digest, Brevo for email) is WRITTEN.
- VERIFIED: `node scripts/ingest.mjs` ran locally (BOOTSTRAP_DAYS=1, no NVD key): fetched 5329 CVEs, kept 5178; KEV matched 28, EPSS matched 5121; wrote site/data/cves.json (5.27 MB, produced with the earlier 120-day retention) and state.json.
- VERIFIED: `node --check` passes for scripts/digest.mjs, scripts/ingest.mjs, worker/index.js, site/app.js.
- NOT VERIFIED (never run): Worker API (`wrangler dev`), D1 schema apply, Turnstile flow, verification/digest emails, Brevo calls, Cloudflare D1 REST calls in digest.mjs, GitHub workflows, dashboard in a browser.
- Git: repo initialized on branch `main` (2026-10-25), remote `origin` = https://github.com/hissain/cvealerts.git. NO commits yet, nothing pushed. `.gitignore` expanded (node_modules, .wrangler, .dev.vars, .env*, site/data/* except .gitkeep, logs, OS/editor files). `npm install --include=dev` done (npm config omits dev deps by default on this machine, so plain `npm install` skips wrangler).
- Nothing deployed. No secrets configured. Handoff file is now HANDOFF.md (was HANDOFF.doc; renamed outside this session).

## 3. Architecture and files
```
GitHub Actions ingest (cron 23 */3 * * *) -> NVD + CISA KEV + FIRST EPSS -> site/data/cves.json -> force-pushed to orphan `data` branch -> `wrangler deploy`
GitHub Actions digest (cron 41 6 * * *)   -> D1 REST query (active subscribers) -> match -> Brevo email -> update last_digest_at
Browser: static dashboard (client-side filtering of /data/cves.json) + subscribe form (Turnstile) -> /api/subscribe
```
- package.json: scripts ingest, digest, dev, deploy, db:init, db:init:local; devDependency wrangler ^4; ESM.
- wrangler.toml: Worker `cvealert`, main worker/index.js, [assets] ./site with run_worker_first ["/api/*"], D1 binding DB (database_id is a PLACEHOLDER), vars SITE_URL, MAIL_FROM_EMAIL, MAIL_FROM_NAME, TURNSTILE_SITEKEY (test key; placeholders to replace).
- schema.sql: table `subscribers` (email unique nocase, status pending|active|unsubscribed, verify_hash, verify_expires, last_verify_sent, last_digest_at, min_severity, kev_only, min_epss, vendors/keywords/cwes as JSON text).
- worker/index.js: GET /api/config, POST /api/subscribe, GET /api/verify?t=, GET|POST /api/unsubscribe?id=&t=. Turnstile check, generic response (no account probing), 10-min resend cooldown, sha256-hashed 24h verify token, HMAC-SHA256 unsubscribe token (`unsub:<id>` keyed with UNSUB_SECRET), Brevo transactional API. Active subscriber re-subscribing = silent no-op.
- scripts/lib.mjs: severity ranks, `matches(cve, sub)`, `unsubToken`.
- scripts/ingest.mjs: NVD delta by lastModStartDate/EndDate (clamped to 119 days; 6.5s gap without key, 0.7s with key; retries on 429/5xx), normalizes (CVSS v4>3.1>3.0>2, CWE, CPE vendors/products, 5 refs), skips rejected CVEs, drops old CVEs only re-analysed (published before retention cutoff), pulls recent KEV additions missing from window (max 20), EPSS from https://epss.empiricalsecurity.com/epss_scores-current.csv.gz, `firstSeen` (unix s) assigned on first ingest, retention default 45 days (just changed from 120), MAX_CVES 6000, keeps KEV entries regardless.
- scripts/digest.mjs: env CF_ACCOUNT_ID, CF_D1_DATABASE_ID, CF_API_TOKEN, BREVO_API_KEY, UNSUB_SECRET, SITE_URL, MAIL_FROM_EMAIL/NAME, MAX_EMAILS_PER_RUN (default 90), DRY_RUN=1. Sends CVEs with firstSeen > subscriber.last_digest_at, max 40 per mail, KEV first, List-Unsubscribe one-click headers; failures leave last_digest_at unchanged (retry next run).
- site/: index.html (explicit Turnstile render via /api/config), app.js, style.css (light/dark).
- .github/workflows/ingest.yml (restore data branch, ingest, force-push orphan `data` branch, deploy) and digest.yml (fetch data branch, run digest; manual dry_run input).
- RESEARCH.md: options analysis with sources/limits (NVD, cvelistV5, KEV, EPSS, email tiers, Cloudflare/Supabase/GitHub limits, Options A-D). README.md: setup checklist.
- .gitignore ignores site/data/*.json, node_modules, .wrangler, .dev.vars, .env.

## 4. Key decisions and rationale
- Option A chosen by user ("1"). Rejected for now: Supabase (free project pauses after 7 idle days, throttled auth mail), self-hosted/Listmonk (ops burden), static-only RSS (no email).
- Ingest/matching runs in GitHub Actions, NOT Worker cron: Cloudflare Workers Free cron has 10 ms CPU limit. D1 free limits (5M reads/100k writes per day) are hard-enforced since 2026-09-01, so the dashboard filters static JSON instead of querying D1.
- Data lives on orphan `data` branch (force-pushed) to avoid repo bloat from multi-MB JSON commits. The deploy step relies on the working tree still containing all files after `git rm --cached` (index swap only) - UNTESTED.
- Email: Brevo free (300/day, shared by verification + digests; free plan adds Brevo branding). Resend (100/day) is the alternative. Digest design = one email per subscriber per run.
- A sender domain with SPF/DKIM/DMARC is required for deliverability (~$10/yr, only non-zero cost). User has NOT said whether they own a domain.
- Free tier numbers came from web searches (2026-10-25); sources disagreed on MailerSend/SES - re-verify before relying.

## 5. Blockers, risks, open questions
- OPEN QUESTIONS for user: meaning of "domains" filter; whether they own a sending domain; preferred hostname (workers.dev vs custom).
- Dashboard payload was 5 MB before retention was cut to 45 days; re-run ingest and re-check size (gzip by Cloudflare helps).
- GitHub scheduled workflows: delayed under load; disabled after 60 days without repo activity (unclear whether pushes to the `data` branch count - verify).
- First digest run: all CVEs get firstSeen=now on bootstrap, but subscribers' last_digest_at is set at verification, so no historical flood is expected - verify with dry run.
- site/data/state.json is publicly served (harmless: only lastSync).
- No tests, no rate limiting beyond Turnstile + resend cooldown, no privacy policy page, no unverified-row purge, no preferences/manage flow.
- Do not commit secrets. Required secrets/vars are listed in README.md (GitHub: NVD_API_KEY, CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID, CF_D1_DATABASE_ID, BREVO_API_KEY, UNSUB_SECRET; vars SITE_URL, MAIL_FROM_EMAIL, MAIL_FROM_NAME, MAX_EMAILS_PER_RUN; Worker secrets: BREVO_API_KEY, TURNSTILE_SECRET, UNSUB_SECRET).

## 6. Next actions (ordered)
1. Ask user the 3 open questions above only if still unanswered; otherwise proceed with defaults.
2. `cd E:\hissain\github\cvealert; npm install` (installs wrangler); create `.dev.vars` (TURNSTILE_SECRET=1x0000000000000000000000000000000AA test secret, UNSUB_SECRET, BREVO_API_KEY dummy); `npm run db:init:local`; `npx wrangler dev`; test subscribe -> verify -> unsubscribe locally (Brevo send will fail without a real key; check D1 rows) and load the dashboard at http://localhost:8787 (re-run `npm run ingest` first with BOOTSTRAP_DAYS=2 to regenerate a smaller cves.json).
3. Fix whatever breaks; add a small test for `matches()` and Worker token logic.
4. `git init`, create public GitHub repo, push; set Cloudflare D1/Turnstile/Brevo/secrets per README; run `ingest` workflow manually, then `digest` with dry_run.
5. Add: unverified-subscriber purge (>48h), manage-preferences flow for active subscribers, privacy/terms page, extra rate limiting.
6. Update this file after each milestone; consolidate when long.

## 7. Operational commands
- Ingest locally: `$env:BOOTSTRAP_DAYS="2"; node scripts/ingest.mjs` (add `$env:NVD_API_KEY` for speed; without key ~6.5 s per NVD page).
- Syntax check: `node --check scripts/digest.mjs; node --check scripts/ingest.mjs; node --check worker/index.js; node --check site/app.js`
- Tools: Desktop Commander MCP (write_file, start_process with shell powershell.exe). Parent dirs must exist before write_file.
