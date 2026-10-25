# CVE Alert

Zero-cost CVE dashboard with verified email alerts. See `RESEARCH.md` for the options analysis.

```
GitHub Actions ──ingest (every 3h)──> NVD + CISA KEV + EPSS ──> site/data/cves.json ──> `data` branch
                └─deploy──────────────────────────────────────> Cloudflare Worker (static site + /api/*)
                └─digest (daily)── D1 subscribers ── match ──> Brevo email
Browser: static dashboard (client-side filtering) + subscribe form (Turnstile) ──> /api/subscribe ──> D1 + verification mail
```

## One-time setup
1. **Repo**: push to a *public* GitHub repo (free Actions minutes). `npm install`.
2. **Cloudflare**: `npx wrangler login`, then `npx wrangler d1 create cvealert` -> put the `database_id` in `wrangler.toml`.
   Run `npm run db:init`.
3. **Turnstile** (free CAPTCHA): create a widget in the Cloudflare dashboard -> set `TURNSTILE_SITEKEY` in `wrangler.toml`, then `npx wrangler secret put TURNSTILE_SECRET`.
4. **Brevo** (300 emails/day free): create an account, verify your sender domain (SPF/DKIM/DMARC) or at least a sender address,
   `npx wrangler secret put BREVO_API_KEY`. Set `MAIL_FROM_EMAIL` / `SITE_URL` in `wrangler.toml`.
5. **Unsubscribe secret**: generate a long random string; `npx wrangler secret put UNSUB_SECRET` and add the same value as a GitHub secret.
6. **NVD key** (free): https://nvd.nist.gov/developers/request-an-api-key -> GitHub secret `NVD_API_KEY`.
7. **GitHub secrets**: `NVD_API_KEY`, `CLOUDFLARE_API_TOKEN` (Workers edit + D1 edit), `CLOUDFLARE_ACCOUNT_ID`, `CF_D1_DATABASE_ID`, `BREVO_API_KEY`, `UNSUB_SECRET`.
   **GitHub variables**: `SITE_URL`, `MAIL_FROM_EMAIL`, `MAIL_FROM_NAME`, optional `MAX_EMAILS_PER_RUN` (default 90).
8. Run the `ingest` workflow manually once (creates the `data` branch and deploys), then `digest` with *dry run* ticked.

## Local test
```
set NVD_API_KEY=...        (optional)
set BOOTSTRAP_DAYS=2
npm run ingest             # writes site/data/cves.json
npm run db:init:local
npx wrangler dev           # http://localhost:8787  (create .dev.vars with secrets; Turnstile test keys work locally)
```

## Behaviour notes
- Double opt-in: link token is random, only its SHA-256 is stored, expires in 24h. Signup always returns the same message (no account probing).
- Digest sends only CVEs first seen *after* the subscriber's last digest / verification time, capped at 40 items per mail.
- Unsubscribe links are HMAC-signed, plus `List-Unsubscribe` one-click headers.
- Free-tier guard rails: `MAX_EMAILS_PER_RUN` (Brevo 300/day shared with verification mails), D1 reads are minimal because the dashboard filters static JSON.
- GitHub disables scheduled workflows after 60 days of repo inactivity; commit occasionally or re-enable manually. Scheduled runs may be late.

## Not done yet (next iterations)
- "Manage preferences" flow for already-active subscribers (currently re-subscribing an active email is a no-op).
- Purge of unverified rows older than 48h (simple scheduled D1 delete).
- Tests, rate limiting beyond Turnstile + resend cooldown, privacy policy page.
