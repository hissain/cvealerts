# CVE Alert

A free, open-source site for keeping up with newly published software vulnerabilities (CVEs). Browse recent CVEs in a filterable dashboard, or subscribe to a daily email that only contains the vulnerabilities you care about.

**Live site: https://cvealerts.infomity.workers.dev**

## What you can do

### Browse the dashboard
- See recently published CVEs with their description, severity, CVSS score and publish date.
- Filter by severity, by whether the CVE is on the CISA Known Exploited Vulnerabilities (KEV) list, by EPSS exploit-likelihood score, and by keyword.
- Filtering happens in your browser, so searching is instant and does not send your queries anywhere.
- The dashboard shows roughly the last 10 days of CVEs. CVEs on the KEV list are kept even if they are older.

### Get email alerts
1. Open the site and find the subscribe form.
2. Enter your email address and choose your filters (see below).
3. Complete the CAPTCHA and submit.
4. Check your inbox for a message titled "Confirm your CVE Alert subscription" and click the link. If you do not see it, check your spam folder.
5. Once confirmed, you receive a digest by email containing only CVEs that match your filters and appeared since your last digest.

Alerts are not active until you click the confirmation link. The link is valid for 24 hours; unconfirmed sign-ups are removed.

### Alert filters
| Filter | What it does |
| --- | --- |
| Minimum severity | Only CVEs at or above Low, Medium, High or Critical. The default is High. |
| Known exploited only | Only CVEs listed in the CISA KEV catalog. |
| Minimum EPSS | Only CVEs whose exploit-prediction score meets your threshold. |
| Vendor / product | Only CVEs that affect the vendors or products you list (for example `microsoft`, `apache`). |
| Keyword | Only CVEs whose description contains your keywords. |
| CWE | Only CVEs with the weakness types you list (for example `CWE-79`). |

If you set several filters, a CVE must satisfy all of them to be included.

### Unsubscribe
Every email contains an unsubscribe link, and mail clients that support it also show a one-click unsubscribe option. Unsubscribing takes effect immediately.

## Your data
- When you subscribe, the service stores your email address, your filter choices, your subscription status and a few timestamps.
- The confirmation token is random and only a hash of it is stored.
- Your email address is used only to send the confirmation message and your alerts.
- Signing up with an address that is already registered shows the same message as any other sign-up, so the form cannot be used to check whether someone is subscribed.
- To have your data removed, unsubscribe, or open an issue on this repository.

## Data sources
- [NVD](https://nvd.nist.gov/) (National Vulnerability Database) for CVE records, descriptions and CVSS scores.
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) for vulnerabilities known to be exploited in the wild.
- [FIRST EPSS](https://www.first.org/epss/) for exploit-prediction scores.

This project is not affiliated with or endorsed by NIST, CISA or FIRST.

## Limitations
- This is an early version. Email goes through a free-tier provider using a shared sender address, so messages can land in spam. Marking the first one as "not spam" helps.
- CVE data is refreshed on a schedule, not in real time, and digests are sent once a day. Scheduled jobs can run late.
- Severity and scores come from NVD. Newly published CVEs may show as "Unknown" until NVD has analysed them.
- There is no preferences page yet. To change filters, unsubscribe and subscribe again.
- CVE Alert is a convenience tool. Do not rely on it as your only source for security monitoring.

## How it works
```
GitHub Actions (ingest, every 3 hours)
    NVD + CISA KEV + EPSS  ->  site/data/cves.json  ->  deployed with the Worker
GitHub Actions (digest, daily)
    active subscribers in Cloudflare D1  ->  match filters  ->  email via Brevo
Browser
    static dashboard  +  subscribe form (Turnstile CAPTCHA)  ->  /api/subscribe  ->  D1 + confirmation email
```
Everything runs on free tiers: Cloudflare Workers, D1 and Turnstile, GitHub Actions, and Brevo. See `RESEARCH.md` for the options analysis and free-tier limits.

## Run your own copy
You need free accounts at GitHub, Cloudflare and Brevo, plus a free NVD API key.

1. Fork this repository and run `npm install --include=dev`.
2. Log in with `npx wrangler login`, then `npx wrangler d1 create cvealert` and put the resulting `database_id` in `wrangler.toml`. Run `npm run db:init`.
3. Create a Turnstile widget in the Cloudflare dashboard. Put the public site key in `wrangler.toml` as `TURNSTILE_SITEKEY`.
4. Set the Worker secrets (you are prompted for each value, nothing is stored in the repository):
   ```
   npx wrangler secret put TURNSTILE_SECRET
   npx wrangler secret put BREVO_API_KEY
   npx wrangler secret put UNSUB_SECRET
   npx wrangler secret put MAIL_FROM_EMAIL
   ```
   `UNSUB_SECRET` should be a long random string. `MAIL_FROM_EMAIL` must be a sender verified in Brevo.
5. Set `SITE_URL` in `wrangler.toml` to the address your Worker is served from (no trailing slash).
6. Add GitHub Actions secrets: `NVD_API_KEY`, `CLOUDFLARE_API_TOKEN` (Workers and D1 edit), `CLOUDFLARE_ACCOUNT_ID`, `CF_D1_DATABASE_ID`, `BREVO_API_KEY`, and `UNSUB_SECRET` (same value as the Worker's).
   Add GitHub Actions variables: `SITE_URL`, `MAIL_FROM_EMAIL`, `MAIL_FROM_NAME`, and optionally `MAX_EMAILS_PER_RUN` (default 90).
7. Run the `ingest` workflow once manually, then run `digest` with the dry-run option ticked.

### Local development
```
copy .env.example .env     # fill in your own values; .env is gitignored
npm run ingest             # writes site/data/cves.json
npm run db:init:local
npx wrangler dev           # needs a .dev.vars file; Turnstile test keys work locally
npm test
```
Never commit `.env`, `.dev.vars` or any API key. Both files are listed in `.gitignore`.

## Contributing
Issues and pull requests are welcome. Please do not include secrets, real subscriber email addresses or API keys in issues, logs or commits.

## License
Released under the [MIT License](LICENSE).