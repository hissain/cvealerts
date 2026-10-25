// Daily digest: reads active subscribers from D1 (REST API), matches new CVEs, sends via Brevo.
// Env: CF_ACCOUNT_ID, CF_D1_DATABASE_ID, CF_API_TOKEN (D1 edit), BREVO_API_KEY, UNSUB_SECRET,
//      SITE_URL, MAIL_FROM_EMAIL, MAIL_FROM_NAME, MAX_EMAILS_PER_RUN (default 90), DRY_RUN=1 to skip sending
import { readFile } from "node:fs/promises";
import { matches, unsubToken, sleep } from "./lib.mjs";

const e = process.env;
for (const k of ["CF_ACCOUNT_ID", "CF_D1_DATABASE_ID", "CF_API_TOKEN", "UNSUB_SECRET", "SITE_URL"]) if (!e[k]) throw new Error(`Missing env ${k}`);
const DRY = e.DRY_RUN === "1";
if (!DRY && !e.BREVO_API_KEY) throw new Error("Missing env BREVO_API_KEY");
const MAX_EMAILS = Number(e.MAX_EMAILS_PER_RUN || 90); // stay under the free-plan daily cap
const MAX_ITEMS = 40;

async function d1(sql, params = []) {
  const r = await fetch(`https://api.cloudflare.com/client/v4/accounts/${e.CF_ACCOUNT_ID}/d1/database/${e.CF_D1_DATABASE_ID}/query`, {
    method: "POST",
    headers: { authorization: `Bearer ${e.CF_API_TOKEN}`, "content-type": "application/json" },
    body: JSON.stringify({ sql, params }),
  });
  const j = await r.json();
  if (!r.ok || !j.success) throw new Error(`D1 error: ${JSON.stringify(j.errors)}`);
  return j.result[0].results;
}

const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function render(list, unsubUrl) {
  const rows = list.slice(0, MAX_ITEMS);
  const more = list.length - rows.length;
  const html = `<h2>${list.length} new CVE${list.length > 1 ? "s" : ""} matching your filters</h2>` +
    rows.map((c) => `<p><b><a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}">${esc(c.id)}</a></b> &middot; ${esc(c.severity)}${c.score != null ? " " + c.score : ""}` +
      `${c.kev ? " &middot; <b>KEV (exploited)</b>" : ""}${c.epss != null ? " &middot; EPSS " + (c.epss * 100).toFixed(1) + "%" : ""}<br>${esc(c.desc.slice(0, 300))}${c.desc.length > 300 ? "…" : ""}</p>`).join("") +
    (more > 0 ? `<p>…and ${more} more on <a href="${esc(e.SITE_URL)}">the dashboard</a>.</p>` : "") +
    `<hr><p style="font-size:12px"><a href="${esc(unsubUrl)}">Unsubscribe</a></p>`;
  const text = `${list.length} new CVE(s) matching your filters\n\n` +
    rows.map((c) => `${c.id} [${c.severity}${c.score != null ? " " + c.score : ""}]${c.kev ? " KEV" : ""}\n${c.desc.slice(0, 300)}\nhttps://nvd.nist.gov/vuln/detail/${c.id}\n`).join("\n") +
    (more > 0 ? `\n...and ${more} more: ${e.SITE_URL}\n` : "") + `\nUnsubscribe: ${unsubUrl}\n`;
  return { html, text };
}

async function send(to, subject, html, text, unsubUrl) {
  const r = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": e.BREVO_API_KEY, "content-type": "application/json" },
    body: JSON.stringify({
      sender: { email: e.MAIL_FROM_EMAIL, name: e.MAIL_FROM_NAME || "CVE Alert" }, to: [{ email: to }], subject, htmlContent: html, textContent: text,
      headers: { "List-Unsubscribe": `<${unsubUrl}>`, "List-Unsubscribe-Post": "List-Unsubscribe=One-Click" },
    }),
  });
  if (!r.ok) throw new Error(`Brevo ${r.status}: ${(await r.text()).slice(0, 200)}`);
}

const store = JSON.parse(await readFile(new URL("../site/data/cves.json", import.meta.url), "utf8"));
// Purge never-verified signups older than 48h (privacy: don't retain unconfirmed emails)
if (!DRY) await d1("DELETE FROM subscribers WHERE status = 'pending' AND COALESCE(last_verify_sent, created_at) < ?", [Math.floor(Date.now() / 1000) - 48 * 3600]);
const subs = await d1("SELECT * FROM subscribers WHERE status = 'active' ORDER BY COALESCE(last_digest_at, 0) ASC");
console.log(`${subs.length} active subscribers, ${store.cves.length} CVEs in store`);

let sent = 0;
for (const s of subs) {
  if (sent >= MAX_EMAILS) { console.log("Daily email cap reached; remaining subscribers wait for next run."); break; }
  const since = s.last_digest_at || s.verified_at || 0;
  const hits = store.cves.filter((c) => c.firstSeen > since && matches(c, s))
    .sort((a, b) => Number(b.kev) - Number(a.kev) || (b.score ?? 0) - (a.score ?? 0));
  const ts = Math.floor(Date.now() / 1000);
  if (!hits.length) { await d1("UPDATE subscribers SET last_digest_at = ? WHERE id = ?", [ts, s.id]); continue; }
  const unsubUrl = `${e.SITE_URL}/api/unsubscribe?id=${s.id}&t=${unsubToken(e.UNSUB_SECRET, s.id)}`;
  const { html, text } = render(hits, unsubUrl);
  try {
    if (DRY) console.log(`[dry-run] would send ${hits.length} CVEs to subscriber #${s.id}`);
    else await send(s.email, `CVE Alert: ${hits.length} new match${hits.length > 1 ? "es" : ""}${hits.some((h) => h.kev) ? " (incl. exploited)" : ""}`, html, text, unsubUrl);
    if (!DRY) await d1("UPDATE subscribers SET last_digest_at = ? WHERE id = ?", [ts, s.id]);
    sent++;
    await sleep(300);
  } catch (err) {
    console.error(`Failed for subscriber #${s.id}: ${err.message}`); // leave last_digest_at so it retries next run
  }
}
console.log(`Sent ${sent} digest(s)`);
