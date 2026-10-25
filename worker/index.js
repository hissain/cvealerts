// Cloudflare Worker: subscribe / verify / unsubscribe API (static site is served by ASSETS).
const SEVERITIES = ["ALL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,255}\.[^\s@]{2,}$/;
const VERIFY_TTL = 24 * 3600;
const RESEND_COOLDOWN = 10 * 60;

const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const sha256 = async (s) => hex(await crypto.subtle.digest("SHA-256", enc.encode(s)));
const now = () => Math.floor(Date.now() / 1000);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function hmac(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}
function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
const page = (title, body) =>
  new Response(
    `<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(title)}</title>` +
      `<body style="font-family:system-ui;max-width:32rem;margin:4rem auto;padding:0 1rem"><h1>${esc(title)}</h1><p>${body}</p><p><a href="/">Back to dashboard</a></p>`,
    { headers: { "content-type": "text/html;charset=utf-8", "cache-control": "no-store" } }
  );

function cleanList(v, max, re) {
  if (!Array.isArray(v)) return [];
  const out = [];
  for (const x of v) {
    const s = String(x).trim().toLowerCase().slice(0, 64);
    if (s && (!re || re.test(s)) && !out.includes(s)) out.push(s);
    if (out.length >= max) break;
  }
  return out;
}

async function verifyTurnstile(env, token, ip) {
  if (!token) return false;
  const body = new FormData();
  body.append("secret", env.TURNSTILE_SECRET);
  body.append("response", token);
  if (ip) body.append("remoteip", ip);
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
  return r.ok && (await r.json()).success === true;
}

async function sendMail(env, to, subject, html, text) {
  const r = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({
      sender: { email: env.MAIL_FROM_EMAIL, name: env.MAIL_FROM_NAME },
      to: [{ email: to }],
      subject,
      htmlContent: html,
      textContent: text,
    }),
  });
  if (!r.ok) throw new Error(`mail provider ${r.status}`);
}

async function handleSubscribe(request, env) {
  let b;
  try { b = await request.json(); } catch { return json({ ok: false, error: "Invalid request" }, 400); }
  const email = String(b.email || "").trim().toLowerCase();
  if (!EMAIL_RE.test(email) || email.length > 254) return json({ ok: false, error: "Please enter a valid email address." }, 400);
  const ip = request.headers.get("CF-Connecting-IP");
  if (!(await verifyTurnstile(env, b.turnstile, ip))) return json({ ok: false, error: "CAPTCHA check failed. Please retry." }, 400);

  const f = b.filters || {};
  const minSeverity = SEVERITIES.includes(String(f.minSeverity).toUpperCase()) ? String(f.minSeverity).toUpperCase() : "HIGH";
  const kevOnly = f.kevOnly ? 1 : 0;
  const minEpss = Math.min(1, Math.max(0, Number(f.minEpss) || 0));
  const vendors = cleanList(f.vendors, 20, /^[a-z0-9_.\-+]+$/);
  const keywords = cleanList(f.keywords, 20);
  const cwes = cleanList(f.cwes, 20, /^cwe-\d{1,5}$/).map((s) => s.toUpperCase());

  const row = await env.DB.prepare("SELECT id, status, last_verify_sent FROM subscribers WHERE email = ?").bind(email).first();
  const t = now();
  // Same generic answer in every case so the form can't be used to probe who is registered.
  const generic = json({ ok: true, message: "If that address can be subscribed, a verification email is on its way. The link expires in 24 hours." });

  if (row && row.status === "active") return generic; // already verified; filter changes need a future "manage" flow
  if (row && row.last_verify_sent && t - row.last_verify_sent < RESEND_COOLDOWN) return generic;

  const token = hex(crypto.getRandomValues(new Uint8Array(32)));
  const vh = await sha256(token);
  if (row) {
    await env.DB.prepare(
      "UPDATE subscribers SET status='pending', verify_hash=?, verify_expires=?, last_verify_sent=?, min_severity=?, kev_only=?, min_epss=?, vendors=?, keywords=?, cwes=? WHERE id=?"
    ).bind(vh, t + VERIFY_TTL, t, minSeverity, kevOnly, minEpss, JSON.stringify(vendors), JSON.stringify(keywords), JSON.stringify(cwes), row.id).run();
  } else {
    await env.DB.prepare(
      "INSERT INTO subscribers (email, status, verify_hash, verify_expires, created_at, last_verify_sent, min_severity, kev_only, min_epss, vendors, keywords, cwes) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(email, "pending", vh, t + VERIFY_TTL, t, t, minSeverity, kevOnly, minEpss, JSON.stringify(vendors), JSON.stringify(keywords), JSON.stringify(cwes)).run();
  }

  const link = `${env.SITE_URL}/api/verify?t=${token}`;
  try {
    await sendMail(env, email, "Confirm your CVE Alert subscription",
      `<p>Confirm your subscription to CVE alerts:</p><p><a href="${link}">Confirm my email</a></p><p>This link expires in 24 hours. If you didn't request this, ignore this message.</p>`,
      `Confirm your subscription to CVE alerts: ${link}\nThis link expires in 24 hours. If you didn't request this, ignore this message.`);
  } catch (e) {
    console.error("verification mail failed", e.message);
  }
  return generic;
}

async function handleVerify(url, env) {
  const token = url.searchParams.get("t") || "";
  if (!/^[0-9a-f]{64}$/.test(token)) return page("Invalid link", "This verification link is not valid.");
  const vh = await sha256(token);
  const row = await env.DB.prepare("SELECT id, verify_expires, status FROM subscribers WHERE verify_hash = ?").bind(vh).first();
  if (!row || row.status === "unsubscribed") return page("Invalid link", "This verification link is not valid or was already used.");
  if (row.verify_expires < now()) return page("Link expired", "Please subscribe again to get a new verification email.");
  const t = now();
  await env.DB.prepare("UPDATE subscribers SET status='active', verified_at=?, verify_hash=NULL, verify_expires=NULL, last_digest_at=? WHERE id=?").bind(t, t, row.id).run();
  return page("You're subscribed", "Your email is verified. You will receive a digest when new CVEs match your filters.");
}

async function handleUnsubscribe(request, url, env) {
  const id = parseInt(url.searchParams.get("id") || "", 10);
  const tok = url.searchParams.get("t") || "";
  if (!Number.isInteger(id) || id < 1) return page("Invalid link", "This unsubscribe link is not valid.");
  const expect = await hmac(env.UNSUB_SECRET, `unsub:${id}`);
  if (!timingSafeEqual(expect, tok)) return page("Invalid link", "This unsubscribe link is not valid.");
  await env.DB.prepare("UPDATE subscribers SET status='unsubscribed', verify_hash=NULL WHERE id=?").bind(id).run();
  if (request.method === "POST") return new Response(null, { status: 200 }); // RFC 8058 one-click
  return page("Unsubscribed", "You will no longer receive CVE alerts.");
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/api/config" && request.method === "GET") return json({ turnstileSiteKey: env.TURNSTILE_SITEKEY });
      if (url.pathname === "/api/subscribe" && request.method === "POST") return await handleSubscribe(request, env);
      if (url.pathname === "/api/verify" && request.method === "GET") return await handleVerify(url, env);
      if (url.pathname === "/api/unsubscribe" && (request.method === "GET" || request.method === "POST")) return await handleUnsubscribe(request, url, env);
    } catch (e) {
      console.error(e);
      return json({ ok: false, error: "Server error" }, 500);
    }
    return json({ ok: false, error: "Not found" }, 404);
  },
};
