// Admin page + API. Fails closed: every route returns 404 until ADMIN_PASSWORD (>=16 chars) and
// ADMIN_SESSION_SECRET (>=32 chars) are set as Worker secrets.
const enc = new TextEncoder();
const hex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
const now = () => Math.floor(Date.now() / 1000);

export const SESSION_TTL = 30 * 60; // absolute, not sliding
const COOKIE = "__Host-cvea_admin";
const WINDOW = 15 * 60;
const LOCK = 15 * 60;
const MAX_FAILS_IP = 5;
const MAX_FAILS_GLOBAL = 30;
const PAGE_SIZE = 25;
const STATUSES = ["pending", "active", "unsubscribed"];

export async function hmacHex(secret, msg) {
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return hex(await crypto.subtle.sign("HMAC", key, enc.encode(msg)));
}
export function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

export function maskEmail(email) {
  const s = String(email || "");
  const at = s.lastIndexOf("@");
  if (at < 1) return "***";
  return `${s[0]}***${s.slice(at)}`;
}
export const escapeLike = (s) => s.replace(/[\\%_]/g, (c) => "\\" + c);

export function adminConfigured(env) {
  return (
    typeof env.ADMIN_PASSWORD === "string" && env.ADMIN_PASSWORD.length >= 16 &&
    typeof env.ADMIN_SESSION_SECRET === "string" && env.ADMIN_SESSION_SECRET.length >= 32
  );
}

// ---- session token: v1.<exp>.<nonce>.<sig>; sig = HMAC(secret, "admin-session:<exp>.<nonce>") ----
export async function makeSession(secret, t = now()) {
  const exp = t + SESSION_TTL;
  const nonce = hex(crypto.getRandomValues(new Uint8Array(16)));
  const sig = await hmacHex(secret, `admin-session:${exp}.${nonce}`);
  return `v1.${exp}.${nonce}.${sig}`;
}
export async function checkSession(secret, token, t = now()) {
  if (typeof token !== "string") return false;
  const p = token.split(".");
  if (p.length !== 4 || p[0] !== "v1" || !/^\d{1,12}$/.test(p[1]) || !/^[0-9a-f]{32}$/.test(p[2])) return false;
  const exp = Number(p[1]);
  if (exp <= t || exp - t > SESSION_TTL + 5) return false;
  return timingSafeEqual(await hmacHex(secret, `admin-session:${exp}.${p[2]}`), p[3]);
}
function cookieValue(request) {
  const h = request.headers.get("cookie") || "";
  for (const part of h.split(";")) {
    const i = part.indexOf("=");
    if (i > 0 && part.slice(0, i).trim() === COOKIE) return part.slice(i + 1).trim();
  }
  return "";
}

const secHeaders = {
  "cache-control": "no-store",
  "x-robots-tag": "noindex, nofollow, noarchive",
  "referrer-policy": "no-referrer",
  "x-content-type-options": "nosniff",
  "x-frame-options": "DENY",
  "cross-origin-opener-policy": "same-origin",
  "cross-origin-resource-policy": "same-origin",
};
const CSP =
  "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; " +
  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

const jres = (obj, status = 200, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...secHeaders, ...extra } });
const notFound = () => new Response("Not found", { status: 404, headers: { ...secHeaders } });


// ---- Cloudflare Access (second factor), enforced in the Worker as defence in depth ----
// When ACCESS_TEAM_DOMAIN (team name only, e.g. "myteam") and ACCESS_AUD (application AUD tag) are set, every admin
// request must carry a valid Cf-Access-Jwt-Assertion (RS256, signed by the team's keys). A half-configured pair fails closed.
const b64uToBytes = (s) => {
  const p = s.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(p + "=".repeat((4 - (p.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};
const b64uJson = (s) => JSON.parse(new TextDecoder().decode(b64uToBytes(s)));
const TEAM_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

export async function verifyAccessJwt(token, { team, aud, getJwk, t = now() }) {
  if (typeof token !== "string") return false;
  const parts = token.split(".");
  if (parts.length !== 3) return false;
  try {
    const header = b64uJson(parts[0]);
    const payload = b64uJson(parts[1]);
    if (header.alg !== "RS256" || typeof header.kid !== "string") return false;
    if (payload.iss !== `https://${team}.cloudflareaccess.com`) return false;
    const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
    if (!auds.includes(aud)) return false;
    if (typeof payload.exp !== "number" || payload.exp <= t) return false;
    if (typeof payload.nbf === "number" && payload.nbf > t + 60) return false;
    const jwk = await getJwk(header.kid);
    if (!jwk) return false;
    const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uToBytes(parts[2]), enc.encode(`${parts[0]}.${parts[1]}`));
  } catch {
    return false;
  }
}

let jwksCache = { team: "", at: 0, keys: [] };
async function jwkFor(team, kid) {
  const t = now();
  const fresh = jwksCache.team === team && t - jwksCache.at < 3600;
  const hit = fresh && jwksCache.keys.find((k) => k.kid === kid);
  if (hit) return hit;
  if (fresh && t - jwksCache.at < 60) return null; // unknown kid: refetch at most once a minute
  const r = await fetch(`https://${team}.cloudflareaccess.com/cdn-cgi/access/certs`);
  if (!r.ok) return null;
  const j = await r.json();
  jwksCache = { team, at: t, keys: Array.isArray(j.keys) ? j.keys : [] };
  return jwksCache.keys.find((k) => k.kid === kid) || null;
}

// returns null when OK, or a Response to send instead
async function accessGate(request, env) {
  const hasTeam = !!env.ACCESS_TEAM_DOMAIN, hasAud = !!env.ACCESS_AUD;
  if (!hasTeam && !hasAud) return null; // Access not configured: password layer only
  if (!hasTeam || !hasAud || !TEAM_RE.test(String(env.ACCESS_TEAM_DOMAIN))) return notFound(); // half/bad config: fail closed
  const team = String(env.ACCESS_TEAM_DOMAIN);
  const ok = await verifyAccessJwt(request.headers.get("cf-access-jwt-assertion"), {
    team, aud: String(env.ACCESS_AUD), getJwk: (kid) => jwkFor(team, kid),
  });
  return ok ? null : jres({ ok: false, error: "Forbidden" }, 403);
}
// ---- throttle + audit (D1; IPs only as truncated HMAC) ----
async function ipKey(env, request) {
  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  return (await hmacHex(env.ADMIN_SESSION_SECRET, `ip:${ip}`)).slice(0, 32);
}
async function locked(env, key, t) {
  const r = await env.DB.prepare("SELECT locked_until FROM admin_throttle WHERE key=?").bind(key).first();
  return r && r.locked_until > t ? r.locked_until - t : 0;
}
async function recordFail(env, key, max, t) {
  await env.DB.prepare(
    `INSERT INTO admin_throttle (key, fails, window_start, locked_until) VALUES (?,1,?,0)
     ON CONFLICT(key) DO UPDATE SET
       fails = CASE WHEN window_start + ? < ? THEN 1 ELSE fails + 1 END,
       window_start = CASE WHEN window_start + ? < ? THEN ? ELSE window_start END`
  ).bind(key, t, WINDOW, t, WINDOW, t, t).run();
  await env.DB.prepare("UPDATE admin_throttle SET locked_until=? WHERE key=? AND fails>=?").bind(t + LOCK, key, max).run();
}
async function audit(env, action, subscriberId, ipHash) {
  await env.DB.prepare("INSERT INTO admin_audit (at, action, subscriber_id, ip_hash) VALUES (?,?,?,?)")
    .bind(now(), action, subscriberId ?? null, ipHash ? ipHash.slice(0, 12) : null).run();
}

// ---- static admin page, served through the Worker so it gets strict headers ----
async function servePage(request, env, url) {
  if (request.method !== "GET" && request.method !== "HEAD") return notFound();
  const map = { "/admin": "/admin.html", "/admin/": "/admin.html", "/admin.js": "/admin.js", "/admin.css": "/admin.css" };
  const target = map[url.pathname];
  if (!target) return notFound();
  const r = await env.ASSETS.fetch(new Request(new URL(target, url.origin), { method: "GET" }));
  if (!r.ok) return notFound();
  const h = new Headers(r.headers);
  for (const [k, v] of Object.entries(secHeaders)) h.set(k, v);
  h.set("content-security-policy", CSP);
  h.delete("etag");
  return new Response(r.body, { status: 200, headers: h });
}

const sameOrigin = (request, url) => request.headers.get("origin") === url.origin;

async function login(request, env, url) {
  if (!sameOrigin(request, url)) return jres({ ok: false, error: "Forbidden" }, 403);
  const t = now();
  const ik = await ipKey(env, request);
  const wait = Math.max(await locked(env, `ip:${ik}`, t), await locked(env, "global", t));
  if (wait) return jres({ ok: false, error: "Too many attempts. Try again later." }, 429, { "retry-after": String(wait) });
  let b;
  try { b = await request.json(); } catch { return jres({ ok: false, error: "Invalid request" }, 400); }
  const pw = typeof b.password === "string" ? b.password.slice(0, 256) : "";
  // Compare HMAC digests (equal length, independent of password length).
  const [a, e] = await Promise.all([hmacHex(env.ADMIN_SESSION_SECRET, `pw:${pw}`), hmacHex(env.ADMIN_SESSION_SECRET, `pw:${env.ADMIN_PASSWORD}`)]);
  if (!timingSafeEqual(a, e)) {
    await recordFail(env, `ip:${ik}`, MAX_FAILS_IP, t);
    await recordFail(env, "global", MAX_FAILS_GLOBAL, t);
    await audit(env, "login_fail", null, ik);
    return jres({ ok: false, error: "Invalid credentials" }, 401);
  }
  await env.DB.prepare("DELETE FROM admin_throttle WHERE key=?").bind(`ip:${ik}`).run();
  await audit(env, "login_ok", null, ik);
  // opportunistic retention: audit 90 days, stale throttle rows 1 day
  await env.DB.prepare("DELETE FROM admin_audit WHERE at < ?").bind(t - 90 * 86400).run();
  await env.DB.prepare("DELETE FROM admin_throttle WHERE window_start < ? AND locked_until < ?").bind(t - 86400, t).run();
  const token = await makeSession(env.ADMIN_SESSION_SECRET, t);
  return jres({ ok: true }, 200, { "set-cookie": `${COOKIE}=${token}; Path=/; Max-Age=${SESSION_TTL}; HttpOnly; Secure; SameSite=Strict` });
}

const safeJson = (s) => { try { const v = JSON.parse(s); return Array.isArray(v) ? v : []; } catch { return []; } };
const intId = (v) => (Number.isInteger(v) && v > 0 ? v : null);

export async function handleAdmin(request, env, url) {
  if (!adminConfigured(env)) return notFound();
  const gate = await accessGate(request, env);
  if (gate) return gate;
  const p = url.pathname;
  if (!p.startsWith("/api/admin/")) return servePage(request, env, url);

  if (p === "/api/admin/login" && request.method === "POST") return login(request, env, url);

  // Everything below needs a valid session.
  if (!(await checkSession(env.ADMIN_SESSION_SECRET, cookieValue(request)))) return jres({ ok: false, error: "Unauthorized" }, 401);
  const ik = await ipKey(env, request);
  const t = now();

  if (request.method === "GET") {
    if (p === "/api/admin/summary") {
      const rows = (await env.DB.prepare("SELECT status, COUNT(*) AS n FROM subscribers GROUP BY status").all()).results;
      const stale = await env.DB.prepare("SELECT COUNT(*) AS n FROM subscribers WHERE status='pending' AND created_at < ?").bind(t - 48 * 3600).first();
      const counts = { pending: 0, active: 0, unsubscribed: 0 };
      for (const r of rows) if (r.status in counts) counts[r.status] = r.n;
      return jres({ ok: true, counts, stalePending: stale ? stale.n : 0 });
    }
    if (p === "/api/admin/subscribers") {
      const status = STATUSES.includes(url.searchParams.get("status")) ? url.searchParams.get("status") : "";
      const q = escapeLike((url.searchParams.get("q") || "").trim().toLowerCase().slice(0, 100));
      const page = Math.min(10000, Math.max(0, parseInt(url.searchParams.get("page") || "0", 10) || 0));
      const where = "(?1 = '' OR status = ?1) AND (?2 = '' OR email LIKE '%' || ?2 || '%' ESCAPE '\\')";
      const total = await env.DB.prepare(`SELECT COUNT(*) AS n FROM subscribers WHERE ${where}`).bind(status, q).first();
      const rows = (await env.DB.prepare(
        `SELECT id, email, status, created_at, verified_at, last_digest_at, min_severity, kev_only, min_epss, vendors, keywords, cwes
         FROM subscribers WHERE ${where} ORDER BY id DESC LIMIT ?3 OFFSET ?4`
      ).bind(status, q, PAGE_SIZE, page * PAGE_SIZE).all()).results;
      return jres({
        ok: true, total: total ? total.n : 0, page, pageSize: PAGE_SIZE,
        items: rows.map((r) => ({
          id: r.id, email: maskEmail(r.email), status: r.status, createdAt: r.created_at, verifiedAt: r.verified_at,
          lastDigestAt: r.last_digest_at, minSeverity: r.min_severity, kevOnly: !!r.kev_only, minEpss: r.min_epss,
          vendors: safeJson(r.vendors), keywords: safeJson(r.keywords), cwes: safeJson(r.cwes),
        })),
      });
    }
    if (p === "/api/admin/audit") {
      const rows = (await env.DB.prepare("SELECT at, action, subscriber_id, ip_hash FROM admin_audit ORDER BY id DESC LIMIT 50").all()).results;
      return jres({ ok: true, items: rows.map((r) => ({ at: r.at, action: r.action, subscriberId: r.subscriber_id, ip: r.ip_hash })) });
    }
    return jres({ ok: false, error: "Not found" }, 404);
  }

  if (request.method === "POST") {
    // CSRF: SameSite=Strict cookie + exact Origin match + JSON body (not sendable cross-site without CORS preflight).
    if (!sameOrigin(request, url) || !(request.headers.get("content-type") || "").startsWith("application/json"))
      return jres({ ok: false, error: "Forbidden" }, 403);
    let b;
    try { b = await request.json(); } catch { return jres({ ok: false, error: "Invalid request" }, 400); }
    if (p === "/api/admin/logout") {
      await audit(env, "logout", null, ik);
      return jres({ ok: true }, 200, { "set-cookie": `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict` });
    }
    const id = intId(b.id);
    if (!id) return jres({ ok: false, error: "Invalid id" }, 400);
    if (p === "/api/admin/reveal") {
      const r = await env.DB.prepare("SELECT email FROM subscribers WHERE id=?").bind(id).first();
      if (!r) return jres({ ok: false, error: "Not found" }, 404);
      await audit(env, "reveal", id, ik);
      return jres({ ok: true, email: r.email });
    }
    if (p === "/api/admin/unsubscribe") {
      const r = await env.DB.prepare("UPDATE subscribers SET status='unsubscribed', verify_hash=NULL WHERE id=?").bind(id).run();
      if (!r.meta.changes) return jres({ ok: false, error: "Not found" }, 404);
      await audit(env, "unsubscribe", id, ik);
      return jres({ ok: true });
    }
    if (p === "/api/admin/delete") {
      if (b.confirm !== true) return jres({ ok: false, error: "Confirmation required" }, 400);
      const r = await env.DB.prepare("DELETE FROM subscribers WHERE id=?").bind(id).run();
      if (!r.meta.changes) return jres({ ok: false, error: "Not found" }, 404);
      await audit(env, "delete", id, ik);
      return jres({ ok: true });
    }
  }
  return jres({ ok: false, error: "Not found" }, 404);
}
