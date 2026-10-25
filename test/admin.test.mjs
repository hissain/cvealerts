import test from "node:test";
import assert from "node:assert/strict";
import { maskEmail, escapeLike, makeSession, checkSession, timingSafeEqual, adminConfigured, SESSION_TTL, verifyAccessJwt } from "../worker/admin.js";

const SECRET = "s".repeat(40);

test("maskEmail hides the local part", () => {
  assert.equal(maskEmail("john.doe@gmail.com"), "j***@gmail.com");
  assert.equal(maskEmail("a@b.co"), "a***@b.co");
  assert.equal(maskEmail("garbage"), "***");
  assert.equal(maskEmail(null), "***");
});

test("escapeLike neutralises LIKE wildcards", () => {
  assert.equal(escapeLike("50%_off\\"), "50\\%\\_off\\\\");
});

test("session token: valid, tampered, expired, wrong secret, malformed", async () => {
  const t = 1_800_000_000;
  const tok = await makeSession(SECRET, t);
  assert.equal(await checkSession(SECRET, tok, t + 10), true);
  assert.equal(await checkSession(SECRET, tok, t + SESSION_TTL + 1), false);            // expired
  assert.equal(await checkSession("x".repeat(40), tok, t + 10), false);                  // wrong secret
  const p = tok.split(".");
  assert.equal(await checkSession(SECRET, [p[0], String(Number(p[1]) + 3600), p[2], p[3]].join("."), t + 10), false); // exp extended
  assert.equal(await checkSession(SECRET, tok.slice(0, -1) + (tok.endsWith("0") ? "1" : "0"), t + 10), false);        // sig flipped
  for (const bad of ["", "v1", "v1.1.2.3", undefined, null, 42, "v2." + p.slice(1).join(".")]) assert.equal(await checkSession(SECRET, bad, t + 10), false);
});

test("adminConfigured fails closed on missing or weak secrets", () => {
  assert.equal(adminConfigured({}), false);
  assert.equal(adminConfigured({ ADMIN_PASSWORD: "short", ADMIN_SESSION_SECRET: SECRET }), false);
  assert.equal(adminConfigured({ ADMIN_PASSWORD: "p".repeat(16), ADMIN_SESSION_SECRET: "short" }), false);
  assert.equal(adminConfigured({ ADMIN_PASSWORD: "p".repeat(16), ADMIN_SESSION_SECRET: SECRET }), true);
});

test("timingSafeEqual", () => {
  assert.equal(timingSafeEqual("abc", "abc"), true);
  assert.equal(timingSafeEqual("abc", "abd"), false);
  assert.equal(timingSafeEqual("abc", "abcd"), false);
  assert.equal(timingSafeEqual("abc", undefined), false);
});

// ---- Cloudflare Access JWT verification ----
const b64u = (buf) => Buffer.from(buf).toString("base64url");
async function mkKey(kid) {
  const kp = await crypto.subtle.generateKey({ name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["sign", "verify"]);
  const jwk = { ...(await crypto.subtle.exportKey("jwk", kp.publicKey)), kid, alg: "RS256", use: "sig" };
  return { priv: kp.privateKey, jwk };
}
async function mkJwt(priv, kid, claims, alg = "RS256") {
  const h = b64u(JSON.stringify({ alg, kid, typ: "JWT" }));
  const p = b64u(JSON.stringify(claims));
  const sig = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", priv, new TextEncoder().encode(`${h}.${p}`));
  return `${h}.${p}.${b64u(sig)}`;
}

test("Access JWT: accepts valid, rejects tampered / wrong aud / iss / expired / alg / key / kid", async () => {
  const t = 1_800_000_000;
  const a = await mkKey("k1"), other = await mkKey("k1");
  const base = { iss: "https://myteam.cloudflareaccess.com", aud: ["AUDTAG"], exp: t + 600, email: "me@example.com" };
  const opts = { team: "myteam", aud: "AUDTAG", getJwk: async (kid) => (kid === "k1" ? a.jwk : null), t };
  const good = await mkJwt(a.priv, "k1", base);
  assert.equal(await verifyAccessJwt(good, opts), true);

  const [h, p, s] = good.split(".");
  const forged = b64u(JSON.stringify({ ...base, email: "evil@example.com" }));
  assert.equal(await verifyAccessJwt(`${h}.${forged}.${s}`, opts), false);                                   // payload tampered
  assert.equal(await verifyAccessJwt(await mkJwt(a.priv, "k1", { ...base, aud: ["OTHER"] }), opts), false);  // wrong aud
  assert.equal(await verifyAccessJwt(await mkJwt(a.priv, "k1", { ...base, iss: "https://evil.cloudflareaccess.com" }), opts), false); // wrong iss
  assert.equal(await verifyAccessJwt(await mkJwt(a.priv, "k1", { ...base, exp: t - 1 }), opts), false);      // expired
  assert.equal(await verifyAccessJwt(await mkJwt(a.priv, "k1", { ...base, exp: undefined }), opts), false);  // no exp
  assert.equal(await verifyAccessJwt(await mkJwt(a.priv, "k1", base, "none"), opts), false);                 // alg not RS256
  assert.equal(await verifyAccessJwt(await mkJwt(other.priv, "k1", base), opts), false);                     // signed by a different key
  assert.equal(await verifyAccessJwt(await mkJwt(a.priv, "unknown", base), opts), false);                    // unknown kid
  for (const bad of [undefined, null, "", "a.b", "a.b.c.d", "x.y.z"]) assert.equal(await verifyAccessJwt(bad, opts), false);
});