"use strict";
// All dynamic content is written with textContent / createElement only (stored values are attacker-controlled).
const $ = (id) => document.getElementById(id);
let page = 0;

function el(tag, text, cls) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (cls) e.className = cls;
  return e;
}
const fmt = (s) => (s ? new Date(s * 1000).toISOString().replace("T", " ").slice(0, 16) + "Z" : "-");
function say(text, ok) { const m = $("msg"); m.textContent = text || ""; m.className = ok ? "ok" : ""; }

async function api(path, body) {
  const opt = body === undefined
    ? { method: "GET", credentials: "same-origin", cache: "no-store" }
    : { method: "POST", credentials: "same-origin", cache: "no-store", headers: { "content-type": "application/json" }, body: JSON.stringify(body) };
  let r;
  try { r = await fetch(path, opt); } catch (e) {
    // An expired Cloudflare Access session answers with a cross-origin redirect, which fetch reports as a network error:
    // reload once so Access can show its sign-in page (guarded against reload loops).
    const last = Number(sessionStorage.getItem("adminReload") || 0);
    if (Date.now() - last > 15000) { sessionStorage.setItem("adminReload", String(Date.now())); location.reload(); }
    throw e;
  }
  let data = {};
  try { data = await r.json(); } catch { /* non-JSON error */ }
  if (r.status === 401 && path !== "/api/admin/login") { showLogin(); throw new Error("signed out"); }
  return { status: r.status, data };
}

function showLogin() {
  $("app").hidden = true; $("login").hidden = false; $("pw").value = ""; $("rows").replaceChildren(); $("audit").replaceChildren();
}
function showApp() { $("login").hidden = true; $("app").hidden = false; }

async function signIn() {
  $("loginMsg").textContent = "";
  const { status, data } = await api("/api/admin/login", { password: $("pw").value });
  $("pw").value = "";
  if (status === 200 && data.ok) { showApp(); await refresh(); return; }
  $("loginMsg").textContent = status === 429 ? "Too many attempts. Try again later." : "Sign-in failed.";
}

async function refresh() {
  say("");
  const s = await api("/api/admin/summary");
  if (s.data.ok) {
    const c = $("counts"); c.replaceChildren();
    for (const k of ["active", "pending", "unsubscribed"]) c.append(el("span", `${k}: ${s.data.counts[k]}`));
    if (s.data.stalePending) c.append(el("span", `stale pending (>48h): ${s.data.stalePending}`));
  }
  const qs = new URLSearchParams({ status: $("status").value, q: $("q").value, page: String(page) });
  const r = await api("/api/admin/subscribers?" + qs);
  if (!r.data.ok) { say("Could not load subscribers."); return; }
  const tbody = $("rows"); tbody.replaceChildren();
  for (const it of r.data.items) tbody.append(row(it));
  const pages = Math.max(1, Math.ceil(r.data.total / r.data.pageSize));
  $("pageInfo").textContent = `${r.data.total} total, page ${r.data.page + 1} of ${pages}`;
  $("prev").disabled = page <= 0; $("next").disabled = page + 1 >= pages;
}

function filtersText(it) {
  const parts = [`min ${it.minSeverity}`];
  if (it.kevOnly) parts.push("KEV only");
  if (it.minEpss) parts.push(`EPSS>=${it.minEpss}`);
  if (it.vendors.length) parts.push("vendors: " + it.vendors.join(", "));
  if (it.keywords.length) parts.push("keywords: " + it.keywords.join(", "));
  if (it.cwes.length) parts.push("cwes: " + it.cwes.join(", "));
  return parts.join(" | ");
}

function row(it) {
  const tr = document.createElement("tr");
  const emailCell = el("td", it.email);
  const act = el("td", undefined, "actions");
  const reveal = el("button", "Reveal");
  reveal.type = "button";
  reveal.onclick = async () => {
    const r = await api("/api/admin/reveal", { id: it.id });
    if (!r.data.ok) { say("Reveal failed."); return; }
    emailCell.textContent = r.data.email;
    setTimeout(() => { emailCell.textContent = it.email; }, 15000); // auto-hide
  };
  act.append(reveal);
  if (it.status !== "unsubscribed") {
    const u = el("button", "Unsubscribe"); u.type = "button";
    u.onclick = async () => {
      if (!confirm(`Unsubscribe subscriber #${it.id}?`)) return;
      const r = await api("/api/admin/unsubscribe", { id: it.id });
      say(r.data.ok ? `Subscriber #${it.id} unsubscribed.` : "Action failed.", r.data.ok);
      await refresh();
    };
    act.append(u);
  }
  const d = el("button", "Delete", "danger"); d.type = "button";
  d.onclick = async () => {
    if (!confirm(`Permanently delete subscriber #${it.id}? This cannot be undone.`)) return;
    const r = await api("/api/admin/delete", { id: it.id, confirm: true });
    say(r.data.ok ? `Subscriber #${it.id} deleted.` : "Action failed.", r.data.ok);
    await refresh();
  };
  act.append(d);
  tr.append(el("td", String(it.id)), emailCell, el("td", it.status), el("td", filtersText(it)),
    el("td", fmt(it.createdAt)), el("td", fmt(it.verifiedAt)), el("td", fmt(it.lastDigestAt)), act);
  return tr;
}

async function loadAudit() {
  const r = await api("/api/admin/audit");
  const tb = $("audit"); tb.replaceChildren();
  if (!r.data.ok) return;
  for (const a of r.data.items) {
    const tr = document.createElement("tr");
    tr.append(el("td", fmt(a.at)), el("td", a.action), el("td", a.subscriberId ? `#${a.subscriberId}` : "-"), el("td", a.ip || "-"));
    tb.append(tr);
  }
}

$("loginBtn").onclick = signIn;
$("pw").addEventListener("keydown", (e) => { if (e.key === "Enter") signIn(); });
$("searchBtn").onclick = () => { page = 0; refresh(); };
$("q").addEventListener("keydown", (e) => { if (e.key === "Enter") { page = 0; refresh(); } });
$("status").onchange = () => { page = 0; refresh(); };
$("prev").onclick = () => { if (page > 0) { page--; refresh(); } };
$("next").onclick = () => { page++; refresh(); };
$("auditBox").addEventListener("toggle", (e) => { if (e.target.open) loadAudit(); });
$("logoutBtn").onclick = async () => { try { await api("/api/admin/logout", {}); } finally { showLogin(); } };

// Probe for an existing session; fall back to the login form.
(async () => {
  try {
    const s = await api("/api/admin/summary");
    if (s.data.ok) { showApp(); await refresh(); } else showLogin();
  } catch { showLogin(); }
})();
