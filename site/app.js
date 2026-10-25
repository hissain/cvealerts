const $ = (id) => document.getElementById(id);
const RANK = { UNKNOWN: 0, NONE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const PAGE = 50;
let all = [], view = [], page = 0;

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

async function load() {
  try {
    const r = await fetch("/data/cves.json", { cache: "no-cache" });
    if (!r.ok) throw new Error(r.status);
    const j = await r.json();
    all = j.cves;
    $("meta").textContent = `${j.count.toLocaleString()} CVEs · updated ${new Date(j.generated).toLocaleString()}`;
  } catch {
    $("meta").textContent = "CVE data is not available yet.";
  }
  render();
}

function stats() {
  const c = (f) => all.filter(f).length;
  $("stats").innerHTML = [
    ["Total", all.length], ["Critical", c((x) => x.severity === "CRITICAL")], ["High", c((x) => x.severity === "HIGH")],
    ["Exploited (KEV)", c((x) => x.kev)], ["Last 24h", c((x) => Date.now() - Date.parse(x.published) < 864e5)],
  ].map(([k, v]) => `<div class="stat"><b>${v.toLocaleString()}</b><span>${k}</span></div>`).join("");
}

function apply() {
  const q = $("q").value.trim().toLowerCase();
  const minSev = Number($("sev").value);
  const kev = $("kev").checked;
  const epss = Number($("epss").value || 0) / 100;
  const cwe = $("cwe").value.trim().toUpperCase();
  const sort = $("sort").value;
  view = all.filter((c) =>
    (RANK[c.severity] ?? 0) >= minSev && (!kev || c.kev) && (c.epss ?? 0) >= epss && (!cwe || c.cwes.includes(cwe)) &&
    (!q || c.id.toLowerCase().includes(q) || c.desc.toLowerCase().includes(q) || c.vendors.some((v) => v.includes(q)) || c.products.some((p) => p.includes(q))));
  const key = { published: (c) => c.published, modified: (c) => c.modified, score: (c) => c.score ?? -1, epss: (c) => c.epss ?? -1 }[sort];
  view.sort((a, b) => (key(a) < key(b) ? 1 : key(a) > key(b) ? -1 : 0));
}

function render() {
  stats();
  apply();
  const pages = Math.max(1, Math.ceil(view.length / PAGE));
  page = Math.min(page, pages - 1);
  const slice = view.slice(page * PAGE, page * PAGE + PAGE);
  $("rows").innerHTML = slice.map((c) => `
    <tr>
      <td><a href="https://nvd.nist.gov/vuln/detail/${esc(c.id)}" target="_blank" rel="noopener noreferrer">${esc(c.id)}</a>${c.kev ? ' <span class="badge kev" title="CISA Known Exploited">KEV</span>' : ""}</td>
      <td><span class="badge ${esc(c.severity.toLowerCase())}">${esc(c.severity)}</span></td>
      <td>${c.score ?? "–"}</td>
      <td>${c.epss != null ? (c.epss * 100).toFixed(1) + "%" : "–"}</td>
      <td>${esc(c.published.slice(0, 10))}</td>
      <td><details><summary>${esc(c.desc.slice(0, 140))}${c.desc.length > 140 ? "…" : ""}</summary>
        <p>${esc(c.desc)}</p>
        ${c.vendors.length ? `<p class="muted">Vendors: ${esc(c.vendors.slice(0, 8).join(", "))} · Products: ${esc(c.products.slice(0, 8).join(", "))}</p>` : ""}
        ${c.cwes.length ? `<p class="muted">${esc(c.cwes.join(", "))}</p>` : ""}
        ${c.refs.map((u) => /^https?:\/\//.test(u) ? `<a href="${esc(u)}" target="_blank" rel="noopener noreferrer">${esc(new URL(u).hostname)}</a>` : "").join(" · ")}
      </details></td>
    </tr>`).join("") || `<tr><td colspan="6">No CVEs match these filters.</td></tr>`;
  $("page").textContent = `Page ${page + 1} / ${pages} (${view.length.toLocaleString()} results)`;
  $("prev").disabled = page === 0;
  $("next").disabled = page >= pages - 1;
}

for (const id of ["q", "sev", "kev", "epss", "cwe", "sort"]) $(id).addEventListener("input", () => { page = 0; render(); });
$("prev").onclick = () => { page--; render(); };
$("next").onclick = () => { page++; render(); };

// ---- Subscribe form ----
let tsWidget = null;
async function initTurnstile() {
  const { turnstileSiteKey } = await (await fetch("/api/config")).json();
  const t0 = Date.now();
  const timer = setInterval(() => {
    if (window.turnstile) { clearInterval(timer); tsWidget = window.turnstile.render("#ts", { sitekey: turnstileSiteKey }); }
    else if (Date.now() - t0 > 10000) clearInterval(timer);
  }, 200);
}
const list = (s) => String(s || "").split(",").map((x) => x.trim()).filter(Boolean);

$("subform").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const msg = $("subMsg");
  msg.textContent = "Submitting…";
  const body = {
    email: f.get("email"),
    turnstile: window.turnstile && tsWidget !== null ? window.turnstile.getResponse(tsWidget) : "",
    filters: {
      minSeverity: f.get("minSeverity"), kevOnly: f.get("kevOnly") === "on", minEpss: Number(f.get("minEpss") || 0) / 100,
      vendors: list(f.get("vendors")), keywords: list(f.get("keywords")), cwes: list(f.get("cwes")),
    },
  };
  try {
    const r = await fetch("/api/subscribe", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const j = await r.json();
    msg.textContent = j.message || j.error || "Something went wrong.";
    if (j.ok) ev.target.reset();
  } catch { msg.textContent = "Network error. Please try again."; }
  if (window.turnstile && tsWidget !== null) window.turnstile.reset(tsWidget);
});

load();
initTurnstile();
