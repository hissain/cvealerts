// Incremental CVE ingest: NVD 2.0 (delta by lastModified) + CISA KEV + FIRST EPSS -> site/data/cves.json
// Env: NVD_API_KEY (optional but recommended), RETENTION_DAYS (default 10), BOOTSTRAP_DAYS (default 14)
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { gunzipSync } from "node:zlib";
import { sleep, SEV_RANK } from "./lib.mjs";

const NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0";
const KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz";
const DATA = new URL("../site/data/", import.meta.url);
const KEY = process.env.NVD_API_KEY || "";
const RETENTION_DAYS = Number(process.env.RETENTION_DAYS || 10);
const BOOTSTRAP_DAYS = Number(process.env.BOOTSTRAP_DAYS || 14);
const MAX_CVES = 6000;
const GAP_MS = KEY ? 700 : 6500; // stay under 50/30s with key, 5/30s without

const readJson = async (u, fallback) => { try { return JSON.parse(await readFile(u, "utf8")); } catch { return fallback; } };

async function nvdGet(params, attempt = 0) {
  const url = `${NVD}?${new URLSearchParams(params)}`;
  const r = await fetch(url, { headers: KEY ? { apiKey: KEY } : {} });
  if ((r.status === 429 || r.status >= 500) && attempt < 5) {
    await sleep(GAP_MS * 2 ** (attempt + 1));
    return nvdGet(params, attempt + 1);
  }
  if (!r.ok) throw new Error(`NVD ${r.status} for ${url}`);
  await sleep(GAP_MS);
  return r.json();
}

function pickCvss(metrics = {}) {
  for (const k of ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]) {
    const m = metrics[k]?.[0];
    if (m) return { score: m.cvssData.baseScore, severity: (m.cvssData.baseSeverity || m.baseSeverity || "UNKNOWN").toUpperCase(), version: k.replace("cvssMetric", "") };
  }
  return { score: null, severity: "UNKNOWN", version: null };
}

function normalize(c) {
  const cvss = pickCvss(c.metrics);
  const vendors = new Set(), products = new Set();
  for (const cfg of c.configurations || []) for (const node of cfg.nodes || []) for (const m of node.cpeMatch || []) {
    const p = (m.criteria || "").split(":"); // cpe:2.3:part:vendor:product:...
    if (p.length > 4) { vendors.add(p[3].toLowerCase()); products.add(p[4].toLowerCase()); }
  }
  const cwes = [...new Set((c.weaknesses || []).flatMap((w) => w.description.map((d) => d.value)).filter((v) => /^CWE-\d+$/.test(v)))];
  return {
    id: c.id,
    published: c.published,
    modified: c.lastModified,
    status: c.vulnStatus,
    desc: (c.descriptions || []).find((d) => d.lang === "en")?.value || "",
    score: cvss.score, severity: cvss.severity, cvssVersion: cvss.version,
    cwes, vendors: [...vendors].slice(0, 30), products: [...products].slice(0, 30),
    refs: (c.references || []).slice(0, 5).map((r) => r.url),
    kev: false, epss: null,
  };
}

async function fetchWindow(start, end) {
  const out = [];
  let startIndex = 0;
  for (;;) {
    const j = await nvdGet({ lastModStartDate: start.toISOString(), lastModEndDate: end.toISOString(), resultsPerPage: "2000", startIndex: String(startIndex) });
    out.push(...j.vulnerabilities.map((v) => normalize(v.cve)));
    startIndex += j.resultsPerPage;
    console.log(`NVD ${Math.min(startIndex, j.totalResults)}/${j.totalResults}`);
    if (startIndex >= j.totalResults) break;
  }
  return out;
}

async function loadKev() {
  const r = await fetch(KEV_URL);
  if (!r.ok) throw new Error(`KEV ${r.status}`);
  const j = await r.json();
  return new Map(j.vulnerabilities.map((v) => [v.cveID, { added: v.dateAdded, due: v.dueDate, ransomware: v.knownRansomwareCampaignUse === "Known" }]));
}

async function loadEpss(wanted) {
  const r = await fetch(EPSS_URL);
  if (!r.ok) throw new Error(`EPSS ${r.status}`);
  const lines = gunzipSync(Buffer.from(await r.arrayBuffer())).toString("utf8").split("\n");
  const map = new Map();
  for (const line of lines) {
    if (!line.startsWith("CVE-")) continue; // skips "#model_version" comment and header
    const [id, epss, pct] = line.split(",");
    if (wanted.has(id)) map.set(id, { epss: Number(epss), pct: Number(pct) });
  }
  return map;
}

async function main() {
  await mkdir(DATA, { recursive: true });
  const state = await readJson(new URL("state.json", DATA), {});
  const store = await readJson(new URL("cves.json", DATA), { cves: [] });
  const byId = new Map(store.cves.map((c) => [c.id, c]));
  const nowDate = new Date();
  const nowSec = Math.floor(nowDate.getTime() / 1000);

  let start = state.lastSync ? new Date(new Date(state.lastSync).getTime() - 5 * 60e3) : new Date(nowDate.getTime() - BOOTSTRAP_DAYS * 864e5);
  const maxSpan = 119 * 864e5; // NVD rejects ranges over 120 days
  if (nowDate - start > maxSpan) { console.warn("Last sync older than 119 days; clamping window (data gap)."); start = new Date(nowDate - maxSpan); }

  console.log(`NVD window ${start.toISOString()} -> ${nowDate.toISOString()} (key: ${KEY ? "yes" : "no"})`);
  const cutoff = nowDate.getTime() - RETENTION_DAYS * 864e5;
  for (const c of await fetchWindow(start, nowDate)) {
    if (/reject/i.test(c.status || "") || /^\*\* REJECT \*\*/.test(c.desc)) { byId.delete(c.id); continue; }
    const old = byId.get(c.id);
    if (!old && new Date(c.published).getTime() < cutoff) continue; // old CVE that was merely re-analysed
    byId.set(c.id, { ...c, firstSeen: old?.firstSeen ?? nowSec });
  }

  const kev = await loadKev();
  // Pull in recently KEV-listed CVEs that fell outside the window (usually older CVEs)
  const recent = [...kev].filter(([id, k]) => !byId.has(id) && new Date(k.added).getTime() > nowDate.getTime() - 14 * 864e5).slice(0, 20);
  for (const [id] of recent) {
    const j = await nvdGet({ cveId: id });
    if (j.vulnerabilities[0]) byId.set(id, { ...normalize(j.vulnerabilities[0].cve), firstSeen: nowSec });
  }
  for (const c of byId.values()) {
    const k = kev.get(c.id);
    c.kev = !!k; c.kevAdded = k?.added ?? null; c.kevDue = k?.due ?? null; c.ransomware = k?.ransomware ?? false;
  }

  const epss = await loadEpss(new Set(byId.keys()));
  for (const c of byId.values()) { const e = epss.get(c.id); if (e) { c.epss = e.epss; c.epssPct = e.pct; } }

  const keep = [...byId.values()]
    .filter((c) => c.kev || new Date(c.published).getTime() >= cutoff)
    // If over the cap, drop the least important first: KEV, then higher severity, then newer.
    .sort((a, b) => (b.kev - a.kev) || ((SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0)) || b.published.localeCompare(a.published))
    .slice(0, MAX_CVES)
    .sort((a, b) => b.published.localeCompare(a.published));

  await writeFile(new URL("cves.json", DATA), JSON.stringify({ generated: nowDate.toISOString(), count: keep.length, cves: keep }));
  await writeFile(new URL("state.json", DATA), JSON.stringify({ lastSync: nowDate.toISOString() }));
  console.log(`Saved ${keep.length} CVEs`);
}

main().catch((e) => { console.error(e); process.exit(1); });
