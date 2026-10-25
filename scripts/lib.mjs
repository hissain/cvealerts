// Shared helpers for ingest + digest.
import { createHmac } from "node:crypto";

export const SEV_RANK = { NONE: 0, UNKNOWN: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
export const MIN_RANK = { ALL: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

export function unsubToken(secret, id) {
  return createHmac("sha256", secret).update(`unsub:${id}`).digest("hex");
}

/** Does a CVE record match a subscriber row (as stored in D1)? */
export function matches(cve, sub) {
  if ((SEV_RANK[cve.severity] ?? 0) < (MIN_RANK[sub.min_severity] ?? 3)) return false;
  if (sub.kev_only && !cve.kev) return false;
  if ((cve.epss ?? 0) < (sub.min_epss || 0)) return false;
  const vendors = JSON.parse(sub.vendors || "[]");
  if (vendors.length && !vendors.some((v) => cve.vendors.includes(v) || cve.products.includes(v))) return false;
  const cwes = JSON.parse(sub.cwes || "[]");
  if (cwes.length && !cwes.some((c) => cve.cwes.includes(c))) return false;
  const kws = JSON.parse(sub.keywords || "[]");
  if (kws.length) {
    const hay = `${cve.id} ${cve.desc}`.toLowerCase();
    if (!kws.some((k) => hay.includes(k))) return false;
  }
  return true;
}
