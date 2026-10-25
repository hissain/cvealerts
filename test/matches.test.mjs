import test from "node:test";
import assert from "node:assert/strict";
import { matches, unsubToken } from "../scripts/lib.mjs";

const cve = (o = {}) => ({ id: "CVE-2026-0001", desc: "Remote code execution in Apache Foo", severity: "HIGH", score: 8.1, kev: false, epss: 0.1,
  vendors: ["apache"], products: ["foo"], cwes: ["CWE-79"], ...o });
const sub = (o = {}) => ({ min_severity: "HIGH", kev_only: 0, min_epss: 0, vendors: "[]", keywords: "[]", cwes: "[]", ...o });

test("severity threshold", () => {
  assert.ok(matches(cve(), sub()));
  assert.ok(!matches(cve({ severity: "MEDIUM" }), sub()));
  assert.ok(matches(cve({ severity: "MEDIUM" }), sub({ min_severity: "MEDIUM" })));
  assert.ok(!matches(cve({ severity: "HIGH" }), sub({ min_severity: "CRITICAL" })));
  assert.ok(matches(cve({ severity: "UNKNOWN" }), sub({ min_severity: "ALL" })));
  assert.ok(!matches(cve({ severity: "UNKNOWN" }), sub({ min_severity: "LOW" })));
});

test("KEV and EPSS filters", () => {
  assert.ok(!matches(cve(), sub({ kev_only: 1 })));
  assert.ok(matches(cve({ kev: true }), sub({ kev_only: 1 })));
  assert.ok(!matches(cve({ epss: 0.1 }), sub({ min_epss: 0.5 })));
  assert.ok(matches(cve({ epss: 0.6 }), sub({ min_epss: 0.5 })));
  assert.ok(!matches(cve({ epss: null }), sub({ min_epss: 0.5 })));
});

test("vendor, cwe and keyword filters", () => {
  assert.ok(matches(cve(), sub({ vendors: '["apache"]' })));
  assert.ok(matches(cve(), sub({ vendors: '["foo"]' })));
  assert.ok(!matches(cve(), sub({ vendors: '["microsoft"]' })));
  assert.ok(matches(cve(), sub({ cwes: '["CWE-79","CWE-89"]' })));
  assert.ok(!matches(cve(), sub({ cwes: '["CWE-89"]' })));
  assert.ok(matches(cve(), sub({ keywords: '["remote code"]' })));
  assert.ok(!matches(cve(), sub({ keywords: '["sql injection"]' })));
});

test("unsubscribe token is deterministic, secret- and id-specific", () => {
  assert.equal(unsubToken("s", 1), unsubToken("s", 1));
  assert.notEqual(unsubToken("s", 1), unsubToken("s", 2));
  assert.notEqual(unsubToken("s", 1), unsubToken("t", 1));
  // must equal the Worker's HMAC output (checked against the local wrangler run)
  assert.equal(unsubToken("local-dev-unsub-secret-change-me-0123456789", 1), "149648b154e3db50e4d2ed5c989cb8b44427560fcf804e909dd5eba2663b2984");
});
