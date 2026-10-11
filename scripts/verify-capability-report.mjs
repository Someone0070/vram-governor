import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

const root = resolve(import.meta.dirname, "..");
const reportPath = resolve(root, "docs/current-capabilities-report-2026-08-31.md");
const report = readFileSync(reportPath, "utf8");
const httpRoutes = readFileSync(resolve(root, "internal/api/http.go"), "utf8");

function includesAll(label, values) {
  for (const value of values) {
    assert.ok(report.includes(value), `${label}: report is missing ${JSON.stringify(value)}`);
  }
}

function includesAllCaseInsensitive(label, values) {
  const normalized = report.toLowerCase();
  for (const value of values) {
    assert.ok(normalized.includes(value.toLowerCase()), `${label}: report is missing ${JSON.stringify(value)}`);
  }
}

assert.ok(report.length > 12_000, "report is unexpectedly short");
includesAll("report identity", [
  "# VRAM Governor capability report",
  "2026-08-31",
  "Historical evidence notice",
  "dedicated machine",
  "WSL is not required",
  "Production release gate: NOT READY",
  "## Bottom line",
]);

includesAll("status vocabulary", [
  "Live-proven",
  "Implemented/tested",
  "Simulated only",
  "Partial",
  "Unavailable",
]);

includesAllCaseInsensitive("capability domains", [
  "## Historical live deployment snapshot",
  "## Scheduler behavior",
  "## Model lifecycle and memory tiers",
  "## Protocol and API surface",
  "## Durability and recovery",
  "## Security and control boundaries",
  "## Telemetry and operator experience",
  "## System-agent plane",
  "## Known gaps and recommended completion order",
  "Same model with different context and slots",
  "checkpoint/yield/resume",
  "automated remediation",
  "is not implemented",
  "one active controller",
]);

includesAllCaseInsensitive("honest integration status", [
  "OpenRouter",
  "Not configured and not live-proven",
  "S3-compatible artifacts",
  "No real S3-compatible endpoint has been accepted",
  "No live webhook destination has been accepted",
  "complete visual browser acceptance is outstanding",
]);

const publicRoutes = [
  "/v1/chat/completions",
  "/prompt",
  "/api/v1/workloads",
  "/api/agent/v1/incidents",
  "/admin/api/overview",
  "/ws/node",
];
for (const route of publicRoutes) {
  assert.ok(httpRoutes.includes(route), `route disappeared from internal/api/http.go: ${route}`);
  assert.ok(report.includes(route), `report is missing current public route: ${route}`);
}

const migrations = readdirSync(resolve(root, "migrations"))
  .filter((name) => /^\d{4}_.+\.sql$/.test(name))
  .sort();
assert.equal(migrations.length, 20, "migration count changed; update and re-audit the report");
assert.ok(migrations[0].startsWith("0001_"), "first migration is no longer 0001");
assert.equal(migrations.at(-1), "0020_accelerator_lease_cleanup.sql", "latest migration is not the accelerator lease cleanup migration");
const workloadRevisionMigration = readFileSync(resolve(root, "migrations", "0018_workload_revision.sql"), "utf8");
for (const phrase of ["BEGIN;", "jsonb_set", "budget_reservation_token", "COMMIT;"]) {
  assert.ok(workloadRevisionMigration.includes(phrase), `0018 workload revision migration is missing ${phrase}`);
}
assert.ok(report.includes("PostgreSQL migrations"), "report migration statement is missing");
includesAll("migration history honesty", [
  "Twenty ordered PostgreSQL migrations (`0001` through `0020`)",
  "Migrations `0016` through `0020`",
  "not claimed as applied in that historical live run",
]);

const privateIPv4 = /\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b/;
assert.ok(privateIPv4.test("renderer 10.0.0.246"), "private-address negative control is broken");
assert.ok(!privateIPv4.test(report), "report contains a private host address");

assert.ok(!/\b(?:TODO|TBD)\b/.test(report), "report contains unfinished placeholder language");
assert.ok(
  !/(?:api[_-]?key|authorization|password|token)\s*[:=]\s*["']?[A-Za-z0-9_\-]{12,}/i.test(report),
  "report may contain credential material",
);

console.log("capability report verification passed");
