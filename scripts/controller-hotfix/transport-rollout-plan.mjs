import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import path from "node:path";

export const PIN = Object.freeze({
  candidate: "candidate-20261005061320-3038c0fb3451",
  manifestBytes: 773362,
  manifestSha256: "d94e61c723d62e6cdf675559298fb6dc3cf6311f7e24b28161f28f2c1ac53fe4",
  imageBytes: 12976280,
  imageSha256: "c50f1a7a53ffbca3aa7835786eb1bae67fddfe69260381cd77ec6e7780bdb543",
  originalBytes: 12976280,
  originalSha256: "ef99dfc0a0c1efa7b6386aefce8b0c12bd865c3f40abc90d55e124bd9b95dc4c",
  configBytes: 6789,
  configSha256: "0879fcd9d1852424970e235f2a6245664e46e8f58f438ea91eb7f6784781af37",
  fenceReceiverBytes: 35368,
  fenceReceiverSha256: "96e0c5afe0ba463fe42cbc2700a486322a02f844e8a3f4118ef2373a2e67d496",
});

export const PHASES = Object.freeze(["preflight", "original-active", "original-stopped", "candidate-active", "rollback-original-active", "settled"]);
const HASH = /^[a-f0-9]{64}$/;
function fail() { throw new Error("transport rollout plan rejected"); }
function exact(value, keys) { return value && typeof value === "object" && !Array.isArray(value) && Object.keys(value).sort().join("\0") === [...keys].sort().join("\0"); }

export function validatePreflight(value) {
  if (!exact(value, ["schema", "stage", "nonce", "candidate", "manifest_sha256", "image_sha256", "original_sha256", "config_sha256", "command", "native", "ct", "startup_admission_proven", "effects"]) || value.schema !== "controller-transport-preflight-v1" || value.stage !== "observed" || value.nonce !== "d771b06efb5715b296d04d891f3d854d" || value.startup_admission_proven !== false) fail();
  if (value.candidate !== PIN.candidate || value.manifest_sha256 !== PIN.manifestSha256 || value.image_sha256 !== PIN.imageSha256 || value.original_sha256 !== PIN.originalSha256 || value.config_sha256 !== PIN.configSha256) fail();
  if (!exact(value.command, ["total", "terminal", "expired", "nonterminal", "uncertain", "malformed", "expired_rows", "cache_matched_pairs", "cache_unknown", "transport_only_candidate", "command_clear"])) fail();
  const c = value.command;
  if (![c.total,c.terminal,c.expired,c.nonterminal,c.uncertain,c.malformed,c.expired_rows,c.cache_matched_pairs,c.cache_unknown].every(n => Number.isSafeInteger(n) && n >= 0 && n <= 1000000000) || c.terminal + c.nonterminal !== c.total || c.expired !== c.expired_rows || c.cache_matched_pairs > c.expired_rows || c.cache_unknown > c.expired_rows || c.command_clear !== false || c.transport_only_candidate !== (c.total === c.terminal && c.nonterminal === 0 && c.uncertain === 0 && c.malformed === 0 && c.expired_rows === c.cache_matched_pairs + c.cache_unknown && c.cache_unknown === 0)) fail();
  if (!exact(value.native, ["leaf14_within_probe_unchanged", "cross_operation_identity_joined"]) || value.native.leaf14_within_probe_unchanged !== true || value.native.cross_operation_identity_joined !== true) fail();
  if (!exact(value.ct, ["agent_within_probe_unchanged", "cross_operation_identity_joined"]) || value.ct.agent_within_probe_unchanged !== true || value.ct.cross_operation_identity_joined !== true) fail();
  if (!exact(value.effects, ["controller_stop", "image_write", "controller_start", "history_write", "native_action"]) || Object.values(value.effects).some(v => v !== false)) fail();
  return Object.freeze(value);
}

export function transition(state, event) {
  const next = {
    "preflight:accept": "original-active",
    "original-active:stop-verified": "original-stopped",
    "original-stopped:install-verified": "original-stopped",
    "original-stopped:start-candidate-verified": "candidate-active",
    "candidate-active:accept": "settled",
    "original-stopped:rollback-started": "rollback-original-active",
    "candidate-active:rollback-started": "rollback-original-active",
    "rollback-original-active:original-verified": "settled",
  }[`${state}:${event}`];
  if (!next || !PHASES.includes(state) || !PHASES.includes(next)) fail();
  return next;
}

export function validateBudgets(value) {
  if (!exact(value, ["sessionMs", "stopMs", "installMs", "startMs", "healthMs", "protectedMs", "rollbackReserveMs", "cleanupMs"])) fail();
  const forward = 2 * value.stopMs + value.installMs + value.startMs + value.healthMs + 2 * value.protectedMs;
  const rollback = 2 * value.stopMs + value.installMs + value.startMs + value.healthMs + value.protectedMs + value.cleanupMs;
  if (Object.values(value).some(n => !Number.isSafeInteger(n) || n <= 0) || value.sessionMs > 180000 || value.stopMs > 20000 || value.installMs > 30000 || value.startMs > 20000 || value.healthMs > 30000 || value.protectedMs > 30000 || value.rollbackReserveMs < rollback || value.cleanupMs > 10000 || forward + value.rollbackReserveMs + value.cleanupMs > value.sessionMs) fail();
  return Object.freeze(value);
}

export function validateCli(args) {
  if (args.length === 1 && args[0] === "--preflight") return "preflight";
  if (args.length === 1 && args[0] === "--apply") return "apply";
  fail();
}

export function _planPinForTest(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
export function _planPathForTest() { return path.basename(fileURLToPath(import.meta.url)); }
