#!/usr/bin/env node
import { spawnSync } from "node:child_process";

const modes = new Set(["default", "--migration", "--faults"]);
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && !modes.has(args[0]))) {
  process.stderr.write("usage: node scripts/verify-checkpoint-proof-binding.mjs [default|--migration|--faults]\n");
  process.exit(2);
}
const requested = args[0] ?? "default";

const feature = (pkg, test, subtests = []) => ({ pkg, test, subtests });
const common = [
  feature("./internal/runtime", "TestCheckpointProofV2PositiveControl"),
  feature("./internal/runtime", "TestCheckpointProofV2CanonicalDigestAndMutations", [
    "proof_version", "model_alias", "local_binding", "durable_epoch",
  ]),
  feature("./internal/nodeagent", "TestApplyProductionCheckpointProofIsFailClosed"),
  feature("./internal/nodeagent", "TestPublicCheckpointProofReissuanceFailsBeforeFilesystemWrites"),
  feature("./internal/nodeagent", "TestCheckpointProofBindingRejectsMissingLocalAuthorityBeforeQuery"),
  feature("./internal/nodeagent", "TestGenerateProductionCheckpointProofManagedLifecycleAndDiscovery"),
  feature("./internal/nodeagent", "TestDiscoveryFailsClosedWithoutLocalBindingAcrossModelProfileContextAndRestart"),
  feature("./internal/api", "TestCheckpointProofAdmissionRequiresV2DigestAndDurableEpoch", [
    "positive_v2_control", "unknown_model_alias", "nonresident_model_alias", "ambiguous_resident_alias",
    "legacy_proof", "missing_durable_epoch", "positive_durable_epoch_control", "durable_epoch_replay",
  ]),
  feature("./internal/wsproto", "TestCheckpointProofV2WireSchemaAndMalformedMutants", [
    "duplicate", "alternate_case", "unknown", "missing", "null", "malformed_type", "malformed_epoch", "trailing_value",
  ]),
  feature("./internal/workloads", "TestProductionCheckpointOrderAndKVReuse"),
];
const migration = [
  feature("./internal/nodeagent", "TestCheckpointProofV1MigrationRequiresAuthenticatedPriorCASAndFreshV2Exercise"),
  feature("./internal/nodeagent", "TestDurableCheckpointProofIssuanceSurvivesRestartAndRejectsRollback"),
  feature("./internal/nodeagent", "TestDurableCheckpointProofEpochSurvivesWallClockRollback"),
  feature("./internal/nodeagent", "TestCheckpointProofSidecarCommitBeforeProofWriteRetainsEpoch"),
  feature("./internal/nodeagent", "TestDurableCheckpointProofRebindRequiresPriorCASAndAdvancedFence"),
  feature("./internal/nodeagent", "TestDurableCheckpointProofIssuanceSerializesConcurrentRefreshes"),
  feature("./internal/nodeagent", "TestDurableCheckpointProofIssuanceAcceptsFreshExerciseAfterExpiry"),
  feature("./internal/nodeagent", "TestDiscoveryRejectsPersistedProofAcrossSessionsWithoutLocalAuthority"),
  feature("./internal/nodeagent", "TestCheckpointIssuanceLockNeverStealsOldMtimeLock"),
  feature("./internal/nodeagent", "TestCheckpointIssuanceStateRejectsCorruptV2ReplayMaps", [
    "duplicate_top-level_key", "duplicate_counter_key", "null_high-water", "null_binding_map",
    "null_generation_map", "missing_exercise_map", "missing_target_generation", "missing_target_fence",
    "missing_target_exercise", "missing_target_issued_at", "extra_unbound_target",
    "alternate-case_field", "unknown_field", "trailing_value",
  ]),
  feature("./internal/nodeagent", "TestDurableCheckpointProofRebindRollbacksLeaveSidecarUnchanged", [
    "generation_rollback", "fence_rollback", "valid_fresh_rebind",
  ]),
  feature("./internal/nodeagent", "TestCheckpointProofV1MigrationRejectsUnmigratableOtherTarget", [
    "other_target_missing_safety_counters",
  ]),
  feature("./internal/nodeagent", "TestCheckpointIssuanceStatePreservesLegacyV1WithoutOptionalMaps"),
];
const faults = [
  feature("./internal/runtime", "TestCheckpointProofV2CanonicalDigestAndMutations", [
    "proof_version", "model_alias", "local_binding", "durable_epoch",
  ]),
  feature("./internal/nodeagent", "TestApplyProductionCheckpointProofIsFailClosed"),
  feature("./internal/nodeagent", "TestPublicCheckpointProofReissuanceFailsBeforeFilesystemWrites"),
  feature("./internal/nodeagent", "TestCheckpointProofBindingRejectsMissingLocalAuthorityBeforeQuery"),
  feature("./internal/nodeagent", "TestGenerateProductionCheckpointProofCleansEveryIntermediateFailure", [
    "assign", "start", "pause", "save", "stop_confirm", "release", "reload", "restore", "resume", "continue", "reuse_verify",
  ]),
  feature("./internal/nodeagent", "TestDiscoveryFailsClosedWithoutLocalBindingAcrossModelProfileContextAndRestart"),
  feature("./internal/api", "TestCheckpointProofAdmissionRequiresV2DigestAndDurableEpoch", [
    "positive_v2_control", "unknown_model_alias", "nonresident_model_alias", "ambiguous_resident_alias",
    "legacy_proof", "missing_durable_epoch", "positive_durable_epoch_control", "durable_epoch_replay",
  ]),
  feature("./internal/wsproto", "TestCheckpointProofV2WireSchemaAndMalformedMutants", [
    "duplicate", "alternate_case", "unknown", "missing", "null", "malformed_type", "malformed_epoch", "trailing_value",
  ]),
  feature("./internal/workloads", "TestCheckpointFaultMatrixEveryLifecycleBoundary", [
    "assign", "pause", "save", "stop", "release", "restore_reload", "restore_restore", "restore_reuse", "restore_resume",
  ]),
];

function groupByPackage(features) {
  const groups = new Map();
  for (const item of features) {
    if (!groups.has(item.pkg)) groups.set(item.pkg, []);
    groups.get(item.pkg).push(item);
  }
  return [...groups.entries()];
}

function eventInventoryFailures(events, features) {
  const failures = [];
  const expected = new Map();
  for (const item of features) {
    for (const path of [item.test, ...item.subtests.map((name) => `${item.test}/${name}`)]) {
      if (expected.has(path)) failures.push(`duplicate expected feature path: ${path}`);
      expected.set(path, { runs: 0, terminals: [] });
    }
  }
  const testEvents = events.filter((event) => event.Test && ["run", "pass", "skip", "fail"].includes(event.Action));
  for (const event of testEvents) {
    const record = expected.get(event.Test);
    if (!record) {
      failures.push(`unexpected test outcome event: ${event.Action} ${event.Test}`);
      continue;
    }
    if (event.Action === "run") record.runs++;
    else record.terminals.push(event.Action);
    if (event.Action === "skip") failures.push(`skipped test or subtest: ${event.Test}`);
    if (event.Action === "fail") failures.push(`failed test or subtest: ${event.Test}`);
  }
  for (const [path, record] of expected) {
    if (record.runs !== 1) failures.push(`${path} has ${record.runs} run events; want exactly one`);
    if (record.terminals.length !== 1) failures.push(`${path} has ${record.terminals.length} terminal outcomes; want exactly one`);
    else if (record.terminals[0] !== "pass") failures.push(`${path} ended with ${record.terminals[0]}`);
  }
  return failures;
}

function selfCheckEventOracle() {
  const featureSet = [feature("pkg", "TestControl", ["case_a", "case_b"])];
  const event = (Action, Test) => ({ Action, Test });
  const good = [
    event("run", "TestControl"), event("run", "TestControl/case_a"), event("pass", "TestControl/case_a"),
    event("run", "TestControl/case_b"), event("pass", "TestControl/case_b"), event("pass", "TestControl"),
  ];
  const cases = [
    ["positive event control", good, false],
    ["missing subtest control", good.filter((item) => item.Test !== "TestControl/case_b"), true],
    ["duplicate outcome control", [...good, event("pass", "TestControl/case_a")], true],
    ["skipped test control", good.map((item) => item.Test === "TestControl/case_b" && item.Action === "pass" ? event("skip", item.Test) : item), true],
    ["unexpected test control", [...good, event("run", "TestControl/unexpected")], true],
  ];
  for (const [name, events, shouldFail] of cases) {
    const failed = eventInventoryFailures(events, featureSet).length > 0;
    if (failed !== shouldFail) throw new Error(`verifier event-oracle self-check failed: ${name}`);
  }
}

function runGroup(pkg, features, report) {
  const tests = features.map((item) => item.test);
  const pattern = `^(${tests.join("|")})$`;
  const result = spawnSync("go", ["test", "-count=1", "-json", "-run", pattern, pkg], {
    cwd: process.cwd(),
    encoding: "utf8",
    timeout: 180_000,
    maxBuffer: 16 * 1024 * 1024,
    windowsHide: true,
  });
  const events = [];
  const parseFailures = [];
  for (const [index, line] of (result.stdout ?? "").split(/\r?\n/).entries()) {
    if (!line.trim()) continue;
    try {
      events.push(JSON.parse(line));
    } catch {
      parseFailures.push(`non-JSON go test output at line ${index + 1}`);
    }
  }
  const failures = [...parseFailures];
  if (result.error?.code === "ETIMEDOUT") failures.push("timeout");
  else if (result.error) failures.push(`go execution error: ${result.error.code ?? result.error.message}`);
  if (result.status !== 0) failures.push(`go test exit ${result.status ?? "unknown"}`);
  const output = `${result.stdout ?? ""}\n${result.stderr ?? ""}`;
  if (/panic:|fatal error:|\bFAIL\b/.test(output)) failures.push("panic or failing test output");
  for (const event of events) {
    if (event.Action === "fail" && !event.Test) failures.push(`package failure: ${event.Package ?? pkg}`);
  }
  failures.push(...eventInventoryFailures(events, features));
  const expectedPaths = features.flatMap((item) => [item.test, ...item.subtests.map((name) => `${item.test}/${name}`)]);
  for (const path of expectedPaths) {
    report.features.push({ package: pkg, test: path, action: failures.some((failure) => failure.startsWith(`${path} `) || failure.includes(` ${path}`)) ? "failed" : "pass" });
  }
  if (failures.length) report.failures.push({ package: pkg, failures: [...new Set(failures)] });
}

function run(features, report) {
  for (const [pkg, group] of groupByPackage(features)) runGroup(pkg, group, report);
}

selfCheckEventOracle();
const report = { mode: requested, status: "failed", features: [], failures: [] };
if (requested === "--faults") {
  // Establish a known-good proof first; malformed-proof mutants earn no credit
  // unless the positive control is observed exactly once and passes.
  run([feature("./internal/runtime", "TestCheckpointProofV2PositiveControl")], report);
  if (!report.failures.length) run(faults, report);
} else if (requested === "--migration") {
  run(migration, report);
} else {
  run(common, report);
}

if (!report.failures.length && report.features.every((item) => item.action === "pass")) report.status = "passed";
process.stdout.write(`${JSON.stringify(report)}\n`);
if (report.status !== "passed") process.exitCode = 1;
else {
  const success = requested === "--migration"
    ? "checkpoint proof migration verification passed"
    : requested === "--faults"
      ? "checkpoint proof binding fault verification passed"
      : "checkpoint proof binding verification passed";
  process.stdout.write(`${success}\n`);
}
