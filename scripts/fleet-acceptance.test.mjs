import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import {
  MANAGED_PROTOCOL,
  REQUIRED_SCENARIO_CLASSES,
  npmInvocation,
  preflight,
  runChecked,
  runManifest,
  sanitizeEvidence,
  stableStringify,
  validateIntegration,
  validateManifest,
} from "./fleet-acceptance.mjs";

const examplePath = resolve(import.meta.dirname, "../configs/fleet-acceptance.example.json");
const example = () => JSON.parse(readFileSync(examplePath, "utf8"));

function withCredentialEnvironment(manifest, callback) {
  const previous = new Map();
  for (const variable of Object.values(manifest.credentials)) {
    previous.set(variable, process.env[variable]);
    process.env[variable] = `test-value-for-${variable}`;
  }
  return Promise.resolve(callback()).finally(() => {
    for (const [variable, value] of previous) {
      if (value === undefined) delete process.env[variable]; else process.env[variable] = value;
    }
  });
}

function response(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

async function testManifest() {
  const manifest = example();
  validateManifest(manifest);
  assert.deepEqual(new Set(manifest.scenarios.map((row) => row.class)), new Set(REQUIRED_SCENARIO_CLASSES));
  const embedded = structuredClone(manifest);
  embedded.scenarios[0].steps[0].body.api_token = "should-never-be-here";
  assert.throws(() => validateManifest(embedded), /credential material/);
  const incomplete = structuredClone(manifest);
  incomplete.scenarios.pop();
  assert.throws(() => validateManifest(incomplete), /missing scenario class/);
	const exfiltration = structuredClone(manifest);
	exfiltration.scenarios[0].steps[0].path = "//attacker.invalid/collect";
	assert.throws(() => validateManifest(exfiltration), /controller-relative/);
  console.log("fleet manifest verification passed");
}

async function testRunner() {
  const manifest = example();
  manifest.scenarios = manifest.scenarios.map((scenario, index) => index === 0 ? {
    ...scenario,
    enabled: true,
    steps: [
      { action: "request", method: "POST", path: "/api/v1/workloads", credential: "workflow", save_as: "submitted", body: { workload_type: "llm.inference" } },
      { action: "wait_workload", from: "submitted", credential: "workflow", timeout_seconds: 1, poll_milliseconds: 1, save_as: "finished" },
      { action: "assert", from: "finished", path: "workload.status", operator: "equals", value: "completed" },
      { action: "assert", from: "finished", path: "workload.plan.target_id", operator: "equals", value: "cmp170-llm" },
    ],
  } : { ...scenario, enabled: false });
  let polls = 0;
  await withCredentialEnvironment(manifest, async () => {
    const evidence = await runManifest(manifest, {
		allowDisabled: true,
      now: () => "2026-09-03T00:00:00.000Z",
      sleep: async () => {},
      fetchImpl: async (url, options) => {
        assert.match(options.headers.Authorization, /^Bearer test-value-for-/);
        if (options.method === "POST") return response({ workload: { request: { id: "wl-1" }, status: "queued" }, authorization: "must-be-redacted" });
        polls++;
        return response({ workload: { request: { id: "wl-1" }, status: polls > 1 ? "completed" : "running", plan: { target_id: "cmp170-llm" } }, token: "must-be-redacted" });
      },
    });
    assert.equal(evidence.scenarios[0].status, "passed");
    assert.equal(evidence.scenarios[0].assertions, 2);
    assert.ok(!stableStringify(evidence).includes("must-be-redacted"));

    const broken = structuredClone(manifest);
    broken.scenarios[0].steps.at(-1).value = "rtx3090-llm";
		await assert.rejects(() => runManifest(broken, { allowDisabled: true, sleep: async () => {}, fetchImpl: async (_url, options) => options.method === "POST" ? response({ workload: { request: { id: "wl-1" } } }) : response({ workload: { status: "completed", plan: { target_id: "cmp170-llm" } } }) }), /scenario .* failed/);
		const disabled = structuredClone(manifest);
		disabled.scenarios = disabled.scenarios.map((scenario) => ({ ...scenario, enabled: false }));
		await assert.rejects(() => runManifest(disabled, { sleep: async () => {}, fetchImpl: async () => response({}) }), /live acceptance incomplete/);
  });
  console.log("fleet runner verification passed");
}

async function testPreflight() {
  const manifest = example();
  await withCredentialEnvironment(manifest, async () => {
    const calls = [];
    const evidence = await preflight(manifest, { fetchImpl: async (url, options) => {
      calls.push({ path: new URL(url).pathname, method: options.method });
      if (new URL(url).pathname.endsWith("health")) return response({ status: "ok" });
      return response({
        nodes: manifest.expected_inventory.node_ids.map((id, index) => ({ id, accelerators: [{ id: manifest.expected_inventory.accelerator_ids[index] }] })),
        targets: manifest.expected_inventory.target_ids.map((id) => ({ id })),
      });
    } });
    assert.ok(calls.length === 2 && calls.every((call) => call.method === "GET"), `preflight mutated state: ${JSON.stringify(calls)}`);
    assert.equal(evidence.health.status, "ok");
  });
  console.log("fleet preflight verification passed");
}

async function testIntegration() {
  validateIntegration(examplePath, resolve(import.meta.dirname, "../configs/fleet"), resolve(import.meta.dirname, "../docs/fleet-rollout-and-acceptance.md"));
  const adapter = readFileSync(resolve(import.meta.dirname, "../internal/workloads/managed_comfy.go"), "utf8");
  assert.ok(adapter.includes(MANAGED_PROTOCOL));
  console.log("fleet integration verification passed");
}

async function testEvidence() {
  const first = stableStringify(sanitizeEvidence({ z: 1, token: "secret", a: { password: "secret", value: 2 } }));
  const second = stableStringify(sanitizeEvidence({ a: { value: 2, password: "other" }, token: "other", z: 1 }));
  assert.equal(first, second);
  assert.ok(!first.includes("secret") && !first.includes("password") && !first.includes("token"));
  const incomplete = example();
  incomplete.scenarios = incomplete.scenarios.filter((row) => row.class !== REQUIRED_SCENARIO_CLASSES[0]);
  assert.throws(() => validateManifest(incomplete), /missing scenario class/);
  console.log("fleet evidence verification passed");
}

async function testNpmInvocation() {
  assert.deepEqual(npmInvocation({ platform: "linux", execPath: "/opt/node/bin/node" }), { command: "npm", args: [] });
  const expectedCLI = resolve(dirname(process.execPath), "node_modules", "npm", "bin", "npm-cli.js");
  const windows = npmInvocation({ platform: "win32", execPath: process.execPath, fileExists: (candidate) => candidate === expectedCLI });
  assert.deepEqual(windows, { command: process.execPath, args: [expectedCLI] });
  assert.throws(() => npmInvocation({ platform: "win32", execPath: process.execPath, fileExists: () => false }), /npm CLI is unavailable/);
  assert.throws(() => runChecked(resolve(".missing-fleet-acceptance-command"), [], process.cwd()), /spawn error:/);
  console.log("fleet npm invocation verification passed");
}

const selected = process.argv[2];
const tests = { manifest: testManifest, runner: testRunner, preflight: testPreflight, integration: testIntegration, evidence: testEvidence, npm: testNpmInvocation };
if (!tests[selected]) {
  process.stderr.write("usage: fleet-acceptance.test.mjs <manifest|runner|preflight|integration|evidence|npm>\n");
  process.exitCode = 2;
} else {
  tests[selected]().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
  });
}
