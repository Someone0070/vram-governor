import assert from "node:assert/strict";
import { existsSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import { basename, dirname, relative, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { spawnSync } from "node:child_process";

export const MANIFEST_VERSION = "fleet-acceptance/v1";
export const MANAGED_PROTOCOL = "managed_comfy_v1";
export const REQUIRED_SCENARIO_CLASSES = [
  "urgent_small_on_busy_cmp",
  "locked_video_refusal",
  "cmp_only_20b_wait",
  "sharing_guardrail_rollback",
  "node_reconnect",
  "controller_restart_fencing",
  "agent_escalation",
  "openrouter_fallback",
  "artifact_webhook_recovery",
];

const terminalStatuses = new Set(["completed", "succeeded", "failed", "cancelled", "rejected", "blocked"]);
const allowedActions = new Set(["request", "wait_workload", "assert", "sleep"]);
const secretKey = /(?:authorization|api[_-]?key|password|secret|token)$/i;
const envName = /^[A-Z][A-Z0-9_]*$/;

function object(value, label) {
  assert.ok(value && typeof value === "object" && !Array.isArray(value), `${label} must be an object`);
  return value;
}

function nonempty(value, label) {
  assert.equal(typeof value, "string", `${label} must be a string`);
  assert.ok(value.trim(), `${label} must not be empty`);
  return value;
}

export function validateManifest(manifest) {
  object(manifest, "manifest");
  assert.equal(manifest.version, MANIFEST_VERSION, `version must be ${MANIFEST_VERSION}`);
  const controller = object(manifest.controller, "controller");
  const base = new URL(nonempty(controller.base_url, "controller.base_url"));
  assert.ok(base.protocol === "http:" || base.protocol === "https:", "controller.base_url must use HTTP or HTTPS");
	assert.ok(!base.username && !base.password, "controller.base_url must not contain credentials");
	const loopback = base.hostname === "localhost" || base.hostname === "127.0.0.1" || base.hostname === "[::1]";
	assert.ok(base.protocol === "https:" || loopback, "non-loopback controller.base_url must use HTTPS");
  const credentials = object(manifest.credentials, "credentials");
  assert.ok(Object.keys(credentials).length > 0, "at least one credential role is required");
  for (const [role, variable] of Object.entries(credentials)) {
    nonempty(role, "credential role");
    assert.ok(envName.test(variable), `credential ${role} must name an environment variable`);
  }
  rejectEmbeddedSecrets(manifest, "manifest");

  const expected = object(manifest.expected_inventory, "expected_inventory");
  for (const field of ["node_ids", "accelerator_ids", "target_ids"]) {
    assert.ok(Array.isArray(expected[field]) && expected[field].length > 0, `expected_inventory.${field} must be a non-empty array`);
    assert.equal(new Set(expected[field]).size, expected[field].length, `expected_inventory.${field} contains duplicates`);
    expected[field].forEach((value, index) => nonempty(value, `expected_inventory.${field}[${index}]`));
  }

  assert.ok(Array.isArray(manifest.scenarios), "scenarios must be an array");
  const ids = new Set();
  const classes = new Set();
  for (const scenario of manifest.scenarios) {
    object(scenario, "scenario");
    nonempty(scenario.id, "scenario.id");
    nonempty(scenario.class, `scenario ${scenario.id}.class`);
    assert.ok(!ids.has(scenario.id), `duplicate scenario id ${scenario.id}`);
    ids.add(scenario.id);
    classes.add(scenario.class);
    assert.ok(Array.isArray(scenario.preconditions) && scenario.preconditions.length > 0, `scenario ${scenario.id} must state physical preconditions`);
    assert.ok(Array.isArray(scenario.steps) && scenario.steps.length > 0, `scenario ${scenario.id} must contain steps`);
    for (const [index, step] of scenario.steps.entries()) {
      object(step, `scenario ${scenario.id} step ${index}`);
      assert.ok(allowedActions.has(step.action), `scenario ${scenario.id} has unsupported action ${step.action}`);
      if (step.action === "request") {
        nonempty(step.save_as, `scenario ${scenario.id} request save_as`);
        nonempty(step.method, `scenario ${scenario.id} request method`);
        nonempty(step.path, `scenario ${scenario.id} request path`);
		assert.ok(["GET", "POST"].includes(step.method.toUpperCase()), `scenario ${scenario.id} request method must be GET or POST`);
		assert.ok(step.path.startsWith("/") && !step.path.startsWith("//"), `scenario ${scenario.id} request path must be controller-relative`);
        assert.ok(credentials[step.credential], `scenario ${scenario.id} references unknown credential role ${step.credential}`);
      }
      if (step.action === "wait_workload") {
        nonempty(step.from, `scenario ${scenario.id} wait_workload.from`);
        assert.ok(Number.isFinite(step.timeout_seconds) && step.timeout_seconds > 0 && step.timeout_seconds <= 86400, `scenario ${scenario.id} wait timeout is invalid`);
      }
      if (step.action === "assert") {
        nonempty(step.from, `scenario ${scenario.id} assertion.from`);
        nonempty(step.path, `scenario ${scenario.id} assertion.path`);
        assert.ok(["equals", "includes", "one_of", "exists"].includes(step.operator), `scenario ${scenario.id} assertion operator is invalid`);
      }
      if (step.action === "sleep") {
        assert.ok(Number.isFinite(step.milliseconds) && step.milliseconds >= 0 && step.milliseconds <= 30000, `scenario ${scenario.id} sleep is invalid`);
      }
    }
  }
  for (const required of REQUIRED_SCENARIO_CLASSES) {
    assert.ok(classes.has(required), `acceptance matrix is missing scenario class ${required}`);
  }
  return manifest;
}

function rejectEmbeddedSecrets(value, location) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => rejectEmbeddedSecrets(item, `${location}[${index}]`));
    return;
  }
  if (!value || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value)) {
    if (secretKey.test(key) && typeof child === "string" && child.trim()) {
      throw new Error(`${location}.${key} contains credential material; use credentials environment-variable mappings`);
    }
    rejectEmbeddedSecrets(child, `${location}.${key}`);
  }
}

export function sanitizeEvidence(value) {
  if (Array.isArray(value)) return value.map(sanitizeEvidence);
  if (!value || typeof value !== "object") return value;
  const result = {};
  for (const key of Object.keys(value).sort()) {
    if (secretKey.test(key) || key.toLowerCase() === "headers") continue;
    result[key] = sanitizeEvidence(value[key]);
  }
  return result;
}

export function stableStringify(value) {
  return JSON.stringify(sanitizeEvidence(value), null, 2) + "\n";
}

function resolveTemplate(value, aliases) {
  if (Array.isArray(value)) return value.map((item) => resolveTemplate(item, aliases));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([key, child]) => [key, resolveTemplate(child, aliases)]));
  if (typeof value !== "string") return value;
  return value.replace(/\{\{([^}]+)}}/g, (_, expression) => {
    const resolved = getPath(aliases, expression.trim());
    assert.ok(resolved !== undefined && resolved !== null, `template value ${expression} is unavailable`);
    return String(resolved);
  });
}

export function getPath(value, path) {
  if (!path) return value;
  return path.split(".").reduce((current, part) => current == null ? undefined : current[part], value);
}

function assertValue(actual, step) {
  switch (step.operator) {
    case "equals": assert.deepEqual(actual, step.value); break;
    case "includes":
      assert.ok(typeof actual === "string" || Array.isArray(actual), `assertion ${step.path} is not includable`);
      assert.ok(actual.includes(step.value), `assertion ${step.path} does not include ${JSON.stringify(step.value)}`);
      break;
    case "one_of": assert.ok(Array.isArray(step.value) && step.value.includes(actual), `assertion ${step.path} value ${JSON.stringify(actual)} is not allowed`); break;
    case "exists": assert.ok(actual !== undefined && actual !== null, `assertion ${step.path} does not exist`); break;
    default: throw new Error(`unsupported assertion operator ${step.operator}`);
  }
}

async function httpJSON(fetchImpl, baseURL, credentials, step) {
  const variable = credentials[step.credential];
  const token = process.env[variable];
  assert.ok(token, `required credential environment variable ${variable} is unset`);
  const method = step.method.toUpperCase();
	assert.ok(step.path.startsWith("/") && !step.path.startsWith("//"), "request path must be controller-relative");
	const base = new URL(baseURL);
	const destination = new URL(step.path, base);
	assert.equal(destination.origin, base.origin, "request path escaped the configured controller origin");
	const options = { method, headers: { Accept: "application/json", Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout((step.request_timeout_seconds || 30) * 1000) };
  if (step.body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(step.body);
  }
	const response = await fetchImpl(destination, options);
  const text = await response.text();
  let body;
  try { body = text ? JSON.parse(text) : {}; } catch { throw new Error(`${method} ${step.path} returned non-JSON status ${response.status}`); }
  if (!response.ok) throw new Error(`${method} ${step.path} returned ${response.status}`);
  return body;
}

export async function preflight(manifest, options = {}) {
  validateManifest(manifest);
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  assert.equal(typeof fetchImpl, "function", "fetch is unavailable");
  const baseURL = manifest.controller.base_url;
  const health = await httpJSON(fetchImpl, baseURL, manifest.credentials, { method: "GET", path: "/api/v1/health", credential: "admin" });
  const overview = await httpJSON(fetchImpl, baseURL, manifest.credentials, { method: "GET", path: "/admin/api/overview", credential: "admin" });
  const nodes = new Set((overview.nodes || []).map((row) => row.id));
  const accelerators = new Set((overview.nodes || []).flatMap((row) => row.accelerators || []).map((row) => row.id));
  const targets = new Set((overview.targets || []).map((row) => row.id));
  for (const id of manifest.expected_inventory.node_ids) assert.ok(nodes.has(id), `preflight missing node ${id}`);
  for (const id of manifest.expected_inventory.accelerator_ids) assert.ok(accelerators.has(id), `preflight missing accelerator ${id}`);
  for (const id of manifest.expected_inventory.target_ids) assert.ok(targets.has(id), `preflight missing target ${id}`);
  return sanitizeEvidence({ health, inventory: { nodes: [...nodes].sort(), accelerators: [...accelerators].sort(), targets: [...targets].sort() } });
}

export async function runManifest(manifest, options = {}) {
  validateManifest(manifest);
  const fetchImpl = options.fetchImpl || globalThis.fetch;
  const sleep = options.sleep || ((milliseconds) => new Promise((resolvePromise) => setTimeout(resolvePromise, milliseconds)));
  const now = options.now || (() => new Date().toISOString());
  const evidence = { version: MANIFEST_VERSION, generated_at: now(), scenarios: [] };
	const disabled = [];
  for (const scenario of manifest.scenarios) {
    if (scenario.enabled === false) {
      evidence.scenarios.push({ id: scenario.id, class: scenario.class, status: "not_run", reason: "disabled in manifest" });
		disabled.push(scenario.id);
      continue;
    }
    const aliases = {};
    const record = { id: scenario.id, class: scenario.class, status: "running", assertions: 0, observations: [] };
    try {
      for (const rawStep of scenario.steps) {
        const step = resolveTemplate(rawStep, aliases);
        if (step.action === "request") {
          const response = await httpJSON(fetchImpl, manifest.controller.base_url, manifest.credentials, step);
          aliases[step.save_as] = response;
          record.observations.push({ action: "request", method: step.method.toUpperCase(), path: step.path, response: sanitizeEvidence(response) });
        } else if (step.action === "wait_workload") {
          const source = aliases[step.from];
          assert.ok(source, `wait source ${step.from} is unavailable`);
          const workloadID = getPath(source, step.id_path || "workload.request.id") || getPath(source, "request.id") || getPath(source, "id");
          assert.ok(workloadID, `wait source ${step.from} has no workload id`);
          const deadline = Date.now() + step.timeout_seconds * 1000;
          let response;
          do {
            response = await httpJSON(fetchImpl, manifest.controller.base_url, manifest.credentials, { method: "GET", path: `/api/v1/workloads/${encodeURIComponent(workloadID)}`, credential: step.credential || "admin" });
            const status = String(getPath(response, step.status_path || "workload.status") || getPath(response, "status") || "").toLowerCase();
            if ((step.until || [...terminalStatuses]).map((value) => value.toLowerCase()).includes(status)) break;
            if (Date.now() >= deadline) throw new Error(`workload ${workloadID} timed out after ${step.timeout_seconds}s`);
            await sleep(step.poll_milliseconds || 500);
          } while (true);
          aliases[step.save_as || step.from] = response;
          record.observations.push({ action: "wait_workload", workload_id: workloadID, response: sanitizeEvidence(response) });
        } else if (step.action === "assert") {
          assert.ok(aliases[step.from], `assertion source ${step.from} is unavailable`);
          assertValue(getPath(aliases[step.from], step.path), step);
          record.assertions++;
        } else if (step.action === "sleep") {
          await sleep(step.milliseconds);
        }
      }
      record.status = "passed";
    } catch (error) {
      record.status = "failed";
      record.error = error.message;
      evidence.scenarios.push(record);
      const failure = new Error(`scenario ${scenario.id} failed: ${error.message}`);
      failure.evidence = evidence;
      throw failure;
    }
    evidence.scenarios.push(record);
  }
	if (disabled.length > 0 && !options.allowDisabled) {
		const failure = new Error(`live acceptance incomplete; disabled scenarios: ${disabled.join(", ")}`);
		failure.evidence = evidence;
		throw failure;
	}
  return sanitizeEvidence(evidence);
}

export function validateDeployment(directory) {
  const absolute = resolve(directory);
  const files = readdirSync(absolute).filter((file) => file.endsWith(".yaml")).sort();
  assert.ok(files.length >= 4, "fleet deployment requires three node configs and one controller target fragment");
  const contents = files.map((file) => ({ file, text: readFileSync(resolve(absolute, file), "utf8") }));
  const nodeFiles = contents.filter(({ text }) => /^node_id:\s*/m.test(text));
  assert.equal(nodeFiles.length, 3, "fleet deployment must contain exactly three node configs");
  const nodeIDs = nodeFiles.map(({ text }) => text.match(/^node_id:\s*["']?([^"'\s#]+)/m)?.[1]);
  assert.equal(new Set(nodeIDs).size, 3, "fleet node_ids must be unique");
	const tokenEnvironments = [];
  for (const { file, text } of nodeFiles) {
    assert.match(text, /^token:\s*["']{2}\s*$/m, `${file} must not contain a literal token`);
    assert.match(text, /^token_env:\s*["']?[A-Z][A-Z0-9_]*["']?\s*$/m, `${file} must use token_env`);
    assert.match(text, /^command_signing_secret_env:\s*["']?[A-Z][A-Z0-9_]*["']?\s*$/m, `${file} must use command_signing_secret_env`);
		tokenEnvironments.push(text.match(/^token_env:\s*["']?([A-Z][A-Z0-9_]*)["']?\s*$/m)?.[1]);
  }
	assert.equal(new Set(tokenEnvironments).size, 3, "each node must use a distinct credential environment variable");
  const joined = contents.map(({ text }) => text).join("\n");
  for (const hardware of ["rtx3080", "rtx3090", "cmp170"]) assert.ok(joined.includes(hardware), `fleet config is missing ${hardware}`);
  assert.ok(joined.includes(`runtime_protocol: "${MANAGED_PROTOCOL}"`), "fleet config is missing the managed Comfy protocol");
	assert.ok(joined.includes('accelerator_id: "cmp170-node-gpu0"'), "managed CMP target does not share the node accelerator identity");
	assert.ok(joined.includes('authorization_env: "VRAM_MANAGED_COMFY_AUTHORIZATION"'), "managed harness authorization is not environment-backed");
  assert.match(joined, /sharing_enabled:\s*false/, "fleet sharing must default disabled");
  rejectConfigSecrets(joined);
  return true;
}

function rejectConfigSecrets(text) {
  assert.ok(!/^\s*(?:token|authorization|command_signing_secret|signing_secret|access_key|secret_key):\s*["']?[^"'\s#][^#]*$/gmi.test(text), "deployment templates contain literal credential material");
}

export function validateRunbook(file) {
  const text = readFileSync(resolve(file), "utf8");
  for (const heading of ["Migration and baseline", "Three-node enrollment", "Managed Comfy protocol", "Security planes", "Guarded-sharing rollout", "Live acceptance", "Rollback", "Evidence and release decision"]) {
    assert.ok(text.includes(`## ${heading}`), `runbook is missing ${heading}`);
  }
  for (const phrase of ["0020_accelerator_lease_cleanup.sql", "0001", "0020", MANAGED_PROTOCOL, "fleet-acceptance.mjs preflight", "fleet-acceptance.mjs run", "locked", "checkpointable", "OpenRouter", "S3", "webhook", "automatic remediation remains disabled"]) {
    assert.ok(text.includes(phrase), `runbook is missing ${phrase}`);
  }
  assert.ok(!text.includes("0016_creator_contract_alignment.sql"), "runbook still points at stale migration 0016");
  rejectConfigSecrets(text);
	const service = readFileSync(resolve("deploy/comfy-harness.service"), "utf8");
	for (const hardening of ["NoNewPrivileges=true", "ProtectSystem=strict", "ProtectHome=true", "ReadWritePaths=/var/lib/vram-governor/comfy-harness"]) {
		assert.ok(service.includes(hardening), `managed harness service is missing ${hardening}`);
	}
	assert.ok(!/(?:ExecStart|ExecStartPre)=.*(?:sh\s+-c|bash\s+-c)/i.test(service), "managed harness service invokes a shell");
	const buildScript = readFileSync(resolve("scripts/build-comfy-harness-package.ps1"), "utf8");
	assert.ok(buildScript.includes("./cmd/comfy-harness") && buildScript.includes('GOOS = "linux"'), "managed harness package does not build the Linux command");
  return true;
}

export function validateIntegration(manifestFile, directory, runbookFile) {
  validateManifest(JSON.parse(readFileSync(resolve(manifestFile), "utf8")));
  validateDeployment(directory);
  validateRunbook(runbookFile);
  const source = readFileSync(new URL("./fleet-acceptance.mjs", import.meta.url), "utf8");
  const adapter = readFileSync(resolve("internal/workloads/managed_comfy.go"), "utf8");
  assert.ok(source.includes(MANAGED_PROTOCOL) && adapter.includes(MANAGED_PROTOCOL), "runner and adapter protocol identifiers differ");
  return true;
}

export function validatePlan(file) {
  const text = readFileSync(resolve(file), "utf8");
  const active = [...text.matchAll(/^\| C\d+ \|.+\| (ACTIVE) \| \d+ \|$/gm)];
  assert.ok(active.length >= 14, "plan does not inventory all active completion constraints");
  for (const row of active) {
    assert.ok(!row[0].includes("|  |"), `plan row is missing an owner or observer: ${row[0]}`);
  }
  return true;
}

export function runChecked(command, args, cwd, env = process.env) {
  const result = spawnSync(command, args, { cwd, env, encoding: "utf8", stdio: "pipe", windowsHide: true });
  if (result.status !== 0) {
    const spawnError = result.error ? `spawn error: ${result.error.message}\n` : "";
    throw new Error(`${basename(command)} ${args.join(" ")} failed (status=${result.status})\n${spawnError}${result.stdout || ""}${result.stderr || ""}`);
  }
}

export function npmInvocation({ platform = process.platform, execPath = process.execPath, fileExists = existsSync } = {}) {
  if (platform !== "win32") return { command: "npm", args: [] };
  const execDirectory = dirname(execPath);
  const cliPath = resolve(execDirectory, "node_modules", "npm", "bin", "npm-cli.js");
  assert.ok(fileExists(cliPath), `npm CLI is unavailable beside ${execPath}: ${cliPath}`);
  assert.ok(!relative(execDirectory, cliPath).startsWith(".."), "npm CLI path derivation escaped the Node installation");
  return { command: execPath, args: [cliPath] };
}

export function verifyRepository(root = resolve(import.meta.dirname, "..")) {
  // Use the active toolchain or its normal GOTOOLCHAIN=auto selection. A
  // machine-specific cached 1.23 binary made repository verification fail on
  // otherwise healthy developer and CI environments.
  const go = process.env.GO || "go";
  const env = { ...process.env, GOTOOLCHAIN: process.env.GOTOOLCHAIN || "auto" };
  runChecked(go, ["test", "./...", "-count=1"], root, env);
  runChecked(go, ["vet", "./..."], root, env);
  runChecked(process.execPath, ["scripts/verify-multi-resident-scheduler.mjs"], root);
  runChecked(process.execPath, ["scripts/verify-node-residency-runtime.mjs"], root);
  runChecked(process.execPath, ["scripts/verify-controller-residency-adapter.mjs"], root);
  runChecked(process.execPath, ["scripts/verify-fleet-residency-contract.mjs"], root);
  runChecked(process.execPath, ["scripts/verify-creator-studio-contract.mjs"], root);
  runChecked(process.execPath, ["scripts/verify-capability-report.mjs"], root);
  const npm = npmInvocation();
  runChecked(npm.command, [...npm.args, "run", "build"], resolve(root, "web/ui"));
  runChecked(npm.command, [...npm.args, "audit", "--offline", "--audit-level=high"], resolve(root, "web/ui"));
}

function loadManifest(file) {
  return validateManifest(JSON.parse(readFileSync(resolve(file), "utf8")));
}

function option(args, name) {
  const index = args.indexOf(name);
  assert.ok(index >= 0 && args[index + 1], `missing ${name}`);
  return args[index + 1];
}

async function main(args) {
  const command = args[0];
  if (command === "validate-manifest") {
    loadManifest(option(args, "--file"));
    console.log("fleet acceptance manifest valid");
  } else if (command === "preflight") {
    const evidence = await preflight(loadManifest(option(args, "--file")));
    const output = args.includes("--output") ? option(args, "--output") : "";
    if (output) writeFileSync(resolve(output), stableStringify(evidence), { flag: "wx" });
    console.log("fleet preflight passed");
  } else if (command === "run") {
    const output = option(args, "--output");
	let evidence;
	try {
		evidence = await runManifest(loadManifest(option(args, "--file")));
	} catch (error) {
		if (error.evidence) writeFileSync(resolve(output), stableStringify(error.evidence), { flag: "wx" });
		throw error;
	}
	writeFileSync(resolve(output), stableStringify(evidence), { flag: "wx" });
    console.log("fleet live acceptance passed");
  } else if (command === "validate-deployment") {
    validateDeployment(option(args, "--directory"));
    console.log("fleet deployment templates valid");
  } else if (command === "validate-runbook") {
    validateRunbook(option(args, "--file"));
    console.log("fleet rollout runbook valid");
  } else if (command === "validate-integration") {
    validateIntegration(option(args, "--manifest"), option(args, "--directory"), option(args, "--runbook"));
    console.log("fleet rollout integration valid");
  } else if (command === "validate-plan") {
    validatePlan(option(args, "--file"));
    console.log("fleet completion plan valid");
  } else if (command === "verify-repository") {
    verifyRepository();
    console.log("fleet repository verification passed");
  } else {
    throw new Error("usage: fleet-acceptance.mjs <validate-manifest|preflight|run|validate-deployment|validate-runbook|validate-integration|validate-plan|verify-repository> [options]");
  }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  });
}
