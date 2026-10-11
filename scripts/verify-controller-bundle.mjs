import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync, readSync, readdirSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const read = (path) => readFileSync(resolve(root, path), "utf8");
const migrationRoot = resolve(root, "migrations");
const MAX_MIGRATION_BYTES = 2 * 1024 * 1024;
const MAX_TOTAL_MIGRATION_BYTES = 32 * 1024 * 1024;
const defaultMigrationOperations = Object.freeze({ readdirSync, lstatSync, openSync, fstatSync, readSync, closeSync });
const migrationOperationNames = Object.keys(defaultMigrationOperations);
const allowedReaderMutations = new Set(["zero-digest", "drop-stability", "drop-complete-read", "drop-growth", "drop-utf8"]);
const defaultMigrationGuards = Object.freeze({
  directory: (stat) => assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), "migration directory is not a regular directory"),
  regularFile: (stat, name) => assert.ok(stat.isFile() && !stat.isSymbolicLink(), `migration is not a regular file: ${name}`),
  fileSize: (size, name) => assert.ok(size > 0n && size <= BigInt(MAX_MIGRATION_BYTES), `migration size is invalid: ${name}`),
  openedIdentity: (before, opened, name) => assert.ok(opened.isFile() && before.dev === opened.dev && before.ino === opened.ino,
    `migration changed before being opened: ${name}`),
  stableRead: (before, after, pathAfter, name) => assert.ok(after.isFile() && before.size === after.size && before.mtimeNs === after.mtimeNs &&
    pathAfter.isFile() && !pathAfter.isSymbolicLink() && before.dev === pathAfter.dev && before.ino === pathAfter.ino,
  `migration changed while being read: ${name}`),
  completeRead: (offset, length, name) => assert.equal(offset, length, `migration size changed while being read: ${name}`),
  noGrowth: (overflow, name) => assert.equal(overflow, 0, `migration grew while being read: ${name}`),
  utf8: (bytes) => new TextDecoder("utf-8", { fatal: true }).decode(bytes),
});
const REQUIRED_HISTORICAL = [
  "0001_init.sql", "0002_performance_profiles.sql", "0003_jobs_workitems.sql",
  "0004_unified_workloads.sql", "0005_model_residency.sql", "0006_notification_outbox.sql",
  "0007_node_commands.sql", "0008_budget_reservations.sql", "0009_incident_escalation.sql",
  "0010_interference_profiles.sql", "0011_controller_state.sql", "0012_transition_plans.sql",
  "0013_browser_sessions.sql", "0014_target_policy_overrides.sql", "0015_creator_studio_contract.sql",
  "0016_creator_contract_alignment.sql", "0017_node_enrollments.sql", "0018_workload_revision.sql",
  "0019_model_capacity.sql", "0020_accelerator_lease_cleanup.sql",
];
const REQUIRED_CURRENT = ["0021_llm_checkpoints.sql", "0022_llm_displacement.sql"];

export function reduceMigrationInventory(entries) {
  const seen = new Set();
  const parsed = entries.map((entry) => {
    const name = typeof entry === "string" ? entry : entry.name;
    assert.equal(typeof name, "string", "migration inventory contains an invalid name");
    assert.match(name, /^\d{4}_[a-z0-9]+(?:_[a-z0-9]+)*\.sql$/, `noncanonical migration name: ${name}`);
    assert.ok(!seen.has(name), `duplicate migration name: ${name}`);
    seen.add(name);
    return name;
  }).sort();
  for (const name of REQUIRED_HISTORICAL) {
    assert.ok(seen.has(name), `missing required historical migration: ${name}`);
  }
  for (const name of REQUIRED_CURRENT) {
    assert.ok(seen.has(name), `missing required current migration: ${name}`);
  }
  assert.ok(parsed.length >= 22, "migration inventory is truncated before required current migrations");
  assert.ok(parsed.length <= 256, "migration inventory exceeds bounded entry count");
  for (let index = 0; index < parsed.length; index += 1) {
    const expectedId = String(index + 1).padStart(4, "0");
    assert.equal(parsed[index].slice(0, 4), expectedId, `migration sequence gap or unexpected id at ${expectedId}`);
  }
  assert.deepEqual(parsed.slice(0, 20), REQUIRED_HISTORICAL, "historical migration inventory changed");
  assert.deepEqual(parsed.slice(20, 22), REQUIRED_CURRENT, "required current migration inventory changed");
  return parsed;
}

export function readMigrationInventory(directory = migrationRoot, operationOverrides = undefined, testMutation = undefined) {
  // In-process file operations and closed reader mutants are a bounded regression seam; CLI uses native fs and all guards.
  assert.ok(operationOverrides === undefined || (operationOverrides && typeof operationOverrides === "object" &&
    Object.keys(operationOverrides).every((name) => migrationOperationNames.includes(name)) &&
    Object.values(operationOverrides).every((operation) => typeof operation === "function")),
  "invalid migration test operations");
  assert.ok(testMutation === undefined || allowedReaderMutations.has(testMutation), "invalid migration test mutation");
  const operations = operationOverrides ? { ...defaultMigrationOperations, ...operationOverrides } : defaultMigrationOperations;
  const guards = { ...defaultMigrationGuards };
  if (testMutation === "drop-stability") guards.stableRead = () => {};
  if (testMutation === "drop-complete-read") guards.completeRead = () => {};
  if (testMutation === "drop-growth") guards.noGrowth = () => {};
  if (testMutation === "drop-utf8") guards.utf8 = () => {};
  const directoryStat = operations.lstatSync(directory, { bigint: true });
  guards.directory(directoryStat);
  const names = operations.readdirSync(directory);
  assert.ok(names.length <= 256, "migration directory exceeds bounded entry count");
  const ordered = reduceMigrationInventory(names);
  let totalBytes = 0;
  return ordered.map((name) => {
    const path = resolve(directory, name);
    const before = operations.lstatSync(path, { bigint: true });
    guards.regularFile(before, name);
    guards.fileSize(before.size, name);
    totalBytes += Number(before.size);
    assert.ok(totalBytes <= MAX_TOTAL_MIGRATION_BYTES, "migration inventory exceeds total byte bound");
    const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0);
    const descriptor = operations.openSync(path, flags);
    try {
      const opened = operations.fstatSync(descriptor, { bigint: true });
      guards.openedIdentity(before, opened, name);
      const bytes = Buffer.alloc(Number(before.size));
      let offset = 0;
      while (offset < bytes.length) {
        const count = operations.readSync(descriptor, bytes, offset, bytes.length - offset, offset);
        if (count === 0) break;
        offset += count;
      }
      const overflowProbe = Buffer.alloc(1);
      const overflow = operations.readSync(descriptor, overflowProbe, 0, 1, Number(before.size));
      const after = operations.fstatSync(descriptor, { bigint: true });
      const pathAfter = operations.lstatSync(path, { bigint: true });
      guards.stableRead(before, after, pathAfter, name);
      guards.completeRead(offset, bytes.length, name);
      guards.noGrowth(overflow, name);
      guards.utf8(bytes);
      const sha256 = testMutation === "zero-digest" ? "0".repeat(64) : createHash("sha256").update(bytes).digest("hex");
      return { name, bytes: bytes.length, sha256 };
    } finally {
      operations.closeSync(descriptor);
    }
  });
}

function verifyControllerBundle() {
const required = [
  "deploy/controller/controller.yaml.template",
  "deploy/controller/controller.env.example",
  "deploy/controller/vram-governor-controller.service",
  "deploy/controller/validate-controller.sh",
  "deploy/controller/apply-migrations.sh",
  "deploy/controller/install.sh",
  "deploy/controller/uninstall.sh",
  "deploy/controller/README.txt",
  "docs/dedicated-controller-deployment.md",
  "scripts/build-controller-package.ps1",
  "scripts/package-controller-archive.go",
];
for (const path of required) assert.doesNotThrow(() => read(path), `missing ${path}`);

const config = read(required[0]);
assert.match(config, /production:\s*true/);
assert.match(config, /listen_addr:\s*":8443"/);
assert.match(config, /type:\s*"s3"/);
assert.match(config, /database_url:\s*"postgresql:\/\/\/vram_governor\?host=\/var\/run\/postgresql"/);
for (const identity of ["rtx3080-node", "rtx3090-node", "cmp170-node", "780m-node"]) {
  assert.ok(config.includes(`id: "${identity}"`), `missing node credential ${identity}`);
}
for (const plane of ["node", "enrollment", "ui", "workflow", "mcp", "agent", "admin"]) {
  assert.ok(config.includes(`plane: "${plane}"`), `missing security plane ${plane}`);
}
assert.ok(config.includes('runtime_protocol: "managed_comfy_v1"'));
assert.ok(config.includes('accelerator_id: "cmp170-node-gpu0"'));
assert.ok(!/^\s+token:\s+/m.test(config), "raw credential token field found");
assert.ok((config.match(/token_sha256:/g) ?? []).length >= 8, "expected scoped credential digests");

const service = read(required[2]);
for (const hardening of ["NoNewPrivileges=true", "ProtectSystem=strict", "CapabilityBoundingSet=", "ExecStartPre="]) {
  assert.ok(service.includes(hardening), `service missing ${hardening}`);
}
assert.ok(!service.toLowerCase().includes("wsl"), "controller service must not depend on WSL");

const validator = read(required[3]);
assert.ok(validator.includes("-check-config"));
assert.ok(validator.includes("still contains __PLACEHOLDER__"));
assert.ok(validator.includes("at least 32 characters"));
const installer = read(required[5]);
assert.ok(installer.includes("--config and --environment-file are required together"));
assert.ok(installer.includes("without enabling or starting it"));
assert.ok(installer.includes("controller.yaml.$timestamp.bak"));
const uninstaller = read(required[6]);
assert.ok(uninstaller.includes("were preserved"));
assert.ok(!uninstaller.includes("rm -rf"), "uninstaller must not recursively delete controller data");

const migrations = readMigrationInventory();
assert.deepEqual(migrations.map(({ name }) => name).slice(20, 22), REQUIRED_CURRENT);
const build = read(required[9]);
assert.ok(build.includes("./cmd/controller"));
assert.ok(build.includes("migrations/*.sql"));
assert.ok(build.includes("DEPLOYMENT.md"));
assert.ok(build.includes("package-controller-archive.go"));

const docs = read(required[8]);
for (const phrase of ["separate controller", "RTX 3080", "RTX 3090", "CMP170", "controller.yaml", "controller.env", "apply-migrations.sh", "8443"]) {
  assert.ok(docs.includes(phrase), `deployment guide missing ${phrase}`);
}
assert.ok(read("README.md").includes("dedicated-controller-deployment.md"), "README does not link the bundle guide");
assert.ok(read("cmd/controller/main.go").includes('"check-config"'), "controller lacks config-check mode");

console.log("controller bundle verification passed");
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) verifyControllerBundle();
