import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import {
  FIXED_SSH_HARDLINKS, FIXED_SSH_TOOL_BYTES, FIXED_SSH_TOOL_SHA256, _fixedSshToolForTest,
} from '../controller-hotfix/command-fence.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(HERE, '../..');
const PYTHON = path.join(HERE, 'run-startup.py');
const MATERIALS = path.join(HERE, 'materials.mjs');
const MATERIALS_TEST = path.join(HERE, 'materials.test.mjs');
const PROBE = path.join(HERE, 'isolation-probe.mjs');
const CAPACITY_VERIFIER = path.resolve(HERE, '../../scripts/verify-runtime-profile-projection.mjs');
const SSH = 'C:/Windows/System32/OpenSSH/ssh.exe';
const SSH_KEY = 'C:/Users/Sasha/.ssh/cmp170_proxmox';
const KNOWN_HOSTS = 'C:/Users/Sasha/.ssh/known_hosts';
const HOST = '10.0.0.3';
const MAX_SOURCE = 4 * 1024 * 1024;
const MAX_META = 8 * 1024 * 1024;
const MAX_PAYLOAD = 320 * 1024 * 1024;
const MAX_STDOUT = 8192;
const MAX_STDERR = 8192;
const SESSION_MS = 245_000;
const CAPACITY_SESSION_MS = 480_000;
const CAPACITY_FREEZE_SHA256 = '438df45ee3397c7ba1845f5b03738cae86028d001ed5a97f4918e1372f2652f5';
const CAPACITY_VERIFIER_BYTES = 185643;
const CAPACITY_VERIFIER_SHA256 = 'a099d5e788a1461a78206700680b741075e35e9b701518e287721b1021fd0aa1';
const CAPACITY_PINS = Object.freeze({
  'internal/workloads/manager.go': [411178, 'e661094ed488140743780e413c1dbe42197ae2aab99ddb1b3bb08041c29fe358'],
  'internal/workloads/manager_test.go': [290449, '2b7db9a3ed001330ddafc777788dd0e766508be01f426270fb0d9f009c887c8a'],
  'internal/workloads/residency.go': [112173, '341f55bd6a4e2ee374b8d38562bd5aeab93af1166bdac84db39208afdc53522e'],
  'internal/api/node_commands.go': [79097, '20047d49a8628c65c71efa23c6b3c627279783ed545046a51851e8c5187eb550'],
  'internal/api/node_commands_test.go': [80334, 'b77fec982aae8fc6595dbe05b1f3ed14fa38c570fd156478433493b5e5399bc2'],
  'internal/api/ws.go': [58722, '2a60e84306871a08e372c811d8e2edb82f24d33e94639de988b491be1ed10ead'],
  'internal/api/ws_test.go': [66923, 'a2334022efa245687a128c024e0e010640db1b2d7b15421c18ddb95f0744eed3'],
  'scripts/verify-runtime-profile-projection.mjs': [CAPACITY_VERIFIER_BYTES, CAPACITY_VERIFIER_SHA256],
});
const CAPACITY_PINS_PATH = Object.keys(CAPACITY_PINS);
const CAPACITY_PACKAGES = Object.freeze(['vram-governor/internal/api', 'vram-governor/internal/workloads']);
const CAPACITY_OUTPUT = 'STRICT UNIT: exact uncached package PASS=vram-governor/internal/api,vram-governor/internal/workloads\nSTRICT UNIT: exact unique RUN/PASS inventory=82\nruntime profile projection unit controls passed\n';
const TERMINAL = 'CT200_STARTUP_PASSED';
const FAILURE_STAGES = new Set(['bootstrap', 'request', 'snapshot', 'runtime', 'isolation', 'receipt', 'unclassified']);
const FAILURE_REASONS = new Set([
  'deadline', 'service_start', 'service_activation', 'service_output_bound', 'service_stderr_bound', 'unit_identity_changed',
  'unit_main_membership', 'unit_pid', 'unit_pid_identity', 'unit_pid_gone', 'unit_pid_reused', 'service_result', 'inner_probe', 'inner_unit',
  'service_identity', 'production_unit_changed', 'service_cgroup_identity', 'cleanup_observation',
  'scratch_cleanup', 'systemd_properties', 'rootfs_custody', 'cgroup_limit', 'cgroup_file', 'cgroup_identity',
  'cgroup_main_pid', 'cgroup_pid_membership', 'cgroup', 'cgroup_path', 'unclassified',
]);
const FAILURE_EXCEPTIONS = new Set([
  'reject', 'os_error', 'file_not_found', 'permission_error', 'timeout', 'subprocess_error', 'value_error',
  'type_error', 'key_error', 'index_error', 'attribute_error', 'assertion_error', 'unicode_error', 'eof_error',
  'memory_error', 'overflow_error', 'recursion_error', 'system_exit', 'other',
]);
const FAILURE_FRAMES = new Set([
  'main', 'isolation', 'validation', 'request_validation', 'material_stage', 'source_validation', 'tree_measure',
  'copy_tree', 'copy_file', 'elf_closure', 'command', 'systemd_properties', 'unit_projection', 'unit_capture',
  'cgroup_validation', 'cgroup_read', 'cgroup_path',
  'fixture_cleanup', 'unit_cleanup', 'unlocated',
]);
const SERVICE_DIAGNOSTICS = new Set([
  'launcher', 'permission', 'node_syntax', 'node_module', 'probe', 'probe_config', 'probe_config_shape', 'probe_facts_shape',
  'probe_credentials', 'probe_privilege', 'probe_capabilities', 'probe_namespace', 'probe_identity', 'probe_limits',
  'probe_controls', 'probe_bounded_read', 'probe_file_custody', 'probe_gpu_inventory', 'probe_absence',
  'probe_runtime', 'probe_status_field', 'probe_status_ids', 'probe_config_missing', 'probe_guard_error', 'probe_native_error', 'control', 'overflow', 'unclassified',
]);
let failureEvidence = { stage: 'local', category: 'controlled', exitCode: null, signal: null, stdoutBytes: 0, stderrBytes: 0, receiverFailure: null };

// Pins are refreshed only with a separately reviewed source change.
export const MATERIALS_SHA256 = '49b2f1b33bc4208e216ef9aec73c8beb7f0f5122c8b643ece4ac765a851eec08';
export const MATERIALS_TEST_SHA256 = 'c2ee4859f7ee50078407038ea10eafecbcbacd1df209d7cd13f86c809539348d';
export const PROBE_SHA256 = '9de723c6fb1c98e40f693ad2ba1037dd3d7903cbe1843b79888a0aae8140daf9';
export const RUNNER_SOURCE_BYTES = 262724;
export const RUNNER_SOURCE_SHA256 = '2836f1d5d43c1755f3808284cf1c11e2e77f052c03f3edb8513085345aa71ec3';

function fail(message) { throw new Error(message); }
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function exactKeys(value, keys) {
  return value !== null && typeof value === 'object' && !Array.isArray(value) &&
    Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).sort().join('\0') === [...keys].sort().join('\0');
}
function parseFailureEnvelope(bytes) {
  if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 512 || bytes.some((byte) => byte > 0x7f)) return null;
  const match = /^fixed startup supervisor failed stage=([a-z_]+) category=(controlled|internal) unit=(settled|preserved|unclassified) fixture=(settled|preserved|unclassified) scratch=(retained|absent|unclassified) reason=([a-z0-9_]+) exception=([a-z_]+) frame=([a-z_]+) line=(0|[1-9][0-9]{0,3}) diagnostic=([a-z_]+)\n$/.exec(bytes.toString('ascii'));
  if (!match || !FAILURE_STAGES.has(match[1]) || !FAILURE_REASONS.has(match[6]) || !FAILURE_EXCEPTIONS.has(match[7]) ||
      !FAILURE_FRAMES.has(match[8]) || !SERVICE_DIAGNOSTICS.has(match[10])) return null;
  const line = Number(match[9]);
  if (line > 4096 || (match[8] === 'unlocated' ? line !== 0 : line === 0)) return null;
  return Object.freeze({ stage: match[1], category: match[2], unit: match[3], fixture: match[4], scratch: match[5], reason: match[6], exception: match[7], frame: match[8], line, diagnostic: match[10] });
}
function byteCompare(a, b) { return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')); }
function canonicalJson(value) { return Buffer.from(JSON.stringify(value), 'utf8'); }
function canonicalBase64Shape(value, decodedBytes) {
  const encodedBytes = Math.ceil(decodedBytes / 3) * 4;
  if (value.length !== encodedBytes || value.length % 4 !== 0) return false;
  const remainder = decodedBytes % 3;
  const padding = remainder === 0 ? 0 : remainder === 1 ? 2 : 1;
  const dataEnd = value.length - padding;
  for (let index = 0; index < dataEnd; index += 1) {
    const code = value.charCodeAt(index);
    if (!((code >= 65 && code <= 90) || (code >= 97 && code <= 122) ||
        (code >= 48 && code <= 57) || code === 43 || code === 47)) return false;
  }
  for (let index = dataEnd; index < value.length; index += 1) {
    if (value.charCodeAt(index) !== 61) return false;
  }
  return true;
}
function canonicalWire(value) {
  const stable = (item) => Array.isArray(item) ? `[${item.map(stable).join(',')}]` :
    item && typeof item === 'object' ? `{${Object.keys(item).sort().map((key) => `${JSON.stringify(key)}:${stable(item[key])}`).join(',')}}` : JSON.stringify(item);
  return Buffer.from(stable(value), 'utf8');
}
function validNonce(value) { return typeof value === 'string' && /^[a-f0-9]{32}$/.test(value); }

function sameStat(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.mode === b.mode && a.nlink === b.nlink &&
    a.uid === b.uid && a.gid === b.gid && a.size === b.size && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;
}

function noLinkedAncestors(filename, fsOps = fs) {
  const absolute = path.resolve(filename);
  let cursor = path.parse(absolute).root;
  for (const part of absolute.slice(cursor.length).split(path.sep).filter(Boolean)) {
    cursor = path.join(cursor, part);
    const stat = fsOps.lstatSync(cursor);
    if (stat.isSymbolicLink() || (cursor !== absolute && !stat.isDirectory())) fail('local path custody failed');
  }
}

function readFixedFile(filename, maxBytes, expected = undefined) {
  noLinkedAncestors(filename);
  const before = fs.lstatSync(filename, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size > BigInt(maxBytes) || (expected && expected.bytes !== undefined && before.size !== BigInt(expected.bytes))) fail('fixed local file metadata failed');
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    for (const key of ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs']) if (opened[key] !== before[key]) fail('fixed local file changed before read');
    const chunks = [];
    let total = 0;
    while (total < Number(opened.size)) {
      const buffer = Buffer.alloc(Math.min(65536, Number(opened.size) - total));
      const n = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (n <= 0) fail('fixed local file short read');
      chunks.push(buffer.subarray(0, n));
      total += n;
    }
    const extra = Buffer.alloc(1);
    if (fs.readSync(fd, extra, 0, 1, null) !== 0) fail('fixed local file grew');
    const after = fs.fstatSync(fd, { bigint: true });
    noLinkedAncestors(filename);
    const named = fs.lstatSync(filename, { bigint: true });
    for (const key of ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs']) if (after[key] !== before[key] || named[key] !== before[key]) fail('fixed local file changed during read');
    const bytes = Buffer.concat(chunks);
    if (expected && ((expected.bytes !== undefined && bytes.length !== expected.bytes) || sha256(bytes) !== expected.sha256)) fail('fixed local file pin failed');
    return bytes;
  } finally { fs.closeSync(fd); }
}

function readFixedSsh() {
  const snapshots = FIXED_SSH_HARDLINKS.map((name) => {
    noLinkedAncestors(name);
    const stat = fs.lstatSync(name, { bigint: true });
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 2n || stat.size !== BigInt(FIXED_SSH_TOOL_BYTES)) fail('fixed SSH metadata failed');
    return stat;
  });
  if (snapshots[0].dev !== snapshots[1].dev || snapshots[0].ino !== snapshots[1].ino) fail('fixed SSH hardlink mismatch');
  const fd = fs.openSync(SSH, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  try {
    const opened = fs.fstatSync(fd, { bigint: true });
    for (const key of ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs']) if (opened[key] !== snapshots[0][key]) fail('fixed SSH open custody failed');
    const chunks = [];
    let total = 0;
    while (total < FIXED_SSH_TOOL_BYTES) {
      const buffer = Buffer.alloc(Math.min(65536, FIXED_SSH_TOOL_BYTES - total));
      const n = fs.readSync(fd, buffer, 0, buffer.length, null);
      if (n <= 0) fail('fixed SSH short read');
      chunks.push(buffer.subarray(0, n));
      total += n;
    }
    const extra = Buffer.alloc(1);
    if (fs.readSync(fd, extra, 0, 1, null) !== 0) fail('fixed SSH grew');
    const after = fs.fstatSync(fd, { bigint: true });
    for (let i = 0; i < FIXED_SSH_HARDLINKS.length; i += 1) {
      noLinkedAncestors(FIXED_SSH_HARDLINKS[i]);
      const named = fs.lstatSync(FIXED_SSH_HARDLINKS[i], { bigint: true });
      for (const key of ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeNs', 'ctimeNs']) if (after[key] !== snapshots[i][key] || named[key] !== snapshots[i][key]) fail('fixed SSH changed during read');
    }
    const bytes = Buffer.concat(chunks);
    if (total !== FIXED_SSH_TOOL_BYTES || sha256(bytes) !== FIXED_SSH_TOOL_SHA256) fail('fixed SSH pin failed');
    if (!_fixedSshToolForTest(fs, bytes).equals(bytes)) fail('fixed SSH fence verification failed');
    return bytes;
  } finally { fs.closeSync(fd); }
}

export function validateMaterialsBundle(bundle, mode = 'startup') {
  if (!['startup', 'capacity'].includes(mode)) fail('materials bundle mode rejected');
  const capacityMode = mode === 'capacity';
  const topKeys = ['schema', 'files', 'manifestSha256', 'sourceManifestSha256', 'startupFreezeSha256', 'sourceCount', 'moduleCount', 'moduleInventory',
    ...(capacityMode ? ['mode', 'capacityFreezeSha256'] : [])];
  if (!exactKeys(bundle, topKeys) || bundle.schema !== (capacityMode ? 'ct200-capacity-materials-v1' : 1) ||
      (capacityMode && (bundle.mode !== 'capacity' || bundle.capacityFreezeSha256 !== CAPACITY_FREEZE_SHA256)) ||
      !Array.isArray(bundle.files) || !Array.isArray(bundle.moduleInventory) ||
      !Number.isSafeInteger(bundle.sourceCount) || !Number.isSafeInteger(bundle.moduleCount) || bundle.moduleCount !== bundle.moduleInventory.length ||
      !Number.isSafeInteger(bundle.sourceCount) || bundle.sourceCount <= 1 || bundle.sourceCount > 4112 ||
      !Number.isSafeInteger(bundle.moduleCount) || bundle.moduleCount < 1 || bundle.moduleCount > 128 ||
      typeof bundle.manifestSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(bundle.manifestSha256) ||
      typeof bundle.sourceManifestSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(bundle.sourceManifestSha256) ||
      typeof bundle.startupFreezeSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(bundle.startupFreezeSha256)) fail('materials bundle schema failed');
  let previous = '';
  let total = 0;
  const rows = [];
  const sourceRows = [];
  const moduleRows = [];
  for (const file of bundle.files) {
    if (!exactKeys(file, ['path', 'bytes', 'sha256', 'base64']) || typeof file.path !== 'string' || !Number.isSafeInteger(file.bytes) || file.bytes < 0 ||
        typeof file.sha256 !== 'string' || !/^[a-f0-9]{64}$/.test(file.sha256) || typeof file.base64 !== 'string' || file.path <= previous || file.path.includes('\\') || /[\r\n\0]/.test(file.path) || file.path.split('/').some((part) => !part || part === '.' || part === '..')) fail('materials entry schema or ordering failed');
    if (!file.path.startsWith('source/') && !file.path.startsWith('modules/')) fail('materials entry path escaped fixed source/dependency roots');
    previous = file.path;
    if (file.bytes > MAX_PAYLOAD - total) fail('materials payload exceeds fixed limit');
    total += file.bytes;
    if (!canonicalBase64Shape(file.base64, file.bytes)) fail('materials base64 is not canonical');
    const content = Buffer.from(file.base64, 'base64');
    if (content.length !== file.bytes || content.toString('base64') !== file.base64 || sha256(content) !== file.sha256) fail('materials payload authentication failed');
    const row = { path: file.path, bytes: file.bytes, sha256: file.sha256 };
    rows.push(row);
    if (file.path.startsWith('source/')) sourceRows.push({ path: file.path.slice('source/'.length), bytes: file.bytes, sha256: file.sha256 });
    else moduleRows.push(file.path);
  }
  if (rows.length < 10 || rows.length > 30000 || rows.length !== bundle.sourceCount + 4 * bundle.moduleCount ||
      sha256(canonicalJson(rows)) !== bundle.manifestSha256 || sha256(canonicalJson(sourceRows)) !== bundle.sourceManifestSha256 || sourceRows.length !== bundle.sourceCount) fail('materials manifest authentication failed');
  if (capacityMode) {
    const byPath = new Map(sourceRows.map((row) => [row.path, row]));
    if (CAPACITY_PINS_PATH.some((name) => {
      const row = byPath.get(name);
      const [bytes, digest] = CAPACITY_PINS[name];
      return !row || row.bytes !== bytes || row.sha256 !== digest;
    })) fail('capacity source pin rejected');
  }
  const expectedModuleFiles = [];
  let priorModule = '';
  for (const item of bundle.moduleInventory) {
    if (!exactKeys(item, ['modulePath', 'version', 'files', 'bytes', 'goHash1']) || typeof item.modulePath !== 'string' ||
        !/^[A-Za-z0-9._~+!-]+(?:\/[A-Za-z0-9._~+!-]+)*$/.test(item.modulePath) || item.modulePath.split('/').some((part) => part === '.' || part === '..') ||
        typeof item.version !== 'string' || !/^v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(item.version) ||
        !Number.isSafeInteger(item.files) || item.files < 1 || item.files > 20000 || !Number.isSafeInteger(item.bytes) || item.bytes < 0 || item.bytes > 64 * 1024 * 1024 ||
        typeof item.goHash1 !== 'string' || !/^h1:[A-Za-z0-9+/]{43}=$/.test(item.goHash1) || item.modulePath <= priorModule) fail('materials module inventory rejected');
    priorModule = item.modulePath;
    const escaped = (value) => value.replace(/[A-Z]/g, (char) => `!${char.toLowerCase()}`);
    const base = `modules/${escaped(item.modulePath)}/@v/${escaped(item.version)}`;
    expectedModuleFiles.push(...['.info', '.mod', '.zip', '.ziphash'].map((suffix) => `${base}${suffix}`));
  }
  expectedModuleFiles.sort(byteCompare);
  if (moduleRows.length !== expectedModuleFiles.length || moduleRows.some((name, index) => name !== expectedModuleFiles[index])) fail('materials module file inventory rejected');
  return Object.freeze({ totalBytes: total, fileCount: rows.length });
}

export function validateRunReceipt(bytes, exitCode, nonce, expected) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > MAX_STDOUT || exitCode !== 0 || !validNonce(nonce) ||
      !exactKeys(expected, ['manifestSha256', 'sourceManifestSha256', 'startupFreezeSha256']) ||
      Object.values(expected).some((item) => typeof item !== 'string' || !/^[a-f0-9]{64}$/.test(item))) fail('startup receipt boundary failed');
  const text = bytes.toString('ascii');
  if (!Buffer.from(text, 'ascii').equals(bytes) || !text.endsWith(`\n${TERMINAL}\n`)) fail('startup receipt terminal missing');
  const lines = text.split('\n');
  if (lines.length !== 3 || lines[2] !== '') fail('startup receipt frame shape failed');
  let receipt;
  try { receipt = JSON.parse(lines[0]); } catch { fail('startup receipt JSON failed'); }
  const keys = ['schema', 'status', 'nonce', 'sourceManifestSha256', 'bundleManifestSha256', 'startupFreezeSha256', 'probeReceiptSha256', 'unitOutputSha256', 'testCount', 'productionUnitsPreserved', 'ownedEffectsSettled'];
  if (!exactKeys(receipt, keys) || receipt.schema !== 'ct200-startup-run-v1' || receipt.status !== 'passed' || receipt.nonce !== nonce ||
      receipt.sourceManifestSha256 !== expected.sourceManifestSha256 || receipt.bundleManifestSha256 !== expected.manifestSha256 ||
      receipt.startupFreezeSha256 !== expected.startupFreezeSha256 ||
      !['probeReceiptSha256', 'unitOutputSha256'].every((key) => typeof receipt[key] === 'string' && /^[a-f0-9]{64}$/.test(receipt[key])) ||
      receipt.testCount !== 15 || receipt.productionUnitsPreserved !== true || receipt.ownedEffectsSettled !== true) fail('startup receipt evidence rejected');
  return Object.freeze(receipt);
}

export function validateCapacityRunReceipt(bytes, exitCode, nonce, expected) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > MAX_STDOUT || exitCode !== 0 || !validNonce(nonce) ||
      !exactKeys(expected, ['manifestSha256', 'sourceManifestSha256', 'startupFreezeSha256', 'capacityFreezeSha256']) ||
      Object.values(expected).some((item) => typeof item !== 'string' || !/^[a-f0-9]{64}$/.test(item)) ||
      expected.capacityFreezeSha256 !== CAPACITY_FREEZE_SHA256) fail('capacity receipt boundary failed');
  const text = bytes.toString('ascii');
  if (!Buffer.from(text, 'ascii').equals(bytes) || !text.endsWith('\nCT200_CAPACITY_PASSED\n')) fail('capacity receipt terminal missing');
  const lines = text.split('\n');
  if (lines.length !== 3 || lines[2] !== '') fail('capacity receipt frame shape failed');
  let receipt;
  try { receipt = JSON.parse(lines[0]); } catch { fail('capacity receipt JSON failed'); }
  const keys = ['schema', 'mode', 'status', 'nonce', 'sourceManifestSha256', 'bundleManifestSha256', 'startupFreezeSha256', 'capacityFreezeSha256',
    'probeReceiptSha256', 'capacityOutputSha256', 'testCount', 'packages', 'productionUnitsPreserved', 'ownedEffectsSettled'];
  if (!exactKeys(receipt, keys) || receipt.schema !== 'ct200-capacity-run-v1' || receipt.mode !== 'capacity' || receipt.status !== 'passed' ||
      receipt.nonce !== nonce || receipt.sourceManifestSha256 !== expected.sourceManifestSha256 ||
      receipt.bundleManifestSha256 !== expected.manifestSha256 || receipt.startupFreezeSha256 !== expected.startupFreezeSha256 ||
      receipt.capacityFreezeSha256 !== expected.capacityFreezeSha256 || typeof receipt.probeReceiptSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(receipt.probeReceiptSha256) ||
      receipt.capacityOutputSha256 !== sha256(Buffer.from(CAPACITY_OUTPUT, 'utf8')) || receipt.testCount !== 82 ||
      !Array.isArray(receipt.packages) || receipt.packages.length !== 2 || receipt.packages.some((name, index) => name !== CAPACITY_PACKAGES[index]) ||
      receipt.productionUnitsPreserved !== true || receipt.ownedEffectsSettled !== true) fail('capacity receipt evidence rejected');
  return Object.freeze(receipt);
}

export function validateProbeReceipt(value, config) {
  const keys = ['schema', 'nonce', 'inputSha256', 'pid', 'namespaces', 'limits'];
  if (!exactKeys(config, ['nonce', 'inputSha256', 'outsideNamespaces']) || !validNonce(config.nonce) ||
      typeof config.inputSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(config.inputSha256) ||
      !exactKeys(config.outsideNamespaces, ['pid', 'mnt', 'net']) ||
      ['pid', 'mnt', 'net'].some((kind) => typeof config.outsideNamespaces[kind] !== 'string' || !new RegExp(`^${kind}:\\[[1-9][0-9]{0,19}\\]$`).test(config.outsideNamespaces[kind]))) fail('isolation probe config rejected');
  if (!exactKeys(value, keys) || value.schema !== 'lb-isolation-receipt-v1' || value.nonce !== config.nonce ||
      typeof value.nonce !== 'string' || typeof value.inputSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(value.inputSha256) || value.inputSha256 !== config.inputSha256 || !Number.isSafeInteger(value.pid) || value.pid !== 1 ||
      !exactKeys(value.namespaces, ['pid', 'mnt', 'net']) || !exactKeys(value.limits, ['memory.max', 'memory.swap.max', 'pids.max', 'cpu.max'])) fail('isolation probe receipt rejected');
  for (const kind of ['pid', 'mnt', 'net']) {
    if (typeof value.namespaces[kind] !== 'string' || !new RegExp(`^${kind}:\\[[1-9][0-9]{0,19}\\]$`).test(value.namespaces[kind]) ||
        value.namespaces[kind] === config.outsideNamespaces?.[kind]) fail('isolation probe namespace rejected');
  }
  const limits = { 'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '128', 'cpu.max': '100000 100000' };
  for (const [key, expected] of Object.entries(limits)) if (value.limits[key] !== expected) fail('isolation probe limits rejected');
  return Object.freeze(value);
}

export function validateTerminalInventory(before, after, proof) {
  if (!Array.isArray(before) || before.length !== 5 || !Array.isArray(after) || after.length !== 5 ||
      !exactKeys(proof, ['serviceExited', 'serviceCgroupEmpty', 'namespacesGone', 'ownedFixtureSettled']) ||
      Object.values(proof).some((value) => value !== true)) fail('terminal inventory proof rejected');
  const normalize = (rows) => rows.map((row) => {
    if (!exactKeys(row, ['Id', 'LoadState', 'ActiveState', 'SubState', 'MainPID', 'InvocationID', 'MainPIDStartTime']) ||
        typeof row.Id !== 'string' || !/^[a-z0-9][a-z0-9_.@:-]{0,255}\.service$/.test(row.Id) ||
        !['loaded', 'not-found'].includes(row.LoadState) || typeof row.ActiveState !== 'string' || typeof row.SubState !== 'string' ||
        typeof row.MainPID !== 'string' || !/^[0-9]+$/.test(row.MainPID) || !(row.MainPIDStartTime === null || Number.isSafeInteger(row.MainPIDStartTime)) ||
        typeof row.InvocationID !== 'string' || !(row.InvocationID === '' || /^[a-f0-9]{32}$/.test(row.InvocationID))) fail('production unit projection rejected');
    return [row.Id, row.LoadState, row.ActiveState, row.SubState, row.MainPID, row.InvocationID, row.MainPIDStartTime];
  });
  const expectedNames = ['vram-governor-node-agent.service', 'llama-server.service', 'comfyui.service', 'comfy-harness.service', 'vram-governor-runtime-tunnel.service'];
  const left = normalize(before);
  const right = normalize(after);
  if (left.some((row, index) => row[0] !== expectedNames[index]) || new Set(left.map((row) => row[0])).size !== 5 || JSON.stringify(left) !== JSON.stringify(right)) fail('production unit identity changed');
  return true;
}

export function buildBootstrap(sourceBytes, probeBytes, mode = 'startup') {
  if (!['startup', 'capacity'].includes(mode)) fail('fixed bootstrap mode rejected');
  const capacityMode = mode === 'capacity';
  const bootstrapSeconds = capacityMode ? 470 : 235;
  if (!Buffer.isBuffer(sourceBytes) || sourceBytes.length !== RUNNER_SOURCE_BYTES || sha256(sourceBytes) !== RUNNER_SOURCE_SHA256) fail('startup receiver pin failed');
  if (!Buffer.isBuffer(probeBytes) || sha256(probeBytes) !== PROBE_SHA256 || probeBytes.length > 256 * 1024) fail('isolation probe pin failed');
  return [
    'import os,sys,re,hashlib,signal,time',
    `deadline=time.monotonic()+${bootstrapSeconds}`,
    `signal.setitimer(signal.ITIMER_REAL,${bootstrapSeconds})`,
    'def read_exact(n):',
    ' b=bytearray()',
    ' while len(b)<n:',
    '  x=os.read(0,min(65536,n-len(b)))',
    '  if not x: break',
    '  b.extend(x)',
    ' return bytes(b)',
    'def read_line(limit):',
    ' b=bytearray()',
    ' while len(b)<limit:',
    '  x=os.read(0,1)',
    '  if not x: break',
    '  b.extend(x)',
    '  if x==b"\\n": break',
    ' return bytes(b)',
    'def read_extra(): return os.read(0,1)',
    'n=read_line(16)',
    `if n!=b'${RUNNER_SOURCE_BYTES}\\n': raise SystemExit(91)`,
    'h=read_line(66)',
    `if h!=b'${RUNNER_SOURCE_SHA256}\\n': raise SystemExit(92)`,
    `source=read_exact(${RUNNER_SOURCE_BYTES})`,
    `if len(source)!=${RUNNER_SOURCE_BYTES} or hashlib.sha256(source).hexdigest()!='${RUNNER_SOURCE_SHA256}': raise SystemExit(93)`,
    `probe_bytes=read_exact(${probeBytes.length})`,
    `if len(probe_bytes)!=${probeBytes.length} or hashlib.sha256(probe_bytes).hexdigest()!='${PROBE_SHA256}': raise SystemExit(97)`,
    'mn=read_line(16)',
    'mh=read_line(66)',
    'if not re.fullmatch(b"(?:[1-9][0-9]{0,6})\\n",mn) or not re.fullmatch(b"[a-f0-9]{64}\\n",mh): raise SystemExit(94)',
    'meta_bytes=read_exact(int(mn))',
    'if len(meta_bytes)!=int(mn) or hashlib.sha256(meta_bytes).hexdigest().encode()!=mh.rstrip(b"\\n"): raise SystemExit(95)',
    'try: meta=__import__("json").loads(meta_bytes.decode("ascii"))',
    'except Exception: raise SystemExit(96)',
    'if __import__("json").dumps(meta,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")!=meta_bytes: raise SystemExit(98)',
    `exec(compile(source,'<ct200-startup-supervisor>','exec'),{'__name__':'__main__','_request_meta':meta,'_read_raw':read_exact,'_read_extra':read_extra,'_probe_bytes':probe_bytes,'_deadline':deadline,'_capacity_mode':${capacityMode ? 'True' : 'False'}})`,
  ].join('\n');
}

function posixQuote(value) { return "'" + value.replace(/'/g, "'\\''") + "'"; }
function sshArgs(remote) {
  return [
    '-F', 'none', '-T', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', '-o', 'ServerAliveInterval=5', '-o', 'ServerAliveCountMax=1',
    '-o', 'StrictHostKeyChecking=yes', '-o', `UserKnownHostsFile=C:/Users/Sasha/.ssh/known_hosts`, '-o', 'GlobalKnownHostsFile=none', '-o', `HostName=${HOST}`,
    '-o', 'PermitLocalCommand=no', '-o', 'ClearAllForwardings=yes', '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no', '-o', 'ForwardX11Trusted=no',
    '-o', 'Tunnel=no', '-o', 'UpdateHostKeys=no', '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'ControlMaster=no', '-o', 'ControlPath=none',
    '-o', 'CanonicalizeHostname=no', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none', '-i', SSH_KEY, `root@${HOST}`, remote,
  ];
}

function writeChunk(stream, chunk) {
  if (stream.destroyed || stream.writableEnded) return Promise.reject(new Error('SSH input closed'));
  if (stream.write(chunk)) return Promise.resolve();
  return new Promise((resolve, reject) => {
    const cleanup = () => { stream.removeListener('drain', onDrain); stream.removeListener('error', onError); stream.removeListener('close', onClose); };
    const onDrain = () => { cleanup(); resolve(); };
    const onError = () => { cleanup(); reject(new Error('SSH input failed')); };
    const onClose = () => { cleanup(); reject(new Error('SSH input closed')); };
    stream.once('drain', onDrain); stream.once('error', onError); stream.once('close', onClose);
  });
}

async function transmitBundle(stream, sourceBytes, probeBytes, bundle, nonce, mode = 'startup') {
  if (!['startup', 'capacity'].includes(mode)) fail('fixed transfer mode rejected');
  const capacityMode = mode === 'capacity';
  const rows = bundle.files.map(({ path: p, bytes, sha256: digest }) => ({ path: p, bytes, sha256: digest }));
  const baseMeta = {
    nonce, manifestSha256: bundle.manifestSha256,
    sourceManifestSha256: bundle.sourceManifestSha256, startupFreezeSha256: bundle.startupFreezeSha256,
    sourceCount: bundle.sourceCount, moduleCount: bundle.moduleCount, totalBytes: bundle.files.reduce((n, file) => n + file.bytes, 0), files: rows,
  };
  const meta = capacityMode ? { ...baseMeta, schema: 'ct200-capacity-request-v1', mode: 'capacity', capacityFreezeSha256: bundle.capacityFreezeSha256 } :
    { ...baseMeta, schema: 'ct200-startup-request-v1' };
  const metaBytes = canonicalWire(meta);
  if (metaBytes.length > MAX_META) fail('startup request manifest exceeds bound');
  const runnerSource = readFixedFile(PYTHON, MAX_SOURCE, { bytes: RUNNER_SOURCE_BYTES, sha256: RUNNER_SOURCE_SHA256 });
  await writeChunk(stream, Buffer.from(`${runnerSource.length}\n${RUNNER_SOURCE_SHA256}\n`, 'ascii'));
  await writeChunk(stream, runnerSource);
  await writeChunk(stream, probeBytes);
  await writeChunk(stream, Buffer.from(`${metaBytes.length}\n${sha256(metaBytes)}\n`, 'ascii'));
  await writeChunk(stream, metaBytes);
  for (const file of bundle.files) {
    const bytes = Buffer.from(file.base64, 'base64');
    if (bytes.length !== file.bytes || sha256(bytes) !== file.sha256) fail('local materials entry changed before transport');
    await writeChunk(stream, bytes);
  }
  stream.end();
  return { meta, runnerSource };
}

async function execute(sourceBytes, probeBytes, bundle, nonce, mode = 'startup') {
  if (!['startup', 'capacity'].includes(mode)) fail('fixed execution mode rejected');
  const capacityMode = mode === 'capacity';
  const sessionMs = capacityMode ? CAPACITY_SESSION_MS : SESSION_MS;
  failureEvidence = { stage: 'transport', category: 'transport', exitCode: null, signal: null, stdoutBytes: 0, stderrBytes: 0, receiverFailure: null };
  const bootstrap = buildBootstrap(sourceBytes, probeBytes, mode);
  const remote = `/usr/sbin/pct exec 200 -- /usr/bin/python3 -I -B -c ${posixQuote(bootstrap)}`;
  readFixedFile(MATERIALS, 1024 * 1024, { sha256: MATERIALS_SHA256 });
  readFixedFile(MATERIALS_TEST, 1024 * 1024, { sha256: MATERIALS_TEST_SHA256 });
  readFixedFile(PROBE, 256 * 1024, { bytes: probeBytes.length, sha256: PROBE_SHA256 });
  readFixedFile(PYTHON, MAX_SOURCE, { bytes: sourceBytes.length, sha256: RUNNER_SOURCE_SHA256 });
  readFixedSsh();
  readFixedFile(SSH_KEY, 64 * 1024);
  readFixedFile(KNOWN_HOSTS, 1024 * 1024);
  const child = spawn(SSH, sshArgs(remote), {
    cwd: HERE, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'],
    env: { SystemRoot: 'C:/Windows', WINDIR: 'C:/Windows', ProgramData: 'C:/ProgramData', PATH: 'C:/Windows/System32;C:/Windows', LANG: 'C' },
  });
  const stdout = [];
  let stdoutBytes = 0, stderrBytes = 0;
  const stderr = [];
  let ended = false;
  const deadline = Date.now() + sessionMs;
  const timer = setTimeout(() => { try { child.kill(); } catch {} }, sessionMs);
  let closeResolve;
  let lifecycleReject;
  const closed = new Promise((resolve, reject) => { closeResolve = resolve; lifecycleReject = reject; });
  child.once('error', () => lifecycleReject(new Error('fixed SSH launch failed')));
  child.once('close', (exitCode, signal) => { failureEvidence.exitCode = exitCode; failureEvidence.signal = signal; closeResolve({ exitCode, signal }); });
  child.stdin.on('error', () => lifecycleReject(new Error('fixed SSH input failed')));
  let expiry;
  child.stdout.on('data', (chunk) => { stdoutBytes += chunk.length; failureEvidence.stdoutBytes = Math.min(MAX_STDOUT + 1, stdoutBytes); if (stdoutBytes > MAX_STDOUT) { failureEvidence.category = 'bounds'; try { child.kill(); } catch {} } else stdout.push(chunk); });
  child.stderr.on('data', (chunk) => { stderrBytes += chunk.length; failureEvidence.stderrBytes = Math.min(MAX_STDERR + 1, stderrBytes); if (stderrBytes > MAX_STDERR) { failureEvidence.category = 'bounds'; try { child.kill(); } catch {} } else stderr.push(chunk); });
  try {
    const send = transmitBundle(child.stdin, sourceBytes, probeBytes, bundle, nonce, mode);
    void send.catch(() => {});
    const timeout = new Promise((_, reject) => { expiry = setTimeout(() => { try { child.kill(); } catch {} reject(new Error('fixed SSH deadline expired')); }, Math.max(1, deadline - Date.now())); });
    const first = await Promise.race([send.then(() => ({ sent: true })), closed.then((result) => ({ result })), timeout]);
    if (first.result) {
      ended = true;
      fail('fixed SSH closed before the authenticated frame completed');
    }
    const result = await Promise.race([closed, timeout]);
    ended = true;
    if (result.signal !== null) { failureEvidence.category = 'signal'; fail('fixed SSH ended by signal'); }
    const code = result.exitCode;
    if (!ended || stdoutBytes > MAX_STDOUT || stderrBytes > MAX_STDERR) fail('fixed SSH bounded transport failed');
    const output = Buffer.concat(stdout);
    if (code !== 0) {
      failureEvidence.category = 'remote';
      failureEvidence.receiverFailure = parseFailureEnvelope(Buffer.concat(stderr));
      fail('fixed startup supervisor failed');
    }
    const expected = capacityMode ? { manifestSha256: bundle.manifestSha256, sourceManifestSha256: bundle.sourceManifestSha256,
      startupFreezeSha256: bundle.startupFreezeSha256, capacityFreezeSha256: bundle.capacityFreezeSha256 } :
      { manifestSha256: bundle.manifestSha256, sourceManifestSha256: bundle.sourceManifestSha256, startupFreezeSha256: bundle.startupFreezeSha256 };
    failureEvidence.stage = 'receipt';
    failureEvidence.category = 'receipt';
    const receipt = capacityMode ? validateCapacityRunReceipt(output, code, nonce, expected) : validateRunReceipt(output, code, nonce, expected);
    failureEvidence = { stage: 'complete', category: 'none', exitCode: 0, signal: null, stdoutBytes, stderrBytes, receiverFailure: null };
    return receipt;
  } catch (error) {
    try { child.kill(); } catch {}
    await Promise.race([closed.catch(() => {}), new Promise((resolve) => setTimeout(resolve, 2000))]);
    throw error;
  } finally { clearTimeout(timer); clearTimeout(expiry); }
}

export async function runStartup() {
  readFixedFile(SSH_KEY, 64 * 1024);
  readFixedFile(KNOWN_HOSTS, 1024 * 1024);
  readFixedFile(MATERIALS, 1024 * 1024, { sha256: MATERIALS_SHA256 });
  readFixedFile(MATERIALS_TEST, 1024 * 1024, { sha256: MATERIALS_TEST_SHA256 });
  const probeBytes = readFixedFile(PROBE, 256 * 1024, { sha256: PROBE_SHA256 });
  const runnerBytes = readFixedFile(PYTHON, MAX_SOURCE, { bytes: RUNNER_SOURCE_BYTES, sha256: RUNNER_SOURCE_SHA256 });
  const { buildMaterials } = await import('./materials.mjs');
  const bundle = buildMaterials();
  const bundleSummary = validateMaterialsBundle(bundle);
  const nonce = crypto.randomBytes(16).toString('hex');
  const pythonPin = { bytes: runnerBytes.length, sha256: sha256(runnerBytes) };
  if (pythonPin.bytes !== RUNNER_SOURCE_BYTES || bundleSummary.totalBytes > MAX_PAYLOAD) fail('fixed local source/dependency limit failed');
  return execute(runnerBytes, probeBytes, bundle, nonce);
}

export async function runCapacity() {
  readFixedFile(SSH_KEY, 64 * 1024);
  readFixedFile(KNOWN_HOSTS, 1024 * 1024);
  readFixedFile(MATERIALS, 1024 * 1024, { sha256: MATERIALS_SHA256 });
  readFixedFile(MATERIALS_TEST, 1024 * 1024, { sha256: MATERIALS_TEST_SHA256 });
  const probeBytes = readFixedFile(PROBE, 256 * 1024, { sha256: PROBE_SHA256 });
  readFixedFile(CAPACITY_VERIFIER, 1024 * 1024, { bytes: CAPACITY_VERIFIER_BYTES, sha256: CAPACITY_VERIFIER_SHA256 });
  const runnerBytes = readFixedFile(PYTHON, MAX_SOURCE, { bytes: RUNNER_SOURCE_BYTES, sha256: RUNNER_SOURCE_SHA256 });
  const { buildMaterials } = await import('./materials.mjs');
  const bundle = buildMaterials('capacity');
  const bundleSummary = validateMaterialsBundle(bundle, 'capacity');
  const nonce = crypto.randomBytes(16).toString('hex');
  if (runnerBytes.length !== RUNNER_SOURCE_BYTES || bundleSummary.totalBytes > MAX_PAYLOAD) fail('fixed capacity source/dependency limit failed');
  return execute(runnerBytes, probeBytes, bundle, nonce, 'capacity');
}

export const __test = Object.freeze({ validateMaterialsBundle, validateRunReceipt, validateCapacityRunReceipt, validateProbeReceipt,
  validateTerminalInventory, parseFailureEnvelope, buildBootstrap, posixQuote, canonicalWire, RUNNER_SOURCE_BYTES,
  RUNNER_SOURCE_SHA256, MAX_PAYLOAD, CAPACITY_FREEZE_SHA256, CAPACITY_PINS, CAPACITY_PINS_PATH,
  CAPACITY_VERIFIER_BYTES, CAPACITY_VERIFIER_SHA256, CAPACITY_OUTPUT, SESSION_MS, CAPACITY_SESSION_MS });

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  if (process.argv.length !== 3 || !['--run', '--capacity'].includes(process.argv[2])) {
    process.stderr.write('usage: node run-startup.mjs --run|--capacity\n');
    process.exitCode = 2;
  } else if (process.argv[2] === '--capacity') {
    try {
      failureEvidence = { stage: 'local', category: 'local', exitCode: null, signal: null, stdoutBytes: 0, stderrBytes: 0, receiverFailure: null };
      const receipt = await runCapacity();
      process.stdout.write(`${JSON.stringify(receipt)}\nisolated Linux runtime profile capacity tests passed\n`);
    } catch {
      const stage = ['local', 'transport', 'receipt'].includes(failureEvidence.stage) ? failureEvidence.stage : 'local';
      const category = ['local', 'transport', 'receipt', 'remote', 'signal', 'bounds'].includes(failureEvidence.category) ? failureEvidence.category : 'local';
      const exitCode = Number.isInteger(failureEvidence.exitCode) && failureEvidence.exitCode >= 0 && failureEvidence.exitCode <= 255 ? String(failureEvidence.exitCode) : 'unknown';
      const signal = typeof failureEvidence.signal === 'string' && /^SIG[A-Z0-9]+$/.test(failureEvidence.signal) ? failureEvidence.signal : 'none';
      const stdoutBytes = Number.isSafeInteger(failureEvidence.stdoutBytes) ? Math.min(MAX_STDOUT + 1, failureEvidence.stdoutBytes) : 0;
      const stderrBytes = Number.isSafeInteger(failureEvidence.stderrBytes) ? Math.min(MAX_STDERR + 1, failureEvidence.stderrBytes) : 0;
      const receiver = failureEvidence.receiverFailure;
      const receiverSummary = receiver ? ` receiver_stage=${receiver.stage} receiver_category=${receiver.category} receiver_unit=${receiver.unit} receiver_fixture=${receiver.fixture} receiver_scratch=${receiver.scratch} receiver_reason=${receiver.reason} receiver_exception=${receiver.exception} receiver_frame=${receiver.frame} receiver_line=${receiver.line} receiver_diagnostic=${receiver.diagnostic}` : '';
      process.stderr.write(`isolated capacity transaction failed stage=${stage} category=${category} exit=${exitCode} signal=${signal} stdout_bytes=${stdoutBytes} stderr_bytes=${stderrBytes}${receiverSummary}\n`);
      process.exitCode = 1;
    }
  } else {
    try {
      failureEvidence = { stage: 'local', category: 'local', exitCode: null, signal: null, stdoutBytes: 0, stderrBytes: 0, receiverFailure: null };
      const receipt = await runStartup();
      process.stdout.write(`${JSON.stringify(receipt)}\nisolated Linux startup tests passed\n`);
    } catch {
      const stage = ['local', 'transport', 'receipt'].includes(failureEvidence.stage) ? failureEvidence.stage : 'local';
      const category = ['local', 'transport', 'receipt', 'remote', 'signal', 'bounds'].includes(failureEvidence.category) ? failureEvidence.category : 'local';
      const exitCode = Number.isInteger(failureEvidence.exitCode) && failureEvidence.exitCode >= 0 && failureEvidence.exitCode <= 255 ? String(failureEvidence.exitCode) : 'unknown';
      const signal = typeof failureEvidence.signal === 'string' && /^SIG[A-Z0-9]+$/.test(failureEvidence.signal) ? failureEvidence.signal : 'none';
      const stdoutBytes = Number.isSafeInteger(failureEvidence.stdoutBytes) ? Math.min(MAX_STDOUT + 1, failureEvidence.stdoutBytes) : 0;
      const stderrBytes = Number.isSafeInteger(failureEvidence.stderrBytes) ? Math.min(MAX_STDERR + 1, failureEvidence.stderrBytes) : 0;
      const receiver = failureEvidence.receiverFailure;
      const receiverSummary = receiver ? ` receiver_stage=${receiver.stage} receiver_category=${receiver.category} receiver_unit=${receiver.unit} receiver_fixture=${receiver.fixture} receiver_scratch=${receiver.scratch} receiver_reason=${receiver.reason} receiver_exception=${receiver.exception} receiver_frame=${receiver.frame} receiver_line=${receiver.line} receiver_diagnostic=${receiver.diagnostic}` : '';
      process.stderr.write(`isolated startup transaction failed stage=${stage} category=${category} exit=${exitCode} signal=${signal} stdout_bytes=${stdoutBytes} stderr_bytes=${stderrBytes}${receiverSummary}\n`);
      process.exitCode = 1;
    }
  }
}
