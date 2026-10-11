import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import zlib from 'node:zlib';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
const CACHE = path.resolve('C:/Users/Sasha/go/pkg/mod/cache/download');
const FREEZE = '.unlazy/fleet-residency-v2/startup-runtime-repair2-freeze.json';
const CAPACITY_FREEZE = '.unlazy/fleet-residency-v2/observed-profile-repair31-freeze.json';
const CAPACITY_FREEZE_BYTES = 6622;
const CAPACITY_FREEZE_SHA256 = '438df45ee3397c7ba1845f5b03738cae86028d001ed5a97f4918e1372f2652f5';
const STARTUP_FILES = [
  'internal/nodeagent/checkpoint_launch_plan.go',
  'internal/nodeagent/checkpoint_launch_plan_test.go',
  'internal/nodeagent/checkpoint_fixed_launcher.go',
  'internal/nodeagent/checkpoint_fixed_launcher_test.go',
  'scripts/verify-checkpoint-startup-runtime.mjs',
];
const CAPACITY_PINS = Object.freeze({
  'internal/workloads/manager.go': [411178, 'e661094ed488140743780e413c1dbe42197ae2aab99ddb1b3bb08041c29fe358'],
  'internal/workloads/manager_test.go': [290449, '2b7db9a3ed001330ddafc777788dd0e766508be01f426270fb0d9f009c887c8a'],
  'internal/workloads/residency.go': [112173, '341f55bd6a4e2ee374b8d38562bd5aeab93af1166bdac84db39208afdc53522e'],
  'internal/api/node_commands.go': [79097, '20047d49a8628c65c71efa23c6b3c627279783ed545046a51851e8c5187eb550'],
  'internal/api/node_commands_test.go': [80334, 'b77fec982aae8fc6595dbe05b1f3ed14fa38c570fd156478433493b5e5399bc2'],
  'internal/api/ws.go': [58722, '2a60e84306871a08e372c811d8e2edb82f24d33e94639de988b491be1ed10ead'],
  'internal/api/ws_test.go': [66923, 'a2334022efa245687a128c024e0e010640db1b2d7b15421c18ddb95f0744eed3'],
  'scripts/verify-runtime-profile-projection.mjs': [185643, 'a099d5e788a1461a78206700680b741075e35e9b701518e287721b1021fd0aa1'],
});
const CAPACITY_FILES = Object.freeze(Object.keys(CAPACITY_PINS));
const LIMITS = Object.freeze({
  sourceFiles: 4096, sourceBytes: 64 * 1024 * 1024,
  modules: 128, moduleFiles: 30000, moduleZip: 64 * 1024 * 1024,
  moduleExpanded: 192 * 1024 * 1024, totalBundle: 320 * 1024 * 1024,
  zipEntries: 20000, zipName: 4096, singleExpanded: 32 * 1024 * 1024,
});
const noFollow = fs.constants.O_NOFOLLOW ?? 0;

function fail(message) { throw new Error(message); }
function sha256(bytes) { return crypto.createHash('sha256').update(bytes).digest('hex'); }
function byteCompare(a, b) { return Buffer.compare(Buffer.from(a, 'utf8'), Buffer.from(b, 'utf8')); }
function sameStat(a, b) {
  return a.dev === b.dev && a.ino === b.ino && a.mode === b.mode && a.size === b.size &&
    a.nlink === b.nlink && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs;
}
function statSnapshot(stat) {
  return { dev: stat.dev, ino: stat.ino, mode: stat.mode, size: stat.size, nlink: stat.nlink, mtimeMs: stat.mtimeMs, ctimeMs: stat.ctimeMs };
}
function sameSnapshot(a, b) {
  return Boolean(a && b && a.dev === b.dev && a.ino === b.ino && a.mode === b.mode && a.size === b.size && a.nlink === b.nlink && a.mtimeMs === b.mtimeMs && a.ctimeMs === b.ctimeMs);
}

function assertCanonicalRoot(root) {
  const st = fs.lstatSync(root);
  if (!st.isDirectory() || st.isSymbolicLink() || fs.realpathSync(root) !== root) fail('fixed source root is not canonical');
}

function checkParents(root, relative, leafDirectory = false, ops = fs) {
  const parts = relative.split('/');
  if (!parts.length || parts.some((p) => !p || p === '.' || p === '..' || p.includes('\\') || /[\r\n\0]/.test(p))) fail('unsafe fixed path');
  let cursor = root;
  const count = leafDirectory ? parts.length : parts.length - 1;
  for (let i = 0; i < count; i += 1) {
    cursor = path.join(cursor, parts[i]);
    const st = ops.lstatSync(cursor);
    if (!st.isDirectory() || st.isSymbolicLink()) fail(`linked or non-directory parent: ${relative}`);
    if (ops.realpathSync(cursor) !== cursor) fail(`non-canonical parent: ${relative}`);
  }
  return path.join(root, ...parts);
}

function readFixedFile(root, relative, maxBytes, ops = fs, snapshot = undefined) {
  const absolute = checkParents(root, relative, false, ops);
  const parentPaths = [];
  let parent = root;
  const parts = relative.split('/');
  for (const part of parts.slice(0, -1)) {
    parent = path.join(parent, part);
    parentPaths.push({ path: parent, stat: ops.lstatSync(parent) });
  }
  const before = ops.lstatSync(absolute);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > maxBytes) fail(`invalid, linked, or oversized fixed file: ${relative}`);
  const fd = ops.openSync(absolute, fs.constants.O_RDONLY | noFollow);
  try {
    const opened = ops.fstatSync(fd);
    if (!opened.isFile() || !sameStat(before, opened)) fail(`file changed before descriptor read: ${relative}`);
    const data = Buffer.alloc(opened.size);
    let offset = 0;
    while (offset < data.length) {
      const n = ops.readSync(fd, data, offset, data.length - offset, offset);
      if (!n) fail(`short read: ${relative}`);
      offset += n;
    }
    const afterFd = ops.fstatSync(fd);
    const afterPath = ops.lstatSync(absolute);
    if (!sameStat(opened, afterFd) || !sameStat(opened, afterPath)) fail(`file changed during descriptor read: ${relative}`);
    if (ops.realpathSync(absolute) !== absolute) fail(`file path changed during read: ${relative}`);
    for (const item of parentPaths) {
      const current = ops.lstatSync(item.path);
      if (!current.isDirectory() || current.isSymbolicLink() || !sameStat(item.stat, current) || ops.realpathSync(item.path) !== item.path) fail(`parent changed during descriptor read: ${relative}`);
    }
    if (snapshot) {
      snapshot.file = statSnapshot(opened);
      snapshot.parents = parentPaths.map(({ path: parentPath, stat }) => ({ path: parentPath, stat: statSnapshot(stat) }));
    }
    return data;
  } finally { ops.closeSync(fd); }
}

function listGoFiles(root) {
  const out = [];
  let total = 0;
  function walk(rel) {
    const abs = rel ? checkParents(root, rel, true) : path.join(root, 'internal');
    const before = fs.lstatSync(abs);
    if (!before.isDirectory() || before.isSymbolicLink()) fail('internal source tree contains a linked directory');
    const names = fs.readdirSync(abs).sort(byteCompare);
    for (const name of names) {
      if (!name || name === '.' || name === '..' || name.includes('/') || name.includes('\\') || /[\r\n\0]/.test(name)) fail('invalid source entry name');
      const childRel = rel ? `${rel}/${name}` : `internal/${name}`;
      const childAbs = path.join(root, ...childRel.split('/'));
      const st = fs.lstatSync(childAbs);
      if (st.isSymbolicLink()) fail(`linked source entry: ${childRel}`);
      if (st.isDirectory()) walk(childRel);
      else if (st.isFile() && name.endsWith('.go')) {
        if (out.length >= LIMITS.sourceFiles || st.size > LIMITS.sourceBytes - total) fail('source inventory exceeds fixed limits');
        out.push(childRel);
        total += st.size;
      } else if (!st.isFile()) fail(`special source entry: ${childRel}`);
    }
    const after = fs.lstatSync(abs);
    const afterNames = fs.readdirSync(abs).sort(byteCompare);
    if (!sameStat(before, after) || names.length !== afterNames.length || names.some((name, index) => name !== afterNames[index])) fail(`source directory changed during traversal: ${rel || 'internal'}`);
  }
  walk('internal');
  return out.sort(byteCompare);
}

function escapeGoPath(value) {
  if (!value || /[\r\n\0]/.test(value) || value.includes('\\')) fail('invalid Go module identifier');
  return value.replace(/[A-Z]/g, (c) => `!${c.toLowerCase()}`);
}

function parseGoMod(bytes) {
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) fail('go.mod is not valid UTF-8');
  const modules = [];
  let inRequire = false;
  let sawModule = false;
  let sawGo = false;
  let sawRequire = false;
  const validModulePath = (value) => /^[A-Za-z0-9._~+!-]+(?:\/[A-Za-z0-9._~+!-]+)*$/.test(value) && value.split('/').every((part) => part && part !== '.' && part !== '..');
  const validVersion = (value) => /^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(value);
  const addRequirement = (line) => {
    const match = /^([^\s()]+)\s+(v[^\s()]+)$/.exec(line);
    if (!match || !validModulePath(match[1]) || !validVersion(match[2])) fail('malformed go.mod require entry');
    modules.push({ modulePath: match[1], version: match[2] });
  };
  for (const raw of text.split(/\r?\n/)) {
    const trimmed = raw.trim();
    if (!trimmed || trimmed.startsWith('//')) continue;
    const commentAt = raw.indexOf('//');
    const comment = commentAt >= 0 ? raw.slice(commentAt).trim() : '';
    const line = (commentAt >= 0 ? raw.slice(0, commentAt) : raw).trim();
    if (!line) continue;
    if (inRequire) {
      if (line === ')') { inRequire = false; continue; }
      if (/^(require|module|go)\b/.test(line) || line === '(' || line.includes('(') || line.includes(')')) fail('nested or malformed go.mod require block');
      if (comment && comment !== '// indirect') fail('unsupported go.mod require annotation');
      addRequirement(line);
      continue;
    }
    if (line.startsWith('module ')) {
      const match = /^module\s+([^\s()]+)$/.exec(line);
      if (sawModule || sawGo || sawRequire || !match || !validModulePath(match[1])) fail('malformed or misplaced go.mod module directive');
      sawModule = true;
      continue;
    }
    if (line.startsWith('go ')) {
      const match = /^go\s+(\d+\.\d+(?:\.\d+)?)$/.exec(line);
      if (!sawModule || sawGo || sawRequire || !match) fail('malformed or misplaced go.mod go directive');
      sawGo = true;
      continue;
    }
    if (line === 'require (') {
      if (!sawModule || !sawGo) fail('malformed or misplaced go.mod require block');
      inRequire = true;
      sawRequire = true;
      continue;
    }
    if (line.startsWith('require ')) {
      if (!sawModule || !sawGo || comment && comment !== '// indirect') fail('malformed or misplaced go.mod require directive');
      addRequirement(line.slice('require '.length));
      sawRequire = true;
      continue;
    }
    fail('unsupported or malformed go.mod directive');
  }
  if (inRequire || !sawModule || !sawGo || !sawRequire || modules.length === 0 || modules.length > LIMITS.modules) fail('go.mod require inventory is incomplete or exceeds limits');
  const seen = new Set();
  for (const m of modules) {
    const k = m.modulePath;
    if (seen.has(k)) fail('duplicate module requirement');
    seen.add(k);
  }
  return modules.sort((a, b) => byteCompare(a.modulePath, b.modulePath) || byteCompare(a.version, b.version));
}

function parseGoSum(bytes) {
  const text = bytes.toString('utf8');
  if (!Buffer.from(text, 'utf8').equals(bytes)) fail('go.sum is not valid UTF-8');
  const sums = new Map();
  for (const line of text.split(/\r?\n/)) {
    if (!line) continue;
    const match = /^([^\s]+)\s+(v[^\s]+)\s+(h1:[A-Za-z0-9+/]{43}=)$/.exec(line);
    if (!match) fail('go.sum contains an unsupported or malformed line');
    const key = `${match[1]}\0${match[2]}`;
    if (sums.has(key)) fail('go.sum contains a duplicate checksum');
    sums.set(key, match[3]);
  }
  return sums;
}

function goHash1(files) {
  if (!Array.isArray(files) || files.length > LIMITS.zipEntries) fail('invalid Go hash file inventory');
  const names = new Set();
  const ordered = [...files].sort((a, b) => byteCompare(a.name, b.name));
  const lines = [];
  for (const item of ordered) {
    if (typeof item.name !== 'string' || !Buffer.isBuffer(item.data) || !safeZipEntryName(item.name) || names.has(item.name)) fail('invalid Go hash file entry');
    names.add(item.name);
    lines.push(`${sha256(item.data)}  ${item.name}\n`);
  }
  return `h1:${crypto.createHash('sha256').update(lines.join(''), 'utf8').digest('base64')}`;
}

function safeZipName(name) {
  if (!name || name.length > LIMITS.zipName || name.startsWith('/') || name.startsWith('\\') || name.includes('\\') || /[\r\n\0]/.test(name) || /^[A-Za-z]:/.test(name)) return false;
  const parts = name.split('/');
  return parts.every((part, i) => part && part !== '.' && part !== '..' && !(i === parts.length - 1 && part === ''));
}

function safeZipEntryName(name) {
  if (typeof name !== 'string' || !name || name.length > LIMITS.zipName || name.startsWith('/') || name.startsWith('\\') || name.includes('\\') || /[\r\n\0]/.test(name) || /^[A-Za-z]:/.test(name)) return false;
  const directory = name.endsWith('/');
  const body = directory ? name.slice(0, -1) : name;
  if (!body) return directory;
  return body.split('/').every((part) => part && part !== '.' && part !== '..');
}

function crc32(buffer) {
  let c = 0xffffffff;
  for (const byte of buffer) {
    c ^= byte;
    for (let i = 0; i < 8; i += 1) c = (c >>> 1) ^ (0xedb88320 & -(c & 1));
  }
  return (c ^ 0xffffffff) >>> 0;
}

function parseZip(zip, modulePath, version) {
  if (!Buffer.isBuffer(zip) || zip.length < 22 || zip.length > LIMITS.moduleZip) fail('invalid or oversized module ZIP');
  const min = Math.max(0, zip.length - 22 - 65535);
  let eocd = -1;
  for (let i = zip.length - 22; i >= min; i -= 1) if (zip.readUInt32LE(i) === 0x06054b50) { eocd = i; break; }
  if (eocd < 0) fail('ZIP end record is missing');
  const disk = zip.readUInt16LE(eocd + 4), cdDisk = zip.readUInt16LE(eocd + 6);
  const diskEntries = zip.readUInt16LE(eocd + 8), count = zip.readUInt16LE(eocd + 10);
  const cdSize = zip.readUInt32LE(eocd + 12), cdOffset = zip.readUInt32LE(eocd + 16), commentLen = zip.readUInt16LE(eocd + 20);
  if (disk || cdDisk || diskEntries !== count || count === 0 || count > LIMITS.zipEntries || cdOffset + cdSize !== eocd || eocd + 22 + commentLen !== zip.length || count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) fail('multi-disk, ZIP64, or malformed ZIP directory');
  const prefix = `${modulePath}@${version}/`;
  let p = cdOffset;
  const seen = new Set();
  const ranges = [];
  const out = [];
  let expandedTotal = 0;
  for (let index = 0; index < count; index += 1) {
    if (p + 46 > eocd || zip.readUInt32LE(p) !== 0x02014b50) fail('malformed ZIP central header');
    const madeBy = zip.readUInt16LE(p + 4);
    const flags = zip.readUInt16LE(p + 8), method = zip.readUInt16LE(p + 10);
    const crc = zip.readUInt32LE(p + 16), compressed = zip.readUInt32LE(p + 20), uncompressed = zip.readUInt32LE(p + 24);
    const nameLen = zip.readUInt16LE(p + 28), extraLen = zip.readUInt16LE(p + 30), comment = zip.readUInt16LE(p + 32);
    const diskNo = zip.readUInt16LE(p + 34), external = zip.readUInt32LE(p + 38), localOffset = zip.readUInt32LE(p + 42);
    const end = p + 46 + nameLen + extraLen + comment;
    if (end > eocd || diskNo || !nameLen || nameLen > LIMITS.zipName || compressed === 0xffffffff || uncompressed === 0xffffffff || localOffset === 0xffffffff || (flags & 1) || (flags & ~0x080e) || ![0, 8].includes(method)) fail('unsupported or malformed ZIP entry metadata');
    const nameBytes = zip.subarray(p + 46, p + 46 + nameLen);
    const name = (flags & 0x800) ? new TextDecoder('utf-8', { fatal: true }).decode(nameBytes) : nameBytes.toString('utf8');
    const isDirectory = name.endsWith('/');
    if (!Buffer.from(name, 'utf8').equals(nameBytes) || !safeZipEntryName(name) || !name.startsWith(prefix) || (!isDirectory && name.length <= prefix.length) || (name.length === prefix.length && !isDirectory)) fail('unsafe or unexpected module ZIP path');
    const rel = name.slice(prefix.length);
    if (seen.has(name)) fail('duplicate module ZIP path');
    seen.add(name);
    const unixMode = (madeBy >> 8) === 3 ? (external >>> 16) & 0xffff : 0;
    const type = unixMode & 0xf000;
    const dosDirectory = Boolean(external & 0x10);
    if ((type && type !== (isDirectory ? 0x4000 : 0x8000)) || (dosDirectory !== isDirectory && (madeBy & 0xff00) === 0) || (type && (type === 0x4000) !== isDirectory)) fail('non-regular module ZIP entry');
    for (let x = p + 46 + nameLen; x < p + 46 + nameLen + extraLen;) {
      if (x + 4 > p + 46 + nameLen + extraLen) fail('malformed ZIP extra field');
      const id = zip.readUInt16LE(x), n = zip.readUInt16LE(x + 2); x += 4;
      if (x + n > p + 46 + nameLen + extraLen || id === 0x0001) fail('malformed or ZIP64 extra field');
      x += n;
    }
    if (localOffset + 30 > cdOffset || zip.readUInt32LE(localOffset) !== 0x04034b50) fail('invalid ZIP local header offset');
    const localFlags = zip.readUInt16LE(localOffset + 6), localMethod = zip.readUInt16LE(localOffset + 8);
    const localCrc = zip.readUInt32LE(localOffset + 14), localComp = zip.readUInt32LE(localOffset + 18), localUncomp = zip.readUInt32LE(localOffset + 22);
    const localNameLen = zip.readUInt16LE(localOffset + 26), localExtraLen = zip.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + localNameLen + localExtraLen, dataEnd = dataStart + compressed;
    const localExtraEnd = localOffset + 30 + localNameLen + localExtraLen;
    if (localExtraEnd > cdOffset || dataStart > cdOffset || dataEnd > cdOffset || localFlags !== flags || localMethod !== method || localNameLen !== nameLen || !zip.subarray(localOffset + 30, localOffset + 30 + localNameLen).equals(nameBytes)) fail('local and central ZIP headers disagree');
    for (let x = localOffset + 30 + localNameLen; x < localExtraEnd;) {
      if (x + 4 > localExtraEnd) fail('malformed ZIP local extra field');
      const id = zip.readUInt16LE(x), n = zip.readUInt16LE(x + 2); x += 4;
      if (x + n > localExtraEnd || id === 0x0001) fail('malformed or ZIP64 local extra field');
      x += n;
    }
    const descriptor = flags & 8;
    if (!descriptor && (localCrc !== crc || localComp !== compressed || localUncomp !== uncompressed)) fail('ZIP local size or checksum mismatch');
    if (descriptor && ((localCrc && localCrc !== crc) || (localComp && localComp !== compressed) || (localUncomp && localUncomp !== uncompressed))) fail('ZIP descriptor metadata conflicts with local header');
    if (uncompressed > LIMITS.singleExpanded || uncompressed > LIMITS.moduleExpanded - expandedTotal) fail('module ZIP expansion limit exceeded');
    const packed = zip.subarray(dataStart, dataEnd);
    let data;
    try {
      data = method === 0 ? Buffer.from(packed) : zlib.inflateRawSync(packed, { maxOutputLength: Math.min(LIMITS.singleExpanded, uncompressed + 1) });
    } catch { fail('module ZIP deflate stream is invalid or exceeds bound'); }
    if (data.length !== uncompressed || crc32(data) !== crc) fail('module ZIP uncompressed size or CRC mismatch');
    if (descriptor) {
      let d = dataEnd;
      if (d + 4 <= cdOffset && zip.readUInt32LE(d) === 0x08074b50) d += 4;
      if (d + 12 > cdOffset || zip.readUInt32LE(d) !== crc || zip.readUInt32LE(d + 4) !== compressed || zip.readUInt32LE(d + 8) !== uncompressed) fail('invalid ZIP data descriptor');
      ranges.push([localOffset, d + 12]);
    } else {
      ranges.push([localOffset, dataEnd]);
    }
    expandedTotal += uncompressed;
    if (isDirectory) {
      if (uncompressed !== 0 || crc !== 0 || data.length !== 0) fail('module ZIP directory entry contains data');
    }
    out.push({ name, data });
    p = end;
  }
  if (p !== cdOffset + cdSize) fail('ZIP central directory length mismatch');
  ranges.sort((a, b) => a[0] - b[0]);
  if (!ranges.length || ranges[0][0] !== 0) fail('ZIP has an unaccounted prefix');
  for (let i = 1; i < ranges.length; i += 1) if (ranges[i][0] !== ranges[i - 1][1]) fail('overlapping or unaccounted ZIP local data');
  if (ranges.at(-1)[1] !== cdOffset) fail('ZIP has unaccounted data before its central directory');
  return out;
}

function verifyModuleZip(zip, modulePath, version, expected) {
  const entries = parseZip(zip, modulePath, version);
  const actual = goHash1(entries);
  if (actual !== expected) fail(`cached module ZIP does not match go.sum for ${modulePath}@${version}`);
  return { entries, hash: actual };
}

function readCacheFile(relative, max) { return readFixedFile(CACHE, relative, max); }

function sourceManifest(files) {
  return JSON.stringify(files.map(({ path: p, data }) => ({ path: p, bytes: data.length, sha256: sha256(data) })));
}

function addBundleFile(files, relative, data, budget) {
  if (files.length >= LIMITS.moduleFiles || data.length > budget.remaining) fail('material bundle exceeds fixed file or byte limits');
  files.push({ path: relative, bytes: data.length, sha256: sha256(data), base64: data.toString('base64') });
  budget.remaining -= data.length;
}

function validateFreeze(root, sourceByPath) {
  const bytes = readFixedFile(root, FREEZE, 1024 * 1024);
  let freeze;
  try { freeze = JSON.parse(bytes.toString('utf8')); } catch { fail('startup freeze manifest is malformed'); }
  if (!freeze || !Array.isArray(freeze.files)) fail('startup freeze manifest lacks a file inventory');
  const entries = new Map();
  for (const item of freeze.files) {
    if (!item || typeof item.path !== 'string' || !Number.isSafeInteger(item.bytes) || !/^[a-f0-9]{64}$/.test(item.sha256) || entries.has(item.path)) fail('startup freeze manifest entry is malformed');
    entries.set(item.path, item);
  }
  if (entries.size !== STARTUP_FILES.length || STARTUP_FILES.some((p) => !entries.has(p))) fail('startup freeze manifest does not pin the exact startup file set');
  for (const p of STARTUP_FILES) {
    const data = sourceByPath.get(p);
    const item = entries.get(p);
    if (!data || data.length !== item.bytes || sha256(data) !== item.sha256) fail(`startup pin mismatch: ${p}`);
  }
  return sha256(bytes);
}

function validateCapacityFreezeData(bytes, sourceByPath) {
  if (!Buffer.isBuffer(bytes) || bytes.length !== CAPACITY_FREEZE_BYTES || sha256(bytes) !== CAPACITY_FREEZE_SHA256) fail('capacity freeze pin failed');
  let freeze;
  try { freeze = JSON.parse(bytes.toString('utf8')); } catch { fail('capacity freeze manifest is malformed'); }
  if (!freeze || !Array.isArray(freeze.files) || freeze.files.length !== CAPACITY_FILES.length) fail('capacity freeze inventory failed');
  const rows = new Map();
  for (const item of freeze.files) {
    if (!item || typeof item.path !== 'string' || !Number.isSafeInteger(item.bytes) || typeof item.sha256 !== 'string' ||
        !/^[a-f0-9]{64}$/.test(item.sha256) || rows.has(item.path)) fail('capacity freeze entry is malformed');
    rows.set(item.path, item);
  }
  if (rows.size !== CAPACITY_FILES.length || CAPACITY_FILES.some((name) => !rows.has(name))) fail('capacity freeze path set failed');
  for (const name of CAPACITY_FILES) {
    const [size, digest] = CAPACITY_PINS[name];
    const item = rows.get(name);
    const data = sourceByPath.get(name);
    if (item.bytes !== size || item.sha256 !== digest || !data || data.length !== size || sha256(data) !== digest) fail(`capacity source pin mismatch: ${name}`);
  }
  return CAPACITY_FREEZE_SHA256;
}

export function buildMaterials(mode = 'startup') {
  if (!['startup', 'capacity'].includes(mode)) fail('unsupported materials mode');
  const capacityMode = mode === 'capacity';
  assertCanonicalRoot(ROOT);
  assertCanonicalRoot(CACHE);
  const rootSnapshot = statSnapshot(fs.lstatSync(ROOT));
  const sourceSnapshots = new Map();
  const goModSnapshot = {};
  const goSumSnapshot = {};
  const freezeSnapshot = {};
  const capacityFreezeSnapshot = {};
  const goMod = readFixedFile(ROOT, 'go.mod', 2 * 1024 * 1024, fs, goModSnapshot);
  const goSum = readFixedFile(ROOT, 'go.sum', 8 * 1024 * 1024, fs, goSumSnapshot);
  const freezeData = readFixedFile(ROOT, FREEZE, 1024 * 1024, fs, freezeSnapshot);
  const capacityFreezeData = capacityMode ? readFixedFile(ROOT, CAPACITY_FREEZE, CAPACITY_FREEZE_BYTES, fs, capacityFreezeSnapshot) : null;
  sourceSnapshots.set('go.mod', goModSnapshot);
  sourceSnapshots.set('go.sum', goSumSnapshot);
  let freeze;
  try { freeze = JSON.parse(freezeData.toString('utf8')); } catch { fail('startup freeze manifest is malformed'); }
  if (!freeze || !Array.isArray(freeze.files)) fail('startup freeze manifest lacks a file inventory');
  const expectedStartup = new Map(freeze.files.map((item) => [item.path, item]));
  if (expectedStartup.size !== STARTUP_FILES.length || STARTUP_FILES.some((p) => !expectedStartup.has(p))) fail('startup freeze manifest does not pin exact required files');
  const goFiles = listGoFiles(ROOT);
  const sourcePaths = [...new Set(['go.mod', 'go.sum', ...goFiles, ...STARTUP_FILES, ...(capacityMode ? CAPACITY_FILES : [])])].sort(byteCompare);
  if (sourcePaths.length > LIMITS.sourceFiles + 16) fail('source inventory exceeds file limit');
  const sourceFiles = [];
  const sourceByPath = new Map([['go.mod', goMod], ['go.sum', goSum]]);
  let sourceTotal = goMod.length + goSum.length;
  for (const relative of sourcePaths) {
    let data = sourceByPath.get(relative);
    if (!data) {
      const snapshot = {};
      data = readFixedFile(ROOT, relative, LIMITS.sourceBytes, fs, snapshot);
      sourceSnapshots.set(relative, snapshot);
    }
    sourceByPath.set(relative, data);
    if (relative !== 'go.mod' && relative !== 'go.sum') {
      sourceTotal += data.length;
      if (sourceTotal > LIMITS.sourceBytes) fail('source snapshot exceeds byte limit');
    }
    sourceFiles.push({ path: relative, data });
  }
  const startupFreezeSha256 = validateFreeze(ROOT, sourceByPath);
  if (startupFreezeSha256 !== sha256(freezeData)) fail('startup freeze manifest changed during pin validation');
  const capacityFreezeSha256 = capacityMode ? validateCapacityFreezeData(capacityFreezeData, sourceByPath) : null;
  const modules = parseGoMod(goMod);
  const sums = parseGoSum(goSum);
  const files = [];
  const budget = { remaining: LIMITS.totalBundle };
  for (const item of sourceFiles) addBundleFile(files, `source/${item.path}`, item.data, budget);
  const moduleInventory = [];
  for (const { modulePath, version } of modules) {
    const zipSum = sums.get(`${modulePath}\0${version}`);
    const modSum = sums.get(`${modulePath}\0${version}/go.mod`);
    if (!zipSum || !modSum) fail(`go.sum lacks ZIP or go.mod authentication for ${modulePath}@${version}`);
    const escaped = `${escapeGoPath(modulePath)}/@v/${escapeGoPath(version)}`;
    const zip = readCacheFile(`${escaped}.zip`, LIMITS.moduleZip);
    const mod = readCacheFile(`${escaped}.mod`, 8 * 1024 * 1024);
    const info = readCacheFile(`${escaped}.info`, 64 * 1024);
    let infoJson;
    try { infoJson = JSON.parse(info.toString('utf8')); } catch { fail(`cached module info is malformed for ${modulePath}@${version}`); }
    if (!infoJson || infoJson.Version !== version || typeof infoJson.Time !== 'string' || !Number.isFinite(Date.parse(infoJson.Time))) fail(`cached module info version mismatch for ${modulePath}@${version}`);
    if (goHash1([{ name: 'go.mod', data: mod }]) !== modSum) fail(`cached module go.mod does not match go.sum for ${modulePath}@${version}`);
    const verified = verifyModuleZip(zip, modulePath, version, zipSum);
    const generatedZipHash = Buffer.from(`${verified.hash}\n`, 'utf8');
    addBundleFile(files, `modules/${escaped}.zip`, zip, budget);
    addBundleFile(files, `modules/${escaped}.mod`, mod, budget);
    addBundleFile(files, `modules/${escaped}.info`, info, budget);
    addBundleFile(files, `modules/${escaped}.ziphash`, generatedZipHash, budget);
    moduleInventory.push({ modulePath, version, files: verified.entries.length, bytes: zip.length, goHash1: verified.hash });
  }
  const finalGoFiles = listGoFiles(ROOT);
  if (finalGoFiles.length !== goFiles.length || finalGoFiles.some((relative, index) => relative !== goFiles[index])) fail('source inventory changed during dependency authentication');
  for (const relative of sourcePaths) {
    const original = sourceByPath.get(relative);
    const initial = sourceSnapshots.get(relative);
    const currentSnapshot = {};
    const current = readFixedFile(ROOT, relative, LIMITS.sourceBytes, fs, currentSnapshot);
    if (!original.equals(current) || !sameSnapshot(initial.file, currentSnapshot.file) || initial.parents.length !== currentSnapshot.parents.length || initial.parents.some((item, index) => item.path !== currentSnapshot.parents[index].path || !sameSnapshot(item.stat, currentSnapshot.parents[index].stat))) fail(`source changed during dependency authentication: ${relative}`);
  }
  const finalFreezeSnapshot = {};
  const finalFreeze = readFixedFile(ROOT, FREEZE, 1024 * 1024, fs, finalFreezeSnapshot);
  if (!freezeData.equals(finalFreeze) || !sameSnapshot(freezeSnapshot.file, finalFreezeSnapshot.file) || freezeSnapshot.parents.length !== finalFreezeSnapshot.parents.length || freezeSnapshot.parents.some((item, index) => item.path !== finalFreezeSnapshot.parents[index].path || !sameSnapshot(item.stat, finalFreezeSnapshot.parents[index].stat))) fail('startup freeze manifest changed during dependency authentication');
  if (capacityMode) {
    const finalCapacityFreezeSnapshot = {};
    const finalCapacityFreeze = readFixedFile(ROOT, CAPACITY_FREEZE, CAPACITY_FREEZE_BYTES, fs, finalCapacityFreezeSnapshot);
    if (!capacityFreezeData.equals(finalCapacityFreeze) || !sameSnapshot(capacityFreezeSnapshot.file, finalCapacityFreezeSnapshot.file) ||
        capacityFreezeSnapshot.parents.length !== finalCapacityFreezeSnapshot.parents.length ||
        capacityFreezeSnapshot.parents.some((item, index) => item.path !== finalCapacityFreezeSnapshot.parents[index].path || !sameSnapshot(item.stat, finalCapacityFreezeSnapshot.parents[index].stat))) fail('capacity freeze manifest changed during dependency authentication');
  }
  if (!sameSnapshot(rootSnapshot, statSnapshot(fs.lstatSync(ROOT)))) fail('source root metadata changed during dependency authentication');
  files.sort((a, b) => byteCompare(a.path, b.path));
  const manifest = JSON.stringify(files.map(({ path: p, bytes, sha256: hash }) => ({ path: p, bytes, sha256: hash })));
  const result = {
    schema: 1,
    files: Object.freeze(files.map((entry) => Object.freeze(entry))),
    manifestSha256: sha256(Buffer.from(manifest, 'utf8')),
    sourceManifestSha256: sha256(Buffer.from(sourceManifest(sourceFiles), 'utf8')),
    startupFreezeSha256,
    sourceCount: sourceFiles.length,
    moduleCount: moduleInventory.length,
    moduleInventory: Object.freeze(moduleInventory),
  };
  return Object.freeze(capacityMode ? { ...result, schema: 'ct200-capacity-materials-v1', mode: 'capacity', capacityFreezeSha256 } : result);
}

export const __test = Object.freeze({ goHash1, parseZip, verifyModuleZip, parseGoMod, parseGoSum, escapeGoPath, safeZipName, safeZipEntryName, readFixedFile, crc32, LIMITS,
  CAPACITY_FREEZE_BYTES, CAPACITY_FREEZE_SHA256, CAPACITY_PINS, validateCapacityFreezeData });

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 3 || process.argv[2] !== '--inspect') fail('usage: materials.mjs --inspect');
    const bundle = buildMaterials();
    process.stdout.write(`authenticated Linux test materials ready: source=${bundle.sourceCount} modules=${bundle.moduleCount} bytes=${bundle.files.reduce((n, f) => n + f.bytes, 0)} manifest=${bundle.manifestSha256}\n`);
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
