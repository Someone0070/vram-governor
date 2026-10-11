import fs from 'node:fs';
import crypto from 'node:crypto';
import net from 'node:net';
import { pathToFileURL } from 'node:url';

const fail = () => { throw new Error('isolation verification rejected'); };
const object = (v, keys) => {
  if (!v || typeof v !== 'object' || Array.isArray(v) ||
      Object.keys(v).sort().join(',') !== [...keys].sort().join(',')) fail();
};
const namespace = (s, kind) => typeof s === 'string' && new RegExp(`^${kind}:\\[[1-9][0-9]{0,19}\\]$`).test(s);
export function validateConfig(c) {
  object(c, ['schema', 'nonce', 'outsideRoot', 'outsidePort', 'outsideNamespaces', 'inputSha256']);
  if (c.schema !== 'lb-isolation-config-v1' || typeof c.nonce !== 'string' || !/^[a-f0-9]{32}$/.test(c.nonce) ||
      c.outsideRoot !== `/var/tmp/lb-test-run-${c.nonce}` || !Number.isInteger(c.outsidePort) || c.outsidePort < 1 || c.outsidePort > 65535 ||
      typeof c.inputSha256 !== 'string' || !/^[a-f0-9]{64}$/.test(c.inputSha256)) fail();
  object(c.outsideNamespaces, ['pid', 'mnt', 'net']);
  for (const k of ['pid', 'mnt', 'net']) if (!namespace(c.outsideNamespaces[k], k)) fail();
  return c;
}
export function validateFacts(c, f) {
  validateConfig(c);
  object(f, ['uid', 'gid', 'groups', 'caps', 'noNewPrivs', 'namespaces', 'initPidNamespace', 'pid', 'limits', 'inputSha256', 'writeControl', 'outsideAbsent', 'productionAbsent', 'rootUnavailable', 'gpuAbsent', 'inputReadonly', 'networkDenied']);
  for (const k of ['uid', 'gid']) if (!Array.isArray(f[k]) || f[k].length !== 4 || f[k].some(x => x !== 65534)) fail();
  if (!Array.isArray(f.groups) || f.groups.length !== 0 || f.noNewPrivs !== 1 || f.pid !== 1) fail();
  object(f.caps, ['Inh', 'Prm', 'Eff', 'Bnd', 'Amb']);
  for (const k of Object.keys(f.caps)) if (f.caps[k] !== '0000000000000000') fail();
  object(f.namespaces, ['pid', 'mnt', 'net']);
  for (const k of Object.keys(f.namespaces)) if (!namespace(f.namespaces[k], k) || f.namespaces[k] === c.outsideNamespaces[k]) fail();
  if (f.initPidNamespace !== f.namespaces.pid || f.inputSha256 !== c.inputSha256) fail();
  object(f.limits, ['memory.max', 'memory.swap.max', 'pids.max', 'cpu.max']);
  const expected = { 'memory.max': '2147483648', 'memory.swap.max': '0', 'pids.max': '128', 'cpu.max': '100000 100000' };
  for (const k of Object.keys(expected)) if (f.limits[k] !== expected[k]) fail();
  for (const k of ['writeControl', 'outsideAbsent', 'productionAbsent', 'rootUnavailable', 'gpuAbsent', 'inputReadonly', 'networkDenied']) if (f[k] !== true) fail();
  return { schema: 'lb-isolation-receipt-v1', nonce: c.nonce, inputSha256: f.inputSha256, pid: f.pid, namespaces: f.namespaces, limits: f.limits };
}
export function readBoundedDescriptor(fd, max, io = fs) {
  if (!Number.isSafeInteger(max) || max < 1 || max > 16384) fail();
  const b = Buffer.alloc(max + 1);
  let used = 0;
  while (used < b.length) {
    const n = io.readSync(fd, b, used, b.length - used, null);
    if (!Number.isInteger(n) || n < 0 || n > b.length - used) fail();
    if (n === 0) break;
    used += n;
  }
  if (used > max) fail();
  return b.subarray(0, used);
}
function readBounded(path, max) {
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try { return readBoundedDescriptor(fd, max); }
  finally { fs.closeSync(fd); }
}
function readRegular(path, max) {
  const fd = fs.openSync(path, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW);
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile() || st.size > max || st.uid !== 0 || (st.mode & 0o022) !== 0) fail();
    const b = readBoundedDescriptor(fd, max);
    const after = fs.fstatSync(fd);
    const named = fs.lstatSync(path);
    for (const key of ['dev','ino','mode','uid','gid','nlink','size','mtimeMs','ctimeMs'])
      if (after[key] !== st[key] || named[key] !== st[key]) fail();
    if (b.length !== st.size || b.length > max) fail();
    return b;
  } finally { fs.closeSync(fd); }
}
export function gpuDirectoryAbsent(directory) {
  let count = 0;
  for (;;) {
    const entry = directory.readSync();
    if (entry === null) return true;
    if (++count > 256 || typeof entry.name !== 'string' || entry.name.length > 255) fail();
    if (/^(nvidia|dri|kfd)/.test(entry.name)) return false;
  }
}
function absent(path) {
  try { fs.lstatSync(path); return false; }
  catch (e) { if (e.code === 'ENOENT') return true; fail(); }
}
export function rootUnavailable(io = fs) {
  const root = '/root';
  let before;
  try { before = io.lstatSync(root); }
  catch (e) {
    if (e.code !== 'ENOENT') fail();
    try { io.lstatSync(root); }
    catch (again) { if (again.code === 'ENOENT') return true; fail(); }
    fail();
  }
  const validDirectory = st => st && typeof st.isSymbolicLink === 'function' && !st.isSymbolicLink() &&
    typeof st.isDirectory === 'function' && st.isDirectory() && st.uid === 0 && st.gid === 0 &&
    (st.mode & 0o7777) === 0o750 && Number.isFinite(st.dev) && Number.isFinite(st.ino);
  const sameMetadata = (a, b) => ['dev', 'ino', 'mode', 'nlink', 'uid', 'gid', 'size', 'mtimeMs', 'ctimeMs']
    .every(key => a[key] === b[key]);
  if (!validDirectory(before)) fail();
  let handle;
  try { handle = io.opendirSync(root); }
  catch (e) {
    if (!['EACCES', 'EPERM'].includes(e.code)) fail();
    let after;
    try { after = io.lstatSync(root); } catch { fail(); }
    if (!validDirectory(after) || !sameMetadata(before, after)) fail();
    return true;
  }
  try { handle.closeSync(); }
  catch { fail(); }
  let after;
  try { after = io.lstatSync(root); } catch { fail(); }
  if (!validDirectory(after) || !sameMetadata(before, after)) fail();
  return false;
}
function deniedNetwork(port) {
  return new Promise(resolve => {
    const s = net.createConnection({host: '127.0.0.1', port});
    let settled = false;
    const end = value => { if (!settled) { settled = true; s.destroy(); resolve(value); } };
    s.setTimeout(500, () => end(true));
    s.on('connect', () => end(false));
    s.on('error', e => end(['ECONNREFUSED', 'ENETUNREACH', 'EHOSTUNREACH', 'EACCES', 'EPERM'].includes(e.code)));
  });
}
export async function probe() {
  if (process.platform !== 'linux' || process.pid !== 1) fail();
  const c = validateConfig(JSON.parse(readRegular('/probe-config.json', 2048).toString('utf8')));
  const status = readBounded('/proc/self/status', 16384).toString('utf8');
  const field = name => {
    const values = status.split('\n').filter(x => x.startsWith(`${name}:`));
    if (values.length !== 1) fail();
    return values[0].slice(name.length + 1).trim();
  };
  const ids = name => { const value = field(name); if (!/^[0-9]+\s+[0-9]+\s+[0-9]+\s+[0-9]+$/.test(value)) fail(); return value.split(/\s+/).map(Number); };
  const groups = field('Groups');
  const caps = Object.fromEntries(['Inh','Prm','Eff','Bnd','Amb'].map(k => [k, field(`Cap${k}`)]));
  const namespaces = Object.fromEntries(['pid','mnt','net'].map(k => [k, fs.readlinkSync(`/proc/self/ns/${k}`)]));
  const limits = Object.fromEntries(['memory.max','memory.swap.max','pids.max','cpu.max'].map(k => {
    const v = readBounded(`/.limits/${k}`, 64).toString('utf8'); return [k, v.trim()];
  }));
  const inputSha256 = crypto.createHash('sha256').update(readRegular('/proof-input.txt', 4096)).digest('hex');
  let inputReadonly = false;
  try { const fd = fs.openSync('/proof-input.txt', fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW); fs.closeSync(fd); }
  catch (e) { inputReadonly = ['EROFS', 'EACCES', 'EPERM'].includes(e.code); }
  // No write or truncation attempt is needed to disprove the writable-source boundary.
  const writePath = `/work/isolation-write-${c.nonce}`;
  const payload = Buffer.from(c.nonce);
  let writeControl = false;
  const fd = fs.openSync(writePath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR | fs.constants.O_NOFOLLOW, 0o600);
  try { fs.writeSync(fd, payload); fs.fsyncSync(fd); const got = Buffer.alloc(payload.length); fs.readSync(fd, got, 0, got.length, 0); writeControl = got.equals(payload); }
  finally { fs.closeSync(fd); fs.unlinkSync(writePath); }
  const dev = fs.opendirSync('/dev', {bufferSize: 1});
  let gpuAbsent;
  try { gpuAbsent = gpuDirectoryAbsent(dev); } finally { dev.closeSync(); }
  const f = {
    uid: ids('Uid'), gid: ids('Gid'), groups: groups === '' ? [] : groups.split(/\s+/).map(Number), caps,
    noNewPrivs: field('NoNewPrivs') === '1' ? 1 : 0, namespaces,
    initPidNamespace: fs.readlinkSync('/proc/1/ns/pid'), pid: process.pid, limits, inputSha256, writeControl,
    outsideAbsent: absent(c.outsideRoot) && absent(`${c.outsideRoot}/outside-control.txt`),
    productionAbsent: ['/etc/vram-governor','/run/systemd/private','/run/docker.sock','/var/lib/vram-governor','/models'].every(absent),
    // This proves only that /root is absent or blocked by its fixed root-owned 0750 placeholder;
    // it does not prove that the directory is empty or that no host mount is present.
    rootUnavailable: rootUnavailable(),
    gpuAbsent, inputReadonly,
    networkDenied: await deniedNetwork(c.outsidePort),
  };
  return validateFacts(c, f);
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv.length !== 3 || process.argv[2] !== '--probe') { process.stderr.write('probe usage rejected\n'); process.exitCode = 2; }
  else probe().then(r => { process.stdout.write(`${JSON.stringify(r)}\nisolation kernel controls passed\n`); }).catch(() => { process.stderr.write('isolation verification rejected\n'); process.exitCode = 1; });
}
