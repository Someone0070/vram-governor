import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { __test } from './materials.mjs';

function entry(name, data) {
  const filename = Buffer.from(name, 'utf8');
  const body = Buffer.from(data);
  const crc = __test.crc32(body);
  const local = Buffer.alloc(30 + filename.length + body.length);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0x800, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(crc, 14);
  local.writeUInt32LE(body.length, 18);
  local.writeUInt32LE(body.length, 22);
  local.writeUInt16LE(filename.length, 26);
  filename.copy(local, 30);
  body.copy(local, 30 + filename.length);

  const central = Buffer.alloc(46 + filename.length);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(0x0314, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0x800, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt32LE(crc, 16);
  central.writeUInt32LE(body.length, 20);
  central.writeUInt32LE(body.length, 24);
  central.writeUInt16LE(filename.length, 28);
  filename.copy(central, 46);
  return { local, central };
}

function zip(namesAndData) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const [name, data] of namesAndData) {
    const item = entry(name, data);
    item.central.writeUInt32LE(offset, 42);
    locals.push(item.local);
    centrals.push(item.central);
    offset += item.local.length;
  }
  const centralBytes = Buffer.concat(centrals);
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(namesAndData.length, 8);
  end.writeUInt16LE(namesAndData.length, 10);
  end.writeUInt32LE(centralBytes.length, 12);
  end.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, centralBytes, end]);
}

function rejected(fn, label) {
  assert.throws(fn, undefined, label);
}

function fixtureStat(kind, overrides = {}) {
  return {
    dev: 7, ino: kind === 'directory' ? 11 : 12, mode: kind === 'directory' ? 0o40755 : 0o100644,
    size: kind === 'directory' ? 0 : 4, nlink: 1, mtimeMs: 100, ctimeMs: 100,
    isDirectory: () => kind === 'directory', isFile: () => kind === 'file', isSymbolicLink: () => kind === 'link',
    ...overrides,
  };
}

function custodyFixture(race = '') {
  const root = path.resolve('materials-custody-fixture');
  const parentPath = path.join(root, 'internal');
  const filePath = path.join(parentPath, 'source.go');
  const content = Buffer.from('test');
  let parentReads = 0, fileReads = 0, descriptorReads = 0, closed = false;
  const stableFile = fixtureStat('file');
  const changedFile = fixtureStat('file', { mtimeMs: 101 });
  const changedParent = fixtureStat('directory', { mtimeMs: 101 });
  const ops = {
    lstatSync(target) {
      if (target === parentPath) {
        parentReads += 1;
        return race === 'parent' && parentReads >= 3 ? changedParent : fixtureStat('directory');
      }
      if (target === filePath) {
        fileReads += 1;
        return stableFile;
      }
      throw new Error(`unexpected fixture path: ${target}`);
    },
    realpathSync(target) { return target; },
    openSync(target) { assert.equal(target, filePath); return 42; },
    fstatSync(fd) {
      assert.equal(fd, 42);
      descriptorReads += 1;
      if (race === 'descriptor-before' && descriptorReads === 1) return changedFile;
      if (race === 'descriptor-after' && descriptorReads === 2) return changedFile;
      return stableFile;
    },
    readSync(fd, destination, offset, length) {
      assert.equal(fd, 42);
      content.copy(destination, offset, 0, Math.min(length, content.length));
      return content.length;
    },
    closeSync(fd) { assert.equal(fd, 42); closed = true; },
  };
  return { root, ops, content, wasClosed: () => closed };
}

function verify() {
  const capacityFreezePath = path.resolve('.unlazy/fleet-residency-v2/observed-profile-repair31-freeze.json');
  const capacityFreeze = fs.readFileSync(capacityFreezePath);
  const capacitySources = new Map(Object.keys(__test.CAPACITY_PINS).map((name) => [name, fs.readFileSync(name)]));
  assert.equal(__test.validateCapacityFreezeData(capacityFreeze, capacitySources), __test.CAPACITY_FREEZE_SHA256,
    'capacity validator independently checks the fixed freeze and every pinned source');
  for (const mutate of [
    (bytes) => Buffer.concat([bytes, Buffer.from(' ') ]),
    (bytes) => { const copy = Buffer.from(bytes); copy[copy.length - 1] ^= 1; return copy; },
  ]) rejected(() => __test.validateCapacityFreezeData(mutate(capacityFreeze), capacitySources), 'altered capacity freeze');
  for (const [name, [size, digest]] of Object.entries(__test.CAPACITY_PINS)) {
    const altered = new Map(capacitySources);
    altered.set(name, Buffer.from('wrong pinned source'));
    rejected(() => __test.validateCapacityFreezeData(capacityFreeze, altered), `altered capacity source ${name}`);
    const missing = new Map(capacitySources);
    missing.delete(name);
    rejected(() => __test.validateCapacityFreezeData(capacityFreeze, missing), `missing capacity source ${name}`);
    assert.ok(size > 0 && /^[a-f0-9]{64}$/.test(digest));
  }
  rejected(() => __test.validateCapacityFreezeData(capacityFreeze, new Map()), 'capacity validator rejects absent source set');

  // Known-answer hash was computed independently from Go's documented Hash1
  // construction: SHA256("SHA256(hello\\n)  a.txt\\n"), base64 encoded.
  const expected = 'h1:xULs+l4jrMyt60GIZwYIw7bhbzwK3CkR1JyTboQZesk=';
  const data = Buffer.from('hello\n');
  assert.equal(__test.goHash1([{ name: 'a.txt', data }]), expected);

  const prefix = 'example.com/mod@v1.2.3/';
  const fixture = zip([[prefix, ''], [`${prefix}go.mod`, 'module example.com/mod\n']]);
  const correctHash = 'h1:fj9yIU5xHBkIDZHiG3x7TKxceqfLb6OwmYFJ00mFCBY=';
  const result = __test.verifyModuleZip(fixture, 'example.com/mod', 'v1.2.3', correctHash);
  assert.equal(result.entries.length, 2);
  assert.equal(result.entries[0].name, prefix);
  assert.equal(result.entries[1].name, `${prefix}go.mod`);
  assert.equal(result.hash, correctHash);

  const mixedPrefix = 'example.com/Mod@v1.2.3/';
  const mixedZip = zip([[mixedPrefix, ''], [`${mixedPrefix}go.mod`, 'module example.com/Mod\n'], [`${mixedPrefix}readme`, 'fixture\n']]);
  const mixedHash = 'h1:88x2qLFCXTyL2HGVXpYXu6BFeDFlCeLAvWoCFzVc5K4=';
  assert.equal(__test.verifyModuleZip(mixedZip, 'example.com/Mod', 'v1.2.3', mixedHash).hash, mixedHash);
  assert.equal(__test.escapeGoPath('example.com/Mod'), 'example.com/!mod');

  rejected(() => __test.verifyModuleZip(fixture, 'example.com/mod', 'v1.2.3', 'h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA='), 'bad module checksum');
  rejected(() => __test.parseZip(zip([['example.com/mod@v1.2.3/../escape.go', 'x']]), 'example.com/mod', 'v1.2.3'), 'traversal path');
  rejected(() => __test.parseZip(zip([['example.com/mod@v9.9.9/go.mod', 'x']]), 'example.com/mod', 'v1.2.3'), 'wrong module version path');
  rejected(() => __test.parseZip(zip([[`${prefix}dup.go`, 'one'], [`${prefix}dup.go`, 'two']]), 'example.com/mod', 'v1.2.3'), 'duplicate archive path');
  rejected(() => __test.parseZip(zip([[`${prefix}back\\slash.go`, 'x']]), 'example.com/mod', 'v1.2.3'), 'backslash path');

  const badOffset = Buffer.from(fixture);
  const endAt = badOffset.length - 22;
  badOffset.writeUInt32LE(0xffffffff, endAt + 16);
  rejected(() => __test.parseZip(badOffset, 'example.com/mod', 'v1.2.3'), 'malformed central offset');
  const badLength = Buffer.from(fixture);
  const centralAt = badLength.readUInt32LE(endAt + 16);
  badLength.writeUInt32LE(0xffffffff, centralAt + 20);
  rejected(() => __test.parseZip(badLength, 'example.com/mod', 'v1.2.3'), 'oversized entry length');

  const badCrc = Buffer.from(fixture);
  const localNameLength = badCrc.readUInt16LE(26);
  badCrc[30 + localNameLength] ^= 1;
  rejected(() => __test.parseZip(badCrc, 'example.com/mod', 'v1.2.3'), 'corrupt file body');
  rejected(() => __test.goHash1([{ name: '../x', data }]), 'invalid hash filename');
  rejected(() => __test.parseGoMod(Buffer.from('require (\nexample.com/m v1.0.0\n')), 'unterminated require block');
  rejected(() => __test.parseGoSum(Buffer.from('example.com/m v1.0.0 h1:bad\n')), 'bad go.sum digest');

  const goMod = Buffer.from('module example.com/project\ngo 1.23.4\nrequire (\nexample.com/a v1.2.3\n)\nrequire (\nexample.com/b v0.0.0-20240606120523-5a60cdf6a761 // indirect\n)\n');
  assert.equal(__test.parseGoMod(goMod).length, 2);
  for (const [text, label] of [
    ['module example.com/p\ngo 1.23.4\nrequire (\nexample.com/a v1.0.0 extra\n)\n', 'trailing require garbage'],
    ['module example.com/p\ngo 1.23.4\nrequire (\nrequire (\nexample.com/a v1.0.0\n)\n)\n', 'nested require block'],
    ['module example.com/p\ngo 1.23.4\nreplace example.com/a => example.com/b v1.0.0\n', 'unrecognized directive'],
    ['module example.com/p\ngo 1.23.4\nrequire example.com/a v1.0.0\nrequire example.com/a v1.0.0\n', 'duplicate requirement'],
    ['module example.com/p\ngo 1.23.4\nrequire example.com/a v1.0.0\nrequire example.com/a v1.1.0\n', 'duplicate path with distinct version'],
    ['module example.com/p\ngo 1.23.4\nrequire (\nexample.com/a v1.0.0\n', 'unterminated block'],
  ]) rejected(() => __test.parseGoMod(Buffer.from(text)), label);

  const stableCustody = custodyFixture();
  assert.deepEqual(__test.readFixedFile(stableCustody.root, 'internal/source.go', 128, stableCustody.ops), Buffer.from('test'));
  assert.equal(stableCustody.wasClosed(), true);
  for (const race of ['descriptor-before', 'descriptor-after', 'parent']) {
    const fixture = custodyFixture(race);
    rejected(() => __test.readFixedFile(fixture.root, 'internal/source.go', 128, fixture.ops), `${race} custody race`);
    assert.equal(fixture.wasClosed(), true);
  }

  // Positive control for the standard SHA construction independently checks
  // the per-file digest line before it reaches the production helper.
  const line = `${crypto.createHash('sha256').update(data).digest('hex')}  a.txt\n`;
  assert.equal(__test.goHash1([{ name: 'a.txt', data }]), `h1:${crypto.createHash('sha256').update(line).digest('base64')}`);
  process.stdout.write('authenticated Linux test materials controls passed\n');
}

if (process.argv.length !== 3 || process.argv[2] !== '--verify') {
  process.stderr.write('usage: materials.test.mjs --verify\n');
  process.exitCode = 1;
} else {
  try { verify(); } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}
