import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import { pathToFileURL } from "node:url";
import { _fixedSshToolForTest } from "../controller-hotfix/command-fence.mjs";
import { buildBootstrap, parseReceipt, posixQuote, RECEIVER_BYTES, RECEIVER_SHA256, verifyFixedSshBytes } from "./prepare-tools.mjs";

function sha(bytes) { return crypto.createHash("sha256").update(bytes).digest("hex"); }
function expectThrow(fn) { assert.throws(fn); }

function receipt() {
  const hash = "a".repeat(64);
  return Buffer.from(JSON.stringify({
    schema: "ct200-private-tools-v1",
    status: "staged",
    path: "/var/tmp/lb-verification-tools-ab12_cd34",
    go_archive_sha256: "6924efde5de86fe277676e929dc9917d466efa02fb934197bc2eba35d5680971",
    node_archive_sha256: "9d942932535988091034dc94cc5f42b6dc8784d6366df3a36c4c9ccb3996f0c2",
    go_tree_entries: 100,
    go_files_bytes: 100000,
    go_tree_sha256: hash,
    node_bytes: 120177224,
    node_file_sha256: "b".repeat(64),
    units_before_sha256: hash,
    units_after_sha256: hash,
    downloaded_tools_executed: false,
    production_units_unchanged: true,
  }) + "\nCT200_TOOLS_STAGED\n", "ascii");
}

function fixedSshFixture(bytes) {
  const names = [
    "C:/Windows/System32/OpenSSH/ssh.exe",
    "C:/Windows/WinSxS/amd64_openssh-client-components-onecore_31bf3856ad364e35_10.0.26100.9549_none_9bb78eedccaa8631/ssh.exe",
  ];
  const metadata = names.map((_, i) => ({
    dev: 7n, ino: 11n, mode: 0o100755n, nlink: 2n, uid: 1000n, gid: 1000n,
    size: BigInt(bytes.length), mtimeNs: 13n, ctimeNs: 17n,
    isFile: () => true, isSymbolicLink: () => false, isDirectory: () => false, index: i,
  }));
  const fdOffsets = new Map();
  let nextFd = 100;
  const facade = {
    constants: { O_RDONLY: 0, O_NOFOLLOW: 0 },
    lstatSync(name) {
      const index = names.indexOf(name);
      if (index < 0) return { isDirectory: () => true, isSymbolicLink: () => false };
      return metadata[index];
    },
    openSync(name) {
      const index = names.indexOf(name);
      if (index < 0) throw new Error("unexpected path");
      const fd = nextFd++;
      fdOffsets.set(fd, { index, offset: 0 });
      return fd;
    },
    fstatSync(fd) { return metadata[fdOffsets.get(fd).index]; },
    readSync(fd, buffer, offset, length) {
      const state = fdOffsets.get(fd);
      if (!state) throw new Error("unexpected fd");
      const count = Math.min(length, Math.max(0, bytes.length - state.offset));
      bytes.copy(buffer, offset, state.offset, state.offset + count);
      state.offset += count;
      return count;
    },
    closeSync(fd) { fdOffsets.delete(fd); },
  };
  return facade;
}

function verify() {
  const receiverBytes = fs.readFileSync(new URL("./prepare-tools.py", import.meta.url));
  assert.equal(receiverBytes.length, RECEIVER_BYTES, "production receiver length pin matches its source");
  assert.equal(sha(receiverBytes), RECEIVER_SHA256, "production receiver digest pin matches its source");
  const bootstrap = buildBootstrap(receiverBytes);
  assert.ok(bootstrap.includes(`int(n)!=${RECEIVER_BYTES}`));
  assert.ok(bootstrap.includes(`h!=b'${RECEIVER_SHA256}\\n'`));
  assert.ok(bootstrap.includes("deadline=time.monotonic()+215"));
  assert.ok(bootstrap.includes("signal.setitimer(signal.ITIMER_REAL,215)"));
  assert.ok(bootstrap.includes("'_bootstrap_deadline':deadline"));
  assert.ok(receiverBytes.toString("utf8").includes("DEADLINE = min(STARTED + GLOBAL_SECONDS, globals().get(\"_bootstrap_deadline\""));
  expectThrow(() => buildBootstrap(receiverBytes.subarray(0, -1)));
  const changedReceiver = Buffer.from(receiverBytes);
  changedReceiver[0] ^= 1;
  expectThrow(() => buildBootstrap(changedReceiver));

  const sshFixture = Buffer.from([0x53, 0x53, 0x48, 0x00, 0xff]);
  const fixturePin = { bytes: sshFixture.length, sha256: sha(sshFixture) };
  assert.equal(verifyFixedSshBytes(sshFixture, fixturePin), sshFixture);
  expectThrow(() => verifyFixedSshBytes(Buffer.concat([sshFixture, Buffer.from([0])]), fixturePin));
  expectThrow(() => verifyFixedSshBytes(Buffer.from("changed"), fixturePin));
  assert.deepEqual(_fixedSshToolForTest(fixedSshFixture(sshFixture), sshFixture), sshFixture);

  const known = receipt();
  assert.equal(parseReceipt(known).downloaded_tools_executed, false);
  const goodValue = JSON.parse(known.toString("ascii").split("\n")[0]);
  const frame = (value) => Buffer.from(JSON.stringify(value) + "\nCT200_TOOLS_STAGED\n", "ascii");
  expectThrow(() => parseReceipt(frame({ ...goodValue, node_bytes: 128 * 1024 * 1024 + 1 })));
  for (const key of ["go_archive_sha256", "node_archive_sha256", "go_tree_sha256", "node_file_sha256", "units_before_sha256", "units_after_sha256"]) {
    for (const malformed of [[goodValue[key]], { value: goodValue[key] }, null, 42]) {
      expectThrow(() => parseReceipt(frame({ ...goodValue, [key]: malformed })));
    }
    expectThrow(() => parseReceipt(frame({ ...goodValue, [key]: "invalid" })));
  }
  expectThrow(() => parseReceipt(frame({ ...goodValue, go_archive_sha256: "c".repeat(64) })));
  expectThrow(() => parseReceipt(frame({ ...goodValue, node_archive_sha256: "c".repeat(64) })));
  expectThrow(() => parseReceipt(frame({ ...goodValue, units_after_sha256: "c".repeat(64) })));
  expectThrow(() => parseReceipt(frame({ ...goodValue, downloaded_tools_executed: true })));
  expectThrow(() => parseReceipt(frame({ ...goodValue, production_units_unchanged: false })));
  expectThrow(() => parseReceipt(Buffer.concat([known, Buffer.alloc(4096)])));
  expectThrow(() => parseReceipt(Buffer.from(known.toString("ascii").replace("CT200_TOOLS_STAGED", "CT200_TOOLS_PENDING"), "ascii")));
  expectThrow(() => parseReceipt(Buffer.from(known.toString("ascii").replace("\nCT200_TOOLS_STAGED\n", "\nCT200_TOOLS_STAGED\nextra\n"), "ascii")));
  const withExtra = JSON.parse(known.toString("ascii").split("\n")[0]);
  withExtra.unreviewed = true;
  expectThrow(() => parseReceipt(Buffer.from(JSON.stringify(withExtra) + "\nCT200_TOOLS_STAGED\n", "ascii")));

  assert.equal(posixQuote("abc'def"), "'abc'\\''def'");
  assert.equal(posixQuote("\n$HOME; `id`"), "'\n$HOME; `id`'");
  expectThrow(() => posixQuote("bad\0value"));
  process.stdout.write("CT200 tool preparation controls passed\n");
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  if (process.argv.length !== 3 || process.argv[2] !== "--verify") {
    process.stderr.write("usage: node prepare-tools.test.mjs --verify\n"); process.exitCode = 2;
  } else {
    try { verify(); } catch (error) { process.stderr.write(`CT200 tool preparation controls failed: ${error?.name || "Error"}\n`); process.exitCode = 1; }
  }
}
