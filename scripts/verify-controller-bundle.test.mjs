import assert from "node:assert/strict";
import * as fs from "node:fs";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";
import { test } from "node:test";
import { createHash } from "node:crypto";
import { fileURLToPath } from "node:url";
import { readMigrationInventory, reduceMigrationInventory } from "./verify-controller-bundle.mjs";

const repository = resolve(fileURLToPath(new URL("..", import.meta.url)));
const migrationDirectory = join(repository, "migrations");
const sourceNames = fs.readdirSync(migrationDirectory).sort();
const currentRequiredNames = sourceNames.filter((name) => Number(name.slice(0, 4)) <= 22);
const CONTROL_NAMES = [
  "complete current inventory matches independent file hashes",
  "future ordered migration is accepted",
  "missing and wrong required names are rejected exactly",
  "duplicate basename and duplicate numeric id are rejected exactly",
  "gap and malformed migration names are rejected exactly",
  "reader rejects directories oversized files and unexpected entries",
  "reader rejects symlinks or reports unsupported platform",
  "reader detects deterministic replacement truncation growth and mtime changes",
  "reader rejects invalid UTF-8 bytes",
  "reader and control inventory oracles reject deliberate implementation mutants",
];
const AUDIT_NAME = "expected control inventory settled before success marker";
const registeredNames = [];
const controlResults = [];
let fixtureAttempts = 0;

function registerControl(name, body) {
  registeredNames.push(name);
  test(name, { concurrency: false }, (t) => {
    let result;
    try {
      result = body(t);
      if (result && typeof result.then === "function") throw new Error("inventory controls must settle synchronously");
      const status = result?.status ?? "passed";
      if (status === "unsupported") t.diagnostic(`UNSUPPORTED CONTROL: ${result.reason}`);
      controlResults.push({ name, status, reason: result?.reason });
    } catch (error) {
      controlResults.push({ name, status: "failed", error: String(error?.message ?? error) });
      throw error;
    }
  });
}

function independentInventory(directory) {
  const names = fs.readdirSync(directory).sort();
  assert.ok(names.length <= 256, "independent inventory exceeds 256 entries");
  let total = 0;
  return names.map((name) => {
    assert.equal(basename(name), name, "independent source name must not escape its directory");
    const path = join(directory, name);
    const stat = fs.lstatSync(path);
    assert.ok(stat.isFile() && !stat.isSymbolicLink(), `independent source is not a regular file: ${name}`);
    assert.ok(stat.size > 0 && stat.size <= 2 * 1024 * 1024, `independent source size is invalid: ${name}`);
    total += stat.size;
    assert.ok(total <= 32 * 1024 * 1024, "independent inventory exceeds 32 MiB");
    const bytes = fs.readFileSync(path);
    assert.equal(bytes.length, stat.size, `independent source changed while hashing: ${name}`);
    return { name, bytes: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
  });
}

function assertReaderMatchesIndependent(actual, expected) {
  assert.deepEqual(actual, expected, "reader output differs from independent source bytes and SHA-256 values");
}

function assertReaderRejects(read, expected, label) {
  let failure;
  try { read(); } catch (error) { failure = error; }
  assert.ok(failure, `${label} control accepted the injected fault`);
  if (expected instanceof RegExp) assert.match(failure.message, expected, label);
  else assert.ok(expected(failure), `${label} failed with an unintended category: ${failure.message}`);
}

function withPrivateFixture(assertion, fixtureNames = sourceNames) {
  fixtureAttempts += 1;
  assert.ok(fixtureAttempts <= 6, "fixture family exceeded six exact private parents");
  assert.ok(fixtureNames.length <= 256, "fixture source inventory exceeds 256 entries");
  let sourceBytes = 0;
  for (const name of fixtureNames) {
    const stat = fs.lstatSync(join(migrationDirectory, name));
    assert.ok(stat.isFile() && !stat.isSymbolicLink(), `fixture source is not regular: ${name}`);
    assert.ok(stat.size > 0 && stat.size <= 2 * 1024 * 1024, `fixture source size is invalid: ${name}`);
    sourceBytes += stat.size;
    assert.ok(sourceBytes <= 32 * 1024 * 1024, "fixture source inventory exceeds 32 MiB");
  }
  const parent = fs.mkdtempSync(join(tmpdir(), "controller-bundle17-"));
  const fixture = join(parent, "migrations");
  const ownedChildren = new Map();
  let childCreated = false;
  let result;
  let primaryError;

  try {
    fs.mkdirSync(fixture);
    childCreated = true;
    for (const name of fixtureNames) {
      assert.equal(basename(name), name, "fixture basename must not escape its directory");
      ownedChildren.set(name, "file");
      fs.copyFileSync(join(migrationDirectory, name), join(fixture, name));
    }
    const ownedName = (name) => {
      assert.equal(basename(name), name, "fixture mutations must use one exact basename");
      assert.ok(name !== "." && name !== "..", "fixture mutation basename is invalid");
      return join(fixture, name);
    };
    const mutation = {
      remove(name) {
        fs.unlinkSync(ownedName(name));
        ownedChildren.delete(name);
      },
      write(name, bytes) {
        const path = ownedName(name);
        if (ownedChildren.has(name)) fs.writeFileSync(path, bytes, { flag: "w" });
        else writeNewOwnedFile(path, name, bytes, ownedChildren);
      },
      directory(name) {
        const path = ownedName(name);
        if (ownedChildren.has(name)) {
          fs.unlinkSync(path);
          ownedChildren.delete(name);
        }
        fs.mkdirSync(path);
        ownedChildren.set(name, "directory");
      },
      symlink(name, target) {
        const path = ownedName(name);
        if (ownedChildren.has(name)) {
          fs.unlinkSync(path);
          ownedChildren.delete(name);
        }
        fs.symlinkSync(target, path, "file");
        ownedChildren.set(name, "symlink");
      },
    };
    result = assertion(fixture, mutation);
  } catch (error) {
    primaryError = error;
  }

  const cleanupErrors = [];
  for (const [name, expectedType] of [...ownedChildren].reverse()) {
    const path = join(fixture, name);
    try {
      const stat = fs.lstatSync(path);
      if (expectedType === "directory" && stat.isDirectory() && !stat.isSymbolicLink()) fs.rmdirSync(path);
      else if (expectedType === "symlink" && stat.isSymbolicLink()) fs.unlinkSync(path);
      else if (expectedType === "file" && stat.isFile() && !stat.isSymbolicLink()) fs.unlinkSync(path);
      else throw new Error(`fixture cleanup type mismatch for owned entry ${name}`);
    } catch (error) {
      if (error?.code !== "ENOENT") cleanupErrors.push(error);
    }
  }
  if (childCreated) {
    try { fs.rmdirSync(fixture); } catch (error) { if (error?.code !== "ENOENT") cleanupErrors.push(error); }
  }
  try { fs.rmdirSync(parent); } catch (error) { if (error?.code !== "ENOENT") cleanupErrors.push(error); }

  if (primaryError && cleanupErrors.length) throw new AggregateError([primaryError, ...cleanupErrors], "fixture assertion and exact cleanup failed");
  if (primaryError) throw primaryError;
  if (cleanupErrors.length) throw new AggregateError(cleanupErrors, "exact fixture cleanup failed");
  return result;
}

function writeNewOwnedFile(path, name, bytes, ownedChildren, operations = {
  open: (target, flags) => fs.openSync(target, flags),
  write: (descriptor, contents) => fs.writeFileSync(descriptor, contents),
  close: (descriptor) => fs.closeSync(descriptor),
}) {
  const descriptor = operations.open(path, "wx");
  ownedChildren.set(name, "file");
  let writeFailure;
  let closeFailure;
  try { operations.write(descriptor, bytes); } catch (error) { writeFailure = error; }
  try { operations.close(descriptor); } catch (error) { closeFailure = error; }
  if (writeFailure && closeFailure) throw new AggregateError([writeFailure, closeFailure], "new fixture write and close both failed");
  if (writeFailure) throw writeFailure;
  if (closeFailure) throw closeFailure;
}

function assertControlInventory(expectedNames, registered, results) {
  assert.deepEqual(registered, [...expectedNames, AUDIT_NAME], "registered top-level inventory differs from its frozen list");
  assert.deepEqual(results.map(({ name }) => name), expectedNames, "required controls were omitted, duplicated, or reordered");
  for (const result of results) {
    assert.ok(result.status === "passed" || (result.name === CONTROL_NAMES[6] && result.status === "unsupported"),
      `control did not settle successfully: ${result.name} (${result.status})`);
  }
  assert.equal(new Set(results.map(({ name }) => name)).size, expectedNames.length, "duplicate control result");
}

function injectedReaderOperations(targetName, mode) {
  const descriptors = new Map();
  const fstatCalls = new Map();
  const readCalls = new Map();
  const counts = { opened: 0, closed: 0 };
  const target = (descriptor) => basename(descriptors.get(descriptor) ?? "") === targetName;
  const operations = {
    openSync(path, flags) {
      const descriptor = fs.openSync(path, flags);
      descriptors.set(descriptor, path);
      counts.opened += 1;
      return descriptor;
    },
    closeSync(descriptor) {
      const path = descriptors.get(descriptor);
      try { return fs.closeSync(descriptor); } finally {
        descriptors.delete(descriptor);
        fstatCalls.delete(descriptor);
        readCalls.delete(descriptor);
        if (path) readCalls.delete(path);
        counts.closed += 1;
      }
    },
    fstatSync(descriptor, options) {
      const stat = fs.fstatSync(descriptor, options);
      const call = (fstatCalls.get(descriptor) ?? 0) + 1;
      fstatCalls.set(descriptor, call);
      if (target(descriptor) && mode === "mtime" && call === 2) {
        return new Proxy(stat, { get(object, key) {
          if (key === "mtimeNs") return object.mtimeNs + 1n;
          const value = Reflect.get(object, key, object);
          return typeof value === "function" ? value.bind(object) : value;
        } });
      }
      return stat;
    },
    lstatSync(path, options) {
      const stat = fs.lstatSync(path, options);
      if (basename(path) === targetName && mode === "replacement" && (readCalls.get(path) ?? 0) > 0) {
        return new Proxy(stat, { get(object, key) {
          if (key === "ino") return object.ino + 1n;
          const value = Reflect.get(object, key, object);
          return typeof value === "function" ? value.bind(object) : value;
        } });
      }
      return stat;
    },
    readSync(descriptor, buffer, offset, length, position) {
      if (!target(descriptor)) return fs.readSync(descriptor, buffer, offset, length, position);
      const call = (readCalls.get(descriptor) ?? 0) + 1;
      readCalls.set(descriptor, call);
      readCalls.set(descriptors.get(descriptor), call);
      if (mode === "truncation" && position > 0) return 0;
      if (mode === "growth" && position >= fs.fstatSync(descriptor, { bigint: true }).size) {
        buffer[offset] = 0x41;
        return 1;
      }
      if (mode === "invalid-utf8" && position < fs.fstatSync(descriptor, { bigint: true }).size) {
        const count = Math.min(length, Number(fs.fstatSync(descriptor, { bigint: true }).size) - position);
        buffer.fill(0xff, offset, offset + count);
        return count;
      }
      if (mode === "truncation" && position === 0) return fs.readSync(descriptor, buffer, offset, Math.max(1, Math.floor(length / 2)), position);
      return fs.readSync(descriptor, buffer, offset, length, position);
    },
  };
  return { operations, counts };
}

registerControl(CONTROL_NAMES[0], () => {
  const expected = independentInventory(migrationDirectory);
  assert.ok(sourceNames.length >= 22, "source inventory omits required current migrations");
  assertReaderMatchesIndependent(readMigrationInventory(migrationDirectory), expected);
  withPrivateFixture((fixture) => assertReaderMatchesIndependent(readMigrationInventory(fixture), expected));
});

registerControl(CONTROL_NAMES[1], () => {
  const baselineNames = currentRequiredNames;
  const futureName = "0023_future_migration.sql";
  assert.deepEqual(reduceMigrationInventory([...baselineNames, futureName]).at(-1), futureName);
  withPrivateFixture((fixture, mutate) => {
    const bytes = Buffer.from("-- future ordered migration\n", "utf8");
    mutate.write(futureName, bytes);
    const expected = independentInventory(fixture);
    assertReaderMatchesIndependent(readMigrationInventory(fixture), expected);
  }, baselineNames);
});

registerControl(CONTROL_NAMES[2], () => {
  const missingCurrent = sourceNames.filter((name) => name !== "0022_llm_displacement.sql");
  assert.throws(() => reduceMigrationInventory(missingCurrent), /missing required current migration: 0022_llm_displacement\.sql/);
  const wrongCurrent = sourceNames.map((name) => name === "0022_llm_displacement.sql" ? "0022_wrong_name.sql" : name);
  assert.throws(() => reduceMigrationInventory(wrongCurrent), /missing required current migration: 0022_llm_displacement\.sql/);
  const wrongHistorical = sourceNames.map((name) => name === "0001_init.sql" ? "0001_wrong_name.sql" : name);
  assert.throws(() => reduceMigrationInventory(wrongHistorical), /missing required historical migration: 0001_init\.sql/);
});

registerControl(CONTROL_NAMES[3], () => {
  const baselineNames = currentRequiredNames;
  assert.throws(() => reduceMigrationInventory([...baselineNames, baselineNames.at(-1)]), /duplicate migration name/);
  assert.throws(() => reduceMigrationInventory([...baselineNames, "0022_duplicate_id.sql"]), /sequence gap or unexpected id at 0023/);
});

registerControl(CONTROL_NAMES[4], () => {
  const futureGap = [...currentRequiredNames, "0024_gap_control.sql"];
  assert.throws(() => reduceMigrationInventory(futureGap), /sequence gap or unexpected id at 0023/);
  assert.throws(() => reduceMigrationInventory([...currentRequiredNames, "0023-Bad.sql"]), /noncanonical migration name/);
  withPrivateFixture((fixture, mutate) => {
    mutate.write("notes.sql", Buffer.from("unexpected", "utf8"));
    assert.throws(() => readMigrationInventory(fixture), /noncanonical migration name/);
  }, currentRequiredNames);
});

registerControl(CONTROL_NAMES[5], () => {
  withPrivateFixture((fixture, mutate) => {
    mutate.remove("0022_llm_displacement.sql");
    mutate.directory("0022_llm_displacement.sql");
    assert.throws(() => readMigrationInventory(fixture), /migration is not a regular file/);
  }, currentRequiredNames);
  withPrivateFixture((fixture, mutate) => {
    mutate.write("0022_llm_displacement.sql", Buffer.alloc(2 * 1024 * 1024 + 1, 0x41));
    assert.throws(() => readMigrationInventory(fixture), /migration size is invalid/);
  }, currentRequiredNames);
});

registerControl(CONTROL_NAMES[6], (t) => {
  return withPrivateFixture((fixture, mutate) => {
    mutate.remove("0022_llm_displacement.sql");
    try {
      mutate.symlink("0022_llm_displacement.sql", join(migrationDirectory, "0022_llm_displacement.sql"));
    } catch (error) {
      if (["EPERM", "EACCES", "ENOTSUP", "EOPNOTSUPP", "ENOSYS"].includes(error?.code)) {
        return { status: "unsupported", reason: `symbolic link creation denied (${error.code})` };
      }
      throw error;
    }
    assert.throws(() => readMigrationInventory(fixture), /migration is not a regular file/);
    return { status: "passed" };
  }, currentRequiredNames);
});

registerControl(CONTROL_NAMES[7], () => {
  const cases = [
    ["mtime", /migration changed while being read/],
    ["replacement", /migration changed while being read/],
    ["truncation", /migration size changed while being read/],
    ["growth", /migration grew while being read/],
  ];
  for (const [mode, expected] of cases) {
    const seam = injectedReaderOperations("0001_init.sql", mode);
    assert.throws(() => readMigrationInventory(migrationDirectory, seam.operations), expected, mode);
    assert.equal(seam.counts.opened, seam.counts.closed, `${mode} reader descriptors must close`);
  }
});

registerControl(CONTROL_NAMES[8], () => {
  const seam = injectedReaderOperations("0001_init.sql", "invalid-utf8");
  assert.throws(
    () => readMigrationInventory(migrationDirectory, seam.operations),
    (error) => error instanceof TypeError && error.code === "ERR_ENCODING_INVALID_ENCODED_DATA",
    "invalid UTF-8 must fail at the reader decode boundary",
  );
  assert.equal(seam.counts.opened, seam.counts.closed, "UTF-8 failure must close reader descriptors");
});

registerControl(CONTROL_NAMES[9], () => {
  const complete = CONTROL_NAMES.map((name) => ({ name, status: "passed" }));
  const testRegistration = [...CONTROL_NAMES, AUDIT_NAME];
  assertControlInventory(CONTROL_NAMES, testRegistration, complete);

  const expected = independentInventory(migrationDirectory);
  const zeroDigestMutant = readMigrationInventory(migrationDirectory, undefined, "zero-digest");
  assert.throws(() => assertReaderMatchesIndependent(zeroDigestMutant, expected), /reader output differs from independent source bytes/);

  const guardMutants = [
    ["mtime", "drop-stability", /migration changed while being read/],
    ["replacement", "drop-stability", /migration changed while being read/],
    ["truncation", "drop-complete-read", /migration size changed while being read/],
    ["growth", "drop-growth", /migration grew while being read/],
    ["invalid-utf8", "drop-utf8", (error) => error instanceof TypeError && error.code === "ERR_ENCODING_INVALID_ENCODED_DATA"],
  ];
  for (const [fault, mutation, expectedFailure] of guardMutants) {
    const seam = injectedReaderOperations("0001_init.sql", fault);
    const mutantRead = () => readMigrationInventory(migrationDirectory, seam.operations, mutation);
    assert.doesNotThrow(mutantRead, `${mutation} should model the bounded broken-reader implementation`);
    assert.throws(() => assertReaderRejects(mutantRead, expectedFailure, `${mutation} mutation`), /control accepted the injected fault/);
    assert.equal(seam.counts.opened, seam.counts.closed, `${mutation} mutant descriptors must close`);
  }

  const omittedRegistration = testRegistration.filter((name) => name !== CONTROL_NAMES[4]);
  assert.throws(() => assertControlInventory(CONTROL_NAMES, omittedRegistration, complete), /registered top-level inventory differs/);
  const missing = complete.filter(({ name }) => name !== CONTROL_NAMES[4]);
  assert.throws(() => assertControlInventory(CONTROL_NAMES, testRegistration, missing), /required controls were omitted/);
  const duplicate = [...complete, { name: CONTROL_NAMES[0], status: "passed" }];
  assert.throws(() => assertControlInventory(CONTROL_NAMES, testRegistration, duplicate), /required controls were omitted, duplicated, or reordered/);
  const failed = complete.map((entry) => entry.name === CONTROL_NAMES[0] ? { ...entry, status: "failed" } : entry);
  assert.throws(() => assertControlInventory(CONTROL_NAMES, testRegistration, failed), /control did not settle successfully/);

  const writeFailure = new Error("synthetic descriptor write failure");
  const closeFailure = new Error("synthetic descriptor close failure");
  const syntheticOwnership = new Map();
  let attemptedClose = 0;
  assert.throws(() => writeNewOwnedFile("virtual-owned-file", "synthetic.sql", Buffer.from("bounded"), syntheticOwnership, {
    open: () => 17,
    write: () => { throw writeFailure; },
    close: () => { attemptedClose += 1; throw closeFailure; },
  }), (error) => error instanceof AggregateError && error.errors.includes(writeFailure) && error.errors.includes(closeFailure));
  assert.equal(attemptedClose, 1, "synthetic close failure must be attempted exactly once");
  assert.deepEqual([...syntheticOwnership], [["synthetic.sql", "file"]], "new object ownership must precede writes");
});

registeredNames.push(AUDIT_NAME);
test(AUDIT_NAME, { concurrency: false }, () => {
  assertControlInventory(CONTROL_NAMES, registeredNames, controlResults);
  const unsupported = controlResults.filter(({ status }) => status === "unsupported").map(({ name, reason }) => `${name}: ${reason}`);
  console.log(unsupported.length
    ? `controller bundle inventory controls passed; explicitly unsupported: ${unsupported.join("; ")}`
    : "controller bundle inventory controls passed");
});
