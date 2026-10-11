import assert from "node:assert/strict";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test, { after } from "node:test";
import { fileURLToPath } from "node:url";
import { assertSameEntries, HELPER_PATH, HELPER_SHA256, testSurface as build } from "./build.mjs";
import { assertEmbeddedAssets, assertExactNames, assertFileManifest, testSurface as verify } from "./verify.mjs";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const digest = (bytes) => crypto.createHash("sha256").update(bytes).digest("hex");
const expectedControls = [
  "pinned Git tree and blob inventory is the positive baseline control",
  "pinned helper and reviewed controller delta have exact identity and placement",
  "delta anchor duplicates and unrelated source mutations fail closed",
  "path policy accepts repository-relative entries and rejects traversal, drives, and links",
  "Git tree parser accepts only bounded regular baseline records",
  "independent source manifest rejects changed, missing, extra, or duplicate entries",
  "binary identity must contain each exact baseline embedded asset",
  "manifest schema control rejects unreviewed fields and assembly verifies before success",
  "complete candidate byte validator accepts one fixture and rejects source closure module tool image and manifest mutants",
  "tracked absence, bounded candidate walkers, and independent H1 mutants fail closed",
  "failure diagnostics disclose only allowlisted stage operation and error codes",
];
const actualControls = [];
let failedControl = false;
function nonSkippingContext(context) {
  return new Proxy(context, {
    get(target, property) {
      if (property === "skip" || property === "todo") return () => { throw new Error("skipped/todo controls are not acceptance evidence"); };
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}
function control(name, run) {
  test(name, async (t) => {
    try { await run(nonSkippingContext(t)); actualControls.push(name); } catch (error) { failedControl = true; throw error; }
  });
}
const goodWs = [
  "package api", "import (", '\t"github.com/coder/websocket"', '\t"github.com/coder/websocket/wsjson"',
  '\t"vram-governor/internal/domain"', '\t"vram-governor/internal/wsproto"', ")", "func handleNodeWS(w http.ResponseWriter, r *http.Request) {",
  "\tconn, err := websocket.Accept(w, r, nil)", "\tif err != nil {", '\t\ts.log.Error("ws accept failed", "err", err)', "\t\treturn", "\t}",
  "\tdefer conn.CloseNow()", "\tvar env wsproto.Envelope", "\tif err := wsjson.Read(ctx, conn, &env); err != nil {", "\t}", "}", "",
].join("\n");

control(expectedControls[0], () => {
  const entries = build.readPinnedGitEntries();
  assert.ok(entries.size > 200);
  assert.ok(entries.has("internal/api/ws.go"));
  assert.ok(entries.has("go.sum"));
  assert.equal(verify.readPinnedGitEntries().size, entries.size);
});

control(expectedControls[1], () => {
  const helper = fs.readFileSync(path.join(root, ...HELPER_PATH.split("/")));
  assert.equal(digest(helper), HELPER_SHA256);
  const transformed = build.transformWs(goodWs);
  assert.equal((transformed.match(/ApplyControlMessageLimit\(conn\)/g) ?? []).length, 1);
  assert.ok(transformed.indexOf('"vram-governor/internal/nodetransport"') < transformed.indexOf("func handleNodeWS"));
  assert.ok(transformed.indexOf("websocket.Accept") < transformed.indexOf("ApplyControlMessageLimit(conn)"));
  assert.ok(transformed.indexOf("ApplyControlMessageLimit(conn)") < transformed.indexOf("wsjson.Read(ctx, conn"));
});

control(expectedControls[2], () => {
  const importNeedle = '\t"vram-governor/internal/domain"\n';
  assert.throws(() => build.transformWs(goodWs.replace(importNeedle, `${importNeedle}${importNeedle}`)));
  const expected = new Map([["internal/api/ws.go", Buffer.from(build.transformWs(goodWs))], [HELPER_PATH, Buffer.from("helper")]]);
  assert.equal(assertSameEntries(expected, new Map(expected)), true);
  const changed = new Map(expected); changed.set("internal/api/ws.go", Buffer.from("mutated"));
  assert.throws(() => assertSameEntries(expected, changed));
  const missing = new Map(expected); missing.delete(HELPER_PATH);
  assert.throws(() => assertSameEntries(expected, missing));
  const extra = new Map(expected); extra.set("internal/nodeagent/agent.go", Buffer.from("forbidden"));
  assert.throws(() => assertSameEntries(expected, extra));
});

control(expectedControls[3], () => {
  assert.equal(build.safeRelative("internal/api/ws.go"), true);
  assert.equal(verify.safeRelative("web/ui/dist/index.html"), true);
  for (const name of ["../escape", "a/../../b", "/absolute", "C:/drive", "a\\b", "a//b", "a/./b"]) {
    assert.equal(build.safeRelative(name), false, name);
    assert.equal(verify.safeRelative(name), false, name);
  }
});

control(expectedControls[4], () => {
  const oid = "a".repeat(40);
  const valid = Buffer.from(`100644 blob ${oid}\tinternal/api/ws.go\0`, "utf8");
  assert.deepEqual(build.parseTreeListing(valid), [{ mode: "100644", type: "blob", oid, name: "internal/api/ws.go" }]);
  for (const entry of [
    `120000 blob ${oid}\tinternal/api/ws.go\0`,
    `100644 tree ${oid}\tinternal/api/ws.go\0`,
    `100644 blob ${oid}\t../escape\0`,
    `100644 blob deadbeef\tinternal/api/ws.go\0`,
  ]) assert.throws(() => build.parseTreeListing(Buffer.from(entry, "utf8")));
  assert.throws(() => build.parseTreeListing(Buffer.from(`100644 blob ${oid}\tinternal/api/ws.go`, "utf8")));
});

control(expectedControls[5], () => {
  const expected = new Map([["cmd/controller/main.go", Buffer.from("main")], ["web/ui/dist/index.html", Buffer.from("asset")] ]);
  const good = [...expected].map(([name, bytes]) => ({ path: name, bytes: bytes.length, sha256: digest(bytes) }));
  assert.equal(assertFileManifest(good, expected), true);
  assert.throws(() => assertFileManifest([{ ...good[0], sha256: "0".repeat(64) }, good[1]], expected));
  assert.throws(() => assertFileManifest(good.slice(0, 1), expected));
  assert.throws(() => assertFileManifest([...good, { path: "extra", bytes: 0, sha256: digest(Buffer.alloc(0)) }], expected));
  assert.throws(() => assertFileManifest([good[0], good[0]], expected));
});

control(expectedControls[6], () => {
  const asset = Buffer.from("baseline embedded html bytes");
  const inventory = new Map([["web/ui/dist/index.html", asset]]);
  const entry = [{ path: "web/ui/dist/index.html", bytes: asset.length, sha256: digest(asset) }];
  assert.equal(assertEmbeddedAssets(Buffer.concat([Buffer.from("ELF"), asset]), entry, inventory), true);
  assert.throws(() => assertEmbeddedAssets(Buffer.from("ELF without asset"), entry, inventory));
  assert.throws(() => assertEmbeddedAssets(Buffer.concat([Buffer.from("ELF"), Buffer.from("mutated")]), entry, inventory));
});

control(expectedControls[7], () => {
  assert.equal(verify.exactKeys({ path: "x", bytes: 1, sha256: "a" }, ["path", "bytes", "sha256"]), true);
  assert.equal(verify.exactKeys({ path: "x", bytes: 1, sha256: "a", command: "go test" }, ["path", "bytes", "sha256"]), false);
  const builder = fs.readFileSync(new URL("./build.mjs", import.meta.url), "utf8");
  assert.ok(builder.indexOf("const closureAfter = collectGoClosure") < builder.indexOf("verifyCandidateDirectory(candidate)"));
  assert.ok(builder.indexOf("verifyCandidateDirectory(candidate)") < builder.indexOf("controller transport hotfix candidate built and verified"));
  assert.ok(builder.includes("timeout: 600_000"));
  assert.throws(() => nonSkippingContext({ skip() {}, todo() {} }).skip("not evidence"), /not acceptance evidence/);
  assert.throws(() => nonSkippingContext({ skip() {}, todo() {} }).todo("not evidence"), /not acceptance evidence/);
  assert.equal(assertExactNames(["manifest.json", "source", "bin"], ["source", "bin", "manifest.json"]), true);
  assert.throws(() => assertExactNames(["manifest.json", "source", "bin"], ["manifest.json", "source", "bin", "extra"]));
  assert.throws(() => assertExactNames(["manifest.json", "source", "bin"], ["manifest.json", "source"]));
  const suite = fs.readFileSync(new URL("./build.test.mjs", import.meta.url), "utf8");
  assert.ok(suite.includes("await run(nonSkippingContext(t)); actualControls.push(name)"));
});

control(expectedControls[8], () => {
  const goModBytes = Buffer.from("module example.test/mod\n", "utf8");
  assert.equal(build.hash1Entries([{ path: "a", bytes: Buffer.from("x", "utf8") }], "example.test/mod@v1.0.0"), "h1:jlA2GcYo5ALVuK1CSAgMcRpCQtjtPznyUgBJOHAiCdI=");
  assert.equal(verify.hash1Entries([{ path: "a", bytes: Buffer.from("x", "utf8") }], "example.test/mod@v1.0.0"), "h1:jlA2GcYo5ALVuK1CSAgMcRpCQtjtPznyUgBJOHAiCdI=");
  assert.equal(build.hash1Entries([{ path: "go.mod", bytes: goModBytes }]), "h1:gp3pcQgUHDYkCnt0UZpCAfRDZNHrmsLdoq9WYZ/AoQs=");
  assert.equal(verify.hash1Entries([{ path: "go.mod", bytes: goModBytes }]), "h1:gp3pcQgUHDYkCnt0UZpCAfRDZNHrmsLdoq9WYZ/AoQs=");
  assert.notEqual(build.hash1Entries([{ path: "a", bytes: Buffer.from("x", "utf8") }], "example.test/other@v1.0.0"), "h1:jlA2GcYo5ALVuK1CSAgMcRpCQtjtPznyUgBJOHAiCdI=");
  assert.throws(() => build.hash1Entries([{ path: "../a", bytes: Buffer.from("x") }], "example.test/mod@v1.0.0"));
  assert.throws(() => build.hash1Entries([{ path: "a", bytes: Buffer.from("x") }], "../mod@v1.0.0"));
  const modSum = `h1:${Buffer.alloc(32, 1).toString("base64")}`;
  const goModSum = `h1:${Buffer.alloc(32, 2).toString("base64")}`;
  const asset = Buffer.from("fixture embedded asset");
  const expectedEntries = new Map([
    ["go.sum", Buffer.from(`example.test/dep v1.2.3 ${modSum}\nexample.test/dep v1.2.3/go.mod ${goModSum}\n`, "utf8")],
    ["internal/api/ws.go", Buffer.from("pinned plus finite receiver delta")],
    ["internal/nodetransport/limits.go", Buffer.from("reviewed helper")],
    ["web/ui/dist/index.html", asset],
  ]);
  const files = (entries) => [...entries].sort(([a], [b]) => a.localeCompare(b)).map(([name, bytes]) => ({ path: name, bytes: bytes.length, sha256: digest(bytes) }));
  const assetRecord = { path: "web/ui/dist/index.html", bytes: asset.length, sha256: digest(asset) };
  const closure = {
    packages: [{ importPath: "cmd/controller", standard: false, module: null }],
    modules: [{ path: "example.test/dep", version: "v1.2.3", sum: modSum, goModSum, treeH1: modSum, fileCount: 1, totalBytes: 1, files: [{ path: "go.mod", bytes: 1, sha256: "a".repeat(64) }] }],
    sourceFiles: files(expectedEntries), standardFiles: [{ path: "@goroot/src/runtime/runtime.go", bytes: 1, sha256: "b".repeat(64) }],
    moduleFiles: [{ path: "example.test/dep@v1.2.3/dep.go", bytes: 1, sha256: "c".repeat(64) }],
    embeddedAssets: [assetRecord],
    toolchain: { goRoot: "pinned-go1.23.4-toolchain", moduleH1: "h1:uAs0v1Tbi8pAEvc6IkL/tazTmMBok9HxjXC9XLzlLss=", tree: { h1: "h1:uAs0v1Tbi8pAEvc6IkL/tazTmMBok9HxjXC9XLzlLss=", fileCount: 9874, totalBytes: 227759789 }, version: "go version go1.23.4 windows/amd64", files: [{ path: "pkg/tool/windows_amd64/compile.exe", bytes: 1, sha256: "d".repeat(64) }], stdlibFiles: [{ path: "@goroot/src/runtime/runtime.go", bytes: 1, sha256: "b".repeat(64) }], asmIncludeFiles: [{ path: "pkg/include/textflag.h", bytes: 1, sha256: "e".repeat(64) }] },
  };
  const binaryBytes = Buffer.concat([Buffer.from("ELF fixture"), asset]);
  const state = { head: "a".repeat(40), index: { path: ".git/index", type: "file", mode: 0o600, bytes: 8, sha256: "f".repeat(64) }, worktree: { count: 0, totalBytes: 0, digest: digest(Buffer.alloc(0)) }, worktreeStatusSha256: "1".repeat(64) };
  const manifest = {
    schema: "controller-transport-hotfix-candidate-v1", candidate: "candidate-20261004010203-abcdef012345", localOnly: true, releaseApproved: false, installedBinaryProvenance: false,
    baseline: { commit: "cf8d06ad71d5e840304a842ec700cbe4c9637002", tree: "a7707962963733e4753a664493f067e89c851138" },
    reviewedDelta: { wsPath: "internal/api/ws.go", helperPath: "internal/nodetransport/limits.go", helperSha256: "0c7453ec051d7f69e34f65bc1c5fdf4e512287a709f75dd409574f24d0bf5a0b", insertion: "ApplyControlMessageLimit after successful websocket.Accept and before first wsjson.Read" },
    inputTrust: { schema: "controller-input-trust-v1", source: "pinned-baseline-go.sum plus official-go-toolchain-module-h1", modulesVerifiedAgainstGoSum: true, toolchainModuleH1: "h1:uAs0v1Tbi8pAEvc6IkL/tazTmMBok9HxjXC9XLzlLss=" },
    sourceFiles: files(expectedEntries), closure,
    build: { goVersion: "go1.23.4", goToolSha256: "8e8356be1603abff526f52c0d5fe887fb4d77b000f310d298ad10cd33e7471e6", environment: { GOOS: "linux", GOARCH: "amd64", GOAMD64: "v1", CGO_ENABLED: "0", GOTOOLCHAIN: "local", GOROOT: "pinned-go1.23.4-toolchain", GOCACHE: "candidate-private", GOMODCACHE: "repo-offline-cache", GOENV: "off", GOWORK: "off", GOFLAGS: "", GOEXPERIMENT: "", GODEBUG: "", GOFIPS140: "", GOAUTH: "", GOPROXY: "off", GOSUMDB: "off", GOPRIVATE: "", GONOPROXY: "", GONOSUMDB: "", GOINSECURE: "", GOVCS: "*:off" }, goos: "linux", goarch: "amd64", goamd64: "v1", cgo: false, workspace: "off", goenv: "off", goflags: "", network: "disabled", command: "go build -mod=readonly -buildvcs=false -trimpath -ldflags=-s -w ./cmd/controller" },
    binary: { path: "vram-governor-controller-linux-amd64", bytes: binaryBytes.length, sha256: digest(binaryBytes) }, gitStateBefore: state, gitStateAfter: state,
  };
  const bytes = (value) => Buffer.from(`${JSON.stringify(value, null, 2)}\n`, "utf8");
  const input = (candidate = manifest, sources = expectedEntries, image = binaryBytes, baseline = expectedEntries, measured = closure, names = ["manifest.json", "source", "vram-governor-controller-linux-amd64"]) => verify.validateCandidateBytes({ candidateName: manifest.candidate, candidateEntries: names, manifestBytes: bytes(candidate), sourceEntries: sources, expectedEntries: baseline, closure: measured, binaryBytes: image, currentState: state });
  assert.deepEqual(input(), manifest);
  const sourceMutant = new Map(expectedEntries); sourceMutant.set("internal/api/ws.go", Buffer.from("changed")); assert.throws(() => input(manifest, sourceMutant));
  const missingSource = new Map(expectedEntries); missingSource.delete("internal/nodetransport/limits.go"); assert.throws(() => input(manifest, missingSource));
  for (const field of ["modules", "standardFiles", "moduleFiles", "embeddedAssets", "toolchain"]) {
    const changed = structuredClone(manifest); changed.closure[field] = field === "modules" ? [{ ...changed.closure.modules[0], treeH1: "h1:mutated" }] : [{ path: "mutated", bytes: 1, sha256: "0".repeat(64) }]; assert.throws(() => input(changed));
  }
  const authorityReject = (mutate, expectedMessage) => {
    const changed = structuredClone(manifest); mutate(changed.closure);
    assert.throws(() => input(changed, expectedEntries, binaryBytes, expectedEntries, changed.closure), new RegExp(expectedMessage));
  };
  authorityReject((measured) => { measured.modules[0].treeH1 = "h1:mutated"; }, "dependency module content identity is not bound to pinned go\\.sum");
  authorityReject((measured) => { measured.modules[0].sum = "h1:mutated"; measured.modules[0].treeH1 = "h1:mutated"; }, "dependency module content identity is not bound to pinned go\\.sum");
  authorityReject((measured) => { measured.toolchain.moduleH1 = "h1:mutated"; measured.toolchain.tree.h1 = "h1:mutated"; }, "compiler/stdlib toolchain tree is not bound to official module checksum");
  assert.throws(() => input(manifest, expectedEntries, Buffer.from("different image")));
  assert.throws(() => input(manifest, expectedEntries, binaryBytes, expectedEntries, closure, ["manifest.json", "source", "vram-governor-controller-linux-amd64", "unexpected"]));
  const changedSum = new Map(expectedEntries); changedSum.set("go.sum", Buffer.from("example.test/dep v1.2.3 h1:changed\n", "utf8"));
  assert.throws(() => input({ ...manifest, sourceFiles: files(changedSum) }, changedSum, binaryBytes, changedSum));
  assert.throws(() => input({ ...manifest, unexpected: true }));
});

control(expectedControls[9], () => {
  const absent = build.missingTrackedWorktreeRecord("tracked/missing.bin", true, "ENOENT");
  assert.deepEqual(absent, verify.missingTrackedWorktreeRecord("tracked/missing.bin", true, "ENOENT"));
  assert.throws(() => build.missingTrackedWorktreeRecord("untracked/missing.bin", false, "ENOENT"));
  assert.throws(() => verify.missingTrackedWorktreeRecord("tracked/missing.bin", true, "EACCES"));
  const removed = build.summarizeWorktreeRecords([absent]);
  const presentEmpty = build.summarizeWorktreeRecords([{ path: absent.path, type: "file", mode: 0o644, bytes: 0, sha256: digest(Buffer.alloc(0)) }]);
  assert.deepEqual(removed, verify.summarizeWorktreeRecords([absent]));
  assert.notEqual(removed.digest, presentEmpty.digest, "tracked absence must differ from present empty file");
  assert.equal(Object.hasOwn(removed, "entries"), false, "large worktree manifests retain only bounded summaries");
  assert.throws(() => build.summarizeWorktreeRecords([absent, absent]));
  assert.throws(() => verify.summarizeWorktreeRecords([absent, absent]));

  for (const surface of [build, verify]) {
    assert.equal(surface.assertCandidateFileBound(0, 0, 0), true);
    assert.throws(() => surface.assertCandidateFileBound(32 * 1024 * 1024 + 1, 0, 0));
    assert.throws(() => surface.assertCandidateFileBound(1, 30_000, 0));
    assert.throws(() => surface.assertCandidateFileBound(1, 0, 4 * 1024 * 1024 * 1024));
  }
  const tempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "controller-hotfix-walker-"));
  try {
    fs.mkdirSync(path.join(tempRoot, "empty"));
    assert.throws(() => build.readTree(tempRoot), /empty directory/);
    assert.throws(() => verify.readFileMap(tempRoot), /empty directory/);
    fs.rmdirSync(path.join(tempRoot, "empty"));
    fs.writeFileSync(path.join(tempRoot, "known.txt"), "ok");
    const measured = build.readTree(tempRoot);
    assert.equal(measured.get("known.txt").toString(), "ok");
    assert.throws(() => assertSameEntries(measured, new Map([...measured, ["unknown.txt", Buffer.from("x")]])));
    assert.throws(() => verify.assertExactNames(["known.txt"], ["known.txt", "unknown.txt"]));
  } finally {
    fs.rmSync(tempRoot, { recursive: true, force: true });
  }

  const modulePath = "example.test/dep"; const version = "v1.2.3";
  const moduleGoMod = Buffer.from("module example.test/dep\n\ngo 1.23.4\n");
  const depGo = Buffer.from("package dep\n\nconst Value = 1\n");
  const moduleSum = "h1:XfMH7/eMkajKzjrv71KF30X6utrEZeOBAbgxYEWJVLg=";
  const goModSum = "h1:0L3QtGxt3hbhsa4hvHo7ISwsuqi1+twHsZDgXqQWEcU=";
  const h1TempRoot = fs.mkdtempSync(path.join(os.tmpdir(), "controller-hotfix-h1-"));
  try {
    for (const surface of [build, verify]) {
      const moduleRoot = path.join(h1TempRoot, surface === build ? "build-module" : "verify-module");
      fs.mkdirSync(moduleRoot);
      fs.writeFileSync(path.join(moduleRoot, "dep.go"), depGo);
      fs.writeFileSync(path.join(moduleRoot, "go.mod"), moduleGoMod);
      const treeH1 = surface.directoryH1(moduleRoot, [], `${modulePath}@${version}`).h1;
      assert.equal(treeH1, moduleSum, "production directory measurement matches fixed module@version go.sum h1");
      const identity = { modulePath, version, treeH1, moduleSum, moduleGoMod, cacheGoMod: Buffer.from(moduleGoMod), goModSum };
      assert.equal(surface.assertModuleChecksumIdentity(identity), true);
      assert.throws(() => surface.assertModuleChecksumIdentity({ ...identity, moduleGoMod: Buffer.from("module changed\n"), cacheGoMod: Buffer.from("module changed\n") }), /pinned go\.sum h1/);
      assert.throws(() => surface.assertModuleChecksumIdentity({ ...identity, cacheGoMod: Buffer.from("module example.test/other\n") }), /pinned go\.sum h1/);
      const assertMeasuredTreeRejected = (label, prefix = `${modulePath}@${version}`) => {
        const measured = surface.directoryH1(moduleRoot, [], prefix);
        assert.throws(() => surface.assertModuleChecksumIdentity({ ...identity, treeH1: measured.h1 }), /pinned go\.sum h1/, label);
      };
      fs.writeFileSync(path.join(moduleRoot, "dep.go"), Buffer.from("package dep\n\nconst Value = 2\n"));
      assertMeasuredTreeRejected("changed module source rejected by pinned sum");
      fs.writeFileSync(path.join(moduleRoot, "dep.go"), depGo);
      fs.unlinkSync(path.join(moduleRoot, "dep.go"));
      assertMeasuredTreeRejected("missing module source rejected by pinned sum");
      fs.writeFileSync(path.join(moduleRoot, "dep.go"), depGo);
      fs.writeFileSync(path.join(moduleRoot, "extra.go"), Buffer.from("package dep\n"));
      assertMeasuredTreeRejected("extra module source rejected by pinned sum");
      fs.unlinkSync(path.join(moduleRoot, "extra.go"));
      assertMeasuredTreeRejected("wrong module@version path prefix rejected by pinned sum", "example.test/wrong@v1.2.3");
    }
  } finally {
    fs.rmSync(h1TempRoot, { recursive: true, force: true });
  }
  for (const surface of [build, verify]) {
    const pinnedToolchain = { h1: "h1:uAs0v1Tbi8pAEvc6IkL/tazTmMBok9HxjXC9XLzlLss=", fileCount: 9874, totalBytes: 227759789, version: "go version go1.23.4 windows/amd64", goToolSha256: "8e8356be1603abff526f52c0d5fe887fb4d77b000f310d298ad10cd33e7471e6" };
    assert.equal(surface.assertToolchainIdentity(pinnedToolchain), true);
    for (const mutation of [{ h1: "h1:wrong" }, { fileCount: 9873 }, { totalBytes: 227759788 }, { version: "go version go1.23.5 windows/amd64" }, { goToolSha256: "0".repeat(64) }]) assert.throws(() => surface.assertToolchainIdentity({ ...pinnedToolchain, ...mutation }));
    const copyPaths = ["src/cmd/go.mod", "src/cmd/objdump/testdata/testfilenum/go.mod", "src/cmd/vet/testdata/rangeloop/go.mod", "src/cmd/vet/testdata/stdversion/go.mod", "src/crypto/internal/bigmod/_asm/go.mod", "src/crypto/internal/edwards25519/field/_asm/go.mod", "src/go.mod"];
    const pairs = copyPaths.map((name) => ({ path: name, copied: Buffer.from("module generated\n"), original: Buffer.from("module generated\n") }));
    assert.equal(surface.assertGeneratedGoModPairs(pairs), true);
    for (let i = 0; i < pairs.length; i++) { const mutated = pairs.map((pair) => ({ ...pair, copied: Buffer.from(pair.copied) })); mutated[i].copied = Buffer.from("module mismatch\n"); assert.throws(() => surface.assertGeneratedGoModPairs(mutated)); }
    assert.throws(() => surface.assertGeneratedGoModPairs(pairs.slice(1)));
  }
  const buildSource = fs.readFileSync(new URL("./build.mjs", import.meta.url), "utf8");
  const verifySource = fs.readFileSync(new URL("./verify.mjs", import.meta.url), "utf8");
  const statusCapture = (source) => source.split(/\r?\n/).find((line) => line.includes('"status", "--porcelain=v2"'));
  assert.match(statusCapture(buildSource) ?? "", /maxBuffer:\s*MAX_STATE_PATH_LIST/);
  assert.match(statusCapture(verifySource) ?? "", /maxBuffer:\s*MAX_STATE_PATH_LIST/);
  const walkerBody = (source, start, end) => source.slice(source.indexOf(start), source.indexOf(end, source.indexOf(start)));
  const buildWalker = walkerBody(buildSource, "function readTree(root)", "function hashFiles(");
  const verifyWalker = walkerBody(verifySource, "function readFileMap(root)", "export function verifyCandidateDirectory(");
  assert.ok(buildWalker.indexOf("entryCount > MAX_CANDIDATE_ENTRIES") < buildWalker.indexOf("stableRead(full, MAX_FILE)"));
  assert.ok(buildWalker.indexOf("assertCandidateFileBound(stat.size, fileCount, totalBytes)") < buildWalker.indexOf("stableRead(full, MAX_FILE)"));
  assert.ok(verifyWalker.indexOf("entryCount > MAX_CANDIDATE_ENTRIES") < verifyWalker.indexOf("stableRead(full, MAX_FILE)"));
  assert.ok(verifyWalker.indexOf("assertCandidateFileBound(st.size, fileCount, totalBytes)") < verifyWalker.indexOf("stableRead(full, MAX_FILE)"));
});

control(expectedControls[10], () => {
  const sensitive = ["C:\\private\\candidate\\manifest.json", "--ldflags=-XSECRET", "stdout bearer-stdout-secret", "stderr password-secret", "API_TOKEN=credential-secret", "C:\\private\\Go\\bin\\go.exe"];
  const raw = Object.assign(new Error(sensitive.join(" | ")), { stdout: sensitive[2], stderr: sensitive[3], path: sensitive[0], env: { API_TOKEN: sensitive[4] }, stack: sensitive.join("\n") });
  const summary = build.formatFailureDiagnostic("compile", raw);
  assert.equal(summary, "stage=compile operation=assertion code=assertion");
  for (const secret of sensitive) assert.equal(summary.includes(secret), false);
  assert.equal(summary.includes("candidate built and verified"), false);

  const timeout = build.makeSafeCommandFailure("go-build", "ETIMEDOUT", null);
  assert.equal(timeout.message, "local command failed");
  assert.equal(build.formatFailureDiagnostic("compile", timeout), "stage=compile operation=go-build code=timeout");
  const buffer = build.makeSafeCommandFailure("git", "ENOBUFS", null);
  assert.equal(build.formatFailureDiagnostic("baseline", buffer), "stage=baseline operation=git code=buffer");
  const exit = verify.makeSafeCommandFailure("go-list", null, 17);
  assert.equal(build.formatFailureDiagnostic("closure-before", exit), "stage=closure-before operation=go-list code=exit-17");
  const errno = verify.makeSafeCommandFailure("git", "EACCES", null);
  assert.equal(build.formatFailureDiagnostic("independent-verifier", errno), "stage=independent-verifier operation=git code=EACCES");
  const invalid = new Error("must not escape");
  invalid[Symbol.for("controller-hotfix.safeFailure.v1")] = { operation: sensitive[0], code: sensitive[4] };
  assert.equal(build.formatFailureDiagnostic("attacker-controlled-stage", invalid), "stage=source operation=assertion code=assertion");
  assert.equal(build.formatFailureDiagnostic("compile", build.makeSafeCommandFailure("go-build", null, 999)), "stage=compile operation=go-build code=terminated");
  const builder = fs.readFileSync(new URL("./build.mjs", import.meta.url), "utf8");
  const allowedStages = ["baseline", "initial-preservation", "source", "closure-before", "compile", "closure-after", "postbuild-preservation", "manifest", "preverify-preservation", "independent-verifier", "final-preservation"];
  for (const stage of allowedStages) assert.ok(builder.includes(`"${stage}"`), `missing allowlisted failure stage ${stage}`);
  assert.match(builder, /catch \(error\) \{\s*process\.stderr\.write\(`controller hotfix assembly failed closed; \$\{formatFailureDiagnostic\(activeFailureStage, error\)\}\\n`\);\s*process\.exitCode = 1;/);
  assert.ok(builder.indexOf("const result = assemble()") < builder.indexOf("controller transport hotfix candidate built and verified:"), "success is printed only after assembly returns");
  const cli = spawnSync(process.execPath, [fileURLToPath(new URL("./build.mjs", import.meta.url)), "--diagnostic-test-invalid"], { cwd: root, env: { ...process.env, API_TOKEN: "credential-secret" }, encoding: "utf8", timeout: 5000, windowsHide: true });
  assert.equal(cli.status, 1);
  assert.equal(cli.stdout, "");
  assert.equal(cli.stderr, "controller hotfix assembly failed closed; stage=baseline operation=assertion code=assertion\n");
  assert.equal(cli.stderr.includes("credential-secret"), false);
});

after(() => {
  assert.deepEqual(actualControls, expectedControls, "the expected named controls all executed exactly once in declared order");
  assert.equal(failedControl, false, "success marker cannot follow failed controls");
  process.stdout.write("controller hotfix unit controls passed\n");
});
