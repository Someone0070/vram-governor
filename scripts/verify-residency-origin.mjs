import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const mode = process.argv[2];
const maxSourceBytes = 2 << 20;
const maxGoTestElapsedSeconds = 45;
const sourceFiles = [
  'internal/domain/workload.go',
  'internal/store/store.go',
  'internal/store/memory.go',
  'internal/store/postgres_workloads.go',
  'internal/store/postgres_contract_test.go',
  'internal/store/residency_origin_test.go',
  'internal/workloads/manager.go',
  'internal/workloads/manager_test.go',
  'internal/workloads/residency.go',
  'internal/workloads/residency_test.go',
  'scripts/verify-residency-origin.mjs',
];
const originTests = [
  'TestResidencyTransitionLeaseOriginMemoryAndPostgres',
  'TestPostgresLeaseOriginRechecksExpiryAfterFenceWait',
  'TestPostgresLeaseOriginExpiresWhileWaitingForFenceSentinel',
  'TestPostgresLeaseOriginRechecksExpiryAfterModelAndTransitionWaits',
  'TestPostgresLeaseBoundReplayRechecksExpiryAfterTransitionWait',
  'TestPostgresLeaseOriginInsertFailureRollsBack',
  'TestResidencyLeaseOriginUsesCanonicalVirtualResource',
  'TestPostgresLeaseRenewAndReleaseSerializeOnSharedFence',
];

function readSources() {
  const sources = new Map();
  for (const relative of sourceFiles) {
    const absolute = path.resolve(root, relative);
    if (!absolute.startsWith(root + path.sep)) throw new Error(`unsafe source path ${relative}`);
    const stat = fs.lstatSync(absolute);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxSourceBytes) throw new Error(`unbounded or non-regular source ${relative}`);
    const fd = fs.openSync(absolute, 'r');
    try {
      const opened = fs.fstatSync(fd);
      if (!opened.isFile() || opened.size !== stat.size || opened.size > maxSourceBytes) throw new Error(`source changed before read ${relative}`);
      const bytes = Buffer.alloc(stat.size + 1);
      const count = fs.readSync(fd, bytes, 0, bytes.length, 0);
      if (count !== stat.size) throw new Error(`source changed during read ${relative}`);
      const text = bytes.subarray(0, count).toString('utf8');
      if (text.includes('\u0000')) throw new Error(`binary content in source ${relative}`);
      sources.set(relative, text);
    } finally { fs.closeSync(fd); }
  }
  return sources;
}

function requireTokens(source, tokens, label) {
  for (const token of tokens) if (!source.includes(token)) throw new Error(`${label} omitted ${token}`);
}

function exactTestInventory(source, expected, label) {
  const found = [...source.matchAll(/^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)/gm)].map((match) => match[1]);
  if (new Set(found).size !== found.length || found.length !== expected.length || found.some((name, index) => name !== expected[index])) {
    throw new Error(`${label} inventory differs: ${JSON.stringify(found)}`);
  }
  return found;
}

function normalizeGoTestManifest(listed) {
  if (!listed || typeof listed !== 'object' || Array.isArray(listed) || !Array.isArray(listed.TestGoFiles)) {
    throw new Error('go list omitted or malformed TestGoFiles');
  }
  const external = listed.XTestGoFiles === undefined ? [] : listed.XTestGoFiles;
  if (!Array.isArray(external)) throw new Error('go list emitted malformed XTestGoFiles');
  const files = [...listed.TestGoFiles, ...external];
  if (files.some((name) => typeof name !== 'string' || !name || name.includes('\\') || name.startsWith('/') || name.split('/').includes('..'))) {
    throw new Error('go list emitted an unsafe compiled test file name');
  }
  if (new Set(files).size !== files.length) throw new Error('go list duplicated a compiled test file');
  return files;
}

function expectRejected(name, action) {
  let rejected = false;
  try { action(); } catch { rejected = true; }
  if (!rejected) throw new Error(`source-only negative control was accepted: ${name}`);
}

function manifestControls() {
  const omittedExternal = normalizeGoTestManifest({ TestGoFiles: ['store_internal_test.go'] });
  if (omittedExternal.length !== 1 || omittedExternal[0] !== 'store_internal_test.go') throw new Error('omitted XTestGoFiles did not normalize to an empty list');
  const emptyExternal = normalizeGoTestManifest({ TestGoFiles: ['store_internal_test.go'], XTestGoFiles: [] });
  if (emptyExternal.length !== 1) throw new Error('present empty XTestGoFiles was rejected');
  const populated = normalizeGoTestManifest({ TestGoFiles: ['store_internal_test.go'], XTestGoFiles: ['store_external_test.go'] });
  if (populated.join('|') !== 'store_internal_test.go|store_external_test.go') throw new Error('external test files were omitted from the compiled inventory');
  for (const [name, listed] of [
    ['TestGoFiles absent', {}],
    ['TestGoFiles malformed', { TestGoFiles: 'store_test.go' }],
    ['XTestGoFiles null', { TestGoFiles: [], XTestGoFiles: null }],
    ['XTestGoFiles malformed', { TestGoFiles: [], XTestGoFiles: 'external_test.go' }],
    ['unsafe path', { TestGoFiles: ['../outside_test.go'] }],
    ['duplicate compiled file', { TestGoFiles: ['same_test.go'], XTestGoFiles: ['same_test.go'] }],
  ]) expectRejected(name, () => normalizeGoTestManifest(listed));
  return { omittedExternal: true, populatedExternal: true, negativeControls: 6 };
}

function transcriptControls() {
  const pkg = 'vram-governor/internal/store';
  const expected = ['TestAlpha', 'TestBeta'];
  const line = (Action, fields = {}) => JSON.stringify({ Action, Package: pkg, ...fields });
  const good = [
    line('start'),
    line('run', { Test: 'TestAlpha' }),
    line('pass', { Test: 'TestAlpha', Elapsed: 0.001 }),
    line('run', { Test: 'TestBeta' }),
    line('pass', { Test: 'TestBeta', Elapsed: 0.002 }),
    line('pass', { Elapsed: 0.003 }),
  ];
  // A complete passing control is parsed before any malformed transcript is
  // mutated, so the negative cases cannot pass by making the parser inert.
  parseGoJSON(good.join('\n'), expected, pkg);
  const nestedPass = [
    line('start'),
    line('run', { Test: 'TestAlpha' }),
    line('run', { Test: 'TestAlpha/child' }),
    line('pass', { Test: 'TestAlpha/child', Elapsed: 0.001 }),
    line('pass', { Test: 'TestAlpha', Elapsed: 0.002 }),
    line('pass', { Elapsed: 0.003 }),
  ];
  parseGoJSON(nestedPass.join('\n'), ['TestAlpha'], pkg);
  const topLevelSlashPass = [
    line('start'),
    line('run', { Test: 'TestAlpha' }),
    line('run', { Test: 'TestAlpha/mutation/hot_vram' }),
    line('pass', { Test: 'TestAlpha/mutation/hot_vram', Elapsed: 0.001 }),
    line('pass', { Test: 'TestAlpha', Elapsed: 0.002 }),
    line('run', { Test: 'TestBeta' }),
    line('pass', { Test: 'TestBeta', Elapsed: 0.001 }),
    line('pass', { Elapsed: 0.003 }),
  ];
  parseGoJSON(topLevelSlashPass.join('\n'), expected, pkg);
  const nestedSlashPass = [
    line('start'),
    line('run', { Test: 'TestAlpha' }),
    line('run', { Test: 'TestAlpha/parent' }),
    line('run', { Test: 'TestAlpha/parent/query/warm_ram' }),
    line('pass', { Test: 'TestAlpha/parent/query/warm_ram', Elapsed: 0.001 }),
    line('pass', { Test: 'TestAlpha/parent', Elapsed: 0.002 }),
    line('pass', { Test: 'TestAlpha', Elapsed: 0.003 }),
    line('run', { Test: 'TestBeta' }),
    line('pass', { Test: 'TestBeta', Elapsed: 0.001 }),
    line('pass', { Elapsed: 0.004 }),
  ];
  parseGoJSON(nestedSlashPass.join('\n'), expected, pkg);
  const rejected = [];
  const reject = (name, lines, want = expected, packageName = pkg) => {
    expectRejected(name, () => parseGoJSON(lines.join('\n'), want, packageName));
    rejected.push(name);
  };
  const rejectWithMessage = (name, lines, expectedMessage, want = expected, packageName = pkg) => {
    let caught;
    try { parseGoJSON(lines.join('\n'), want, packageName); } catch (error) { caught = error; }
    if (!caught) throw new Error(`source-only negative control was accepted: ${name}`);
    if (!String(caught.message).includes(expectedMessage)) throw new Error(`${name} rejected for the wrong reason: ${caught.message}`);
    rejected.push(name);
  };
  reject('missing parent', [good[0], good[1], good[2], good[5]]);
  reject('missing terminal pass', [good[0], good[1], good[2], good[3], good[5]]);
  reject('duplicate parent start', [good[0], good[1], good[1], ...good.slice(2)]);
  reject('duplicate terminal event', [...good.slice(0, 3), good[2], ...good.slice(3)]);
  reject('failed parent', [good[0], good[1], line('fail', { Test: 'TestAlpha', Elapsed: 0.001 })]);
  reject('skipped parent', [good[0], good[1], line('skip', { Test: 'TestAlpha', Elapsed: 0.001 })]);
  reject('failed nested test', [good[0], line('run', { Test: 'TestAlpha' }), line('run', { Test: 'TestAlpha/child' }), line('fail', { Test: 'TestAlpha/child', Elapsed: 0.001 })], ['TestAlpha']);
  reject('foreign package', [good[0], JSON.stringify({ Action: 'run', Package: 'foreign/pkg', Test: 'TestAlpha' })]);
  reject('foreign test', [good[0], line('run', { Test: 'TestForeign' })]);
  reject('malformed JSON', [good[0], '{']);
  reject('malformed event schema', [good[0], line('output', { Output: 17 })]);
  reject('out-of-order registration', [good[0], good[3], good[4], good[1], good[2], good[5]]);
  reject('premature package completion', [good[0], good[5], ...good.slice(1)]);
  reject('failed package terminal', [...good.slice(0, 5), line('fail', { Elapsed: 0.003 })]);
  reject('skipped package terminal', [...good.slice(0, 5), line('skip', { Elapsed: 0.003 })]);
  reject('duplicate package terminal', [...good, good[5]]);
  reject('test elapsed exceeds package command budget', [good[0], good[1], line('pass', { Test: 'TestAlpha', Elapsed: maxGoTestElapsedSeconds + 0.001 })]);
  reject('package elapsed exceeds package command budget', [...good.slice(0, 5), line('pass', { Elapsed: maxGoTestElapsedSeconds + 0.001 })]);
  rejectWithMessage('slash child missing observed owner', [good[0], line('run', { Test: 'TestAlpha/mutation/hot_vram' })], 'no active observed top-level owner', ['TestAlpha', 'TestBeta']);
  rejectWithMessage('slash child orphaned from observed owner', [good[0], line('run', { Test: 'TestAlpha/parent/query/warm_ram' })], 'no active observed top-level owner', ['TestAlpha', 'TestBeta']);
  rejectWithMessage('completed nearest ancestor cannot fall back to active root', [
    good[0], line('run', { Test: 'TestAlpha' }), line('run', { Test: 'TestAlpha/branch' }),
    line('pass', { Test: 'TestAlpha/branch', Elapsed: 0.001 }),
    line('run', { Test: 'TestAlpha/branch/mutation/hot_vram' }),
  ], 'nearest observed ancestor is not running: TestAlpha/branch', ['TestAlpha', 'TestBeta']);
  rejectWithMessage('ancestor cannot finish before observed slash descendant', [
    good[0], line('run', { Test: 'TestAlpha' }), line('run', { Test: 'TestAlpha/branch' }),
    line('run', { Test: 'TestAlpha/branch/mutation/hot_vram' }),
    line('pass', { Test: 'TestAlpha/branch', Elapsed: 0.001 }),
  ], 'parent ended before nested child TestAlpha/branch', ['TestAlpha', 'TestBeta']);
  rejectWithMessage('duplicate slash child run', [
    good[0], line('run', { Test: 'TestAlpha' }), line('run', { Test: 'TestAlpha/mutation/hot_vram' }),
    line('run', { Test: 'TestAlpha/mutation/hot_vram' }),
  ], 'duplicate Go test start TestAlpha/mutation/hot_vram', ['TestAlpha', 'TestBeta']);
  rejectWithMessage('failed slash child', [
    good[0], line('run', { Test: 'TestAlpha' }), line('run', { Test: 'TestAlpha/mutation/hot_vram' }),
    line('fail', { Test: 'TestAlpha/mutation/hot_vram', Elapsed: 0.001 }),
  ], 'Go test did not pass: TestAlpha/mutation/hot_vram fail', ['TestAlpha', 'TestBeta']);
  rejectWithMessage('skipped slash child', [
    good[0], line('run', { Test: 'TestAlpha' }), line('run', { Test: 'TestAlpha/mutation/hot_vram' }),
    line('skip', { Test: 'TestAlpha/mutation/hot_vram', Elapsed: 0.001 }),
  ], 'Go test did not pass: TestAlpha/mutation/hot_vram skip', ['TestAlpha', 'TestBeta']);
  rejectWithMessage('late slash child after package terminal', [
    ...good, line('run', { Test: 'TestAlpha/mutation/hot_vram' }),
  ], 'Go test event outside active package', expected);
  rejectWithMessage('package cannot finish with an active test', [
    good[0], line('run', { Test: 'TestAlpha' }), line('pass', { Test: 'TestAlpha', Elapsed: 0.001 }),
    line('run', { Test: 'TestBeta' }), line('pass', { Elapsed: 0.002 }),
  ], 'Go package ended while test descendants were still running', expected);
  return { positive: true, nestedPositive: true, slashNestedPositive: true, negativeControls: rejected };
}

function sourceOnly() {
  const files = readSources();
  const domain = files.get('internal/domain/workload.go');
  const store = files.get('internal/store/store.go');
  const memory = files.get('internal/store/memory.go');
  const postgres = files.get('internal/store/postgres_workloads.go');
  const pgFake = files.get('internal/store/postgres_contract_test.go');
  const tests = files.get('internal/store/residency_origin_test.go');
  const manager = files.get('internal/workloads/manager.go');
  const residency = files.get('internal/workloads/residency.go');
  const residencyTests = files.get('internal/workloads/residency_test.go');
  const verifier = files.get('scripts/verify-residency-origin.mjs');
  requireTokens(domain, ['LeaseOriginAcceleratorID', 'LeaseOriginWorkloadID', 'LeaseOriginFencingToken', 'LeaseOriginAllocated'], 'transition domain');
  requireTokens(store, ['validateResidencyTransitionLeaseOriginRequest', 'validateCurrentResidencyLeaseOrigin', 'verifyResidencyTransitionLeaseReplay', 'sameResidencyTransitionLeaseOrigin', 'begin as an unobserved planned transition'], 'store origin contract');
  requireTokens(memory, ['AllocateResidencyTransitionWithLease', 'GetResidencyTransitionByIdempotencyForLease', 'validateCurrentResidencyLeaseOrigin', 'MaxInt64'], 'memory store');
  requireTokens(postgres, ['AllocateResidencyTransitionWithLease', 'GetResidencyTransitionByIdempotencyForLease', 'lockResidencyLeaseOrigin', 'recheckLockedResidencyLeaseOrigin', 'SELECT accelerator_id,workload_id,fencing_token,expires_at FROM accelerator_leases WHERE accelerator_id=$1 FOR UPDATE', 'lease_origin_allocated'], 'PostgreSQL store');
  const allocatorStart = postgres.indexOf('func (p *PostgresWorkloadStore) AllocateResidencyTransitionWithLease(');
  const allocatorEnd = postgres.indexOf('\nfunc (p *PostgresWorkloadStore) GetResidencyTransitionByIdempotencyForLease(', allocatorStart);
  const allocator = postgres.slice(allocatorStart, allocatorEnd);
  const modelLock = allocator.indexOf('pg_advisory_xact_lock');
  const postModelExpiry = allocator.indexOf('recheckLockedResidencyLeaseOrigin', modelLock);
  const insert = allocator.indexOf('INSERT INTO residency_transitions');
  const postInsertExpiry = allocator.indexOf('recheckLockedResidencyLeaseOrigin', insert);
  if (allocatorStart < 0 || allocatorEnd < 0 || modelLock < 0 || postModelExpiry < modelLock || insert < 0 || postInsertExpiry < insert) throw new Error('leased allocator omits expiry checks after model wait and insertion');
  const leaseReplayStart = postgres.indexOf('func (p *PostgresWorkloadStore) GetResidencyTransitionByIdempotencyForLease(');
  const leaseReplayEnd = postgres.indexOf('\nfunc ', leaseReplayStart + 1);
  const leaseReplay = postgres.slice(leaseReplayStart, leaseReplayEnd);
  const transitionRead = leaseReplay.indexOf('readErr := tx.QueryRowContext');
  const expiryAfterRead = leaseReplay.indexOf('recheckLockedResidencyLeaseOrigin', transitionRead);
  const notFoundMapping = leaseReplay.indexOf('if readErr != nil { return nil, translateSQLError(readErr) }');
  const expiryBeforeCommit = leaseReplay.lastIndexOf('recheckLockedResidencyLeaseOrigin');
  const commit = leaseReplay.indexOf('tx.Commit()');
  if (leaseReplayStart < 0 || leaseReplayEnd < 0 || transitionRead < 0 || expiryAfterRead < transitionRead || notFoundMapping < expiryAfterRead || expiryBeforeCommit < notFoundMapping || commit < expiryBeforeCommit) {
    throw new Error('lease-bound replay must recheck expiry after any transition read outcome and immediately before commit');
  }
  requireTokens(pgFake, ['expireLeasesOnFenceLock', 'expireLeaseAfterModelLock', 'expireLeaseAfterTransitionLock', 'snapshotLeases', 'lease-fence:', 'r.LeaseOriginAcceleratorID != incoming.LeaseOriginAcceleratorID'], 'PostgreSQL semantic fake');
  const memoryUpdateStart = memory.indexOf('func (m *MemoryStore) UpdateResidencyTransition(');
  const memoryUpdateEnd = memory.indexOf('\nfunc ', memoryUpdateStart + 1);
  requireTokens(memory.slice(memoryUpdateStart, memoryUpdateEnd), ['verifyResidencyTransitionCanonical(current, transition, true)'], 'memory immutable origin update');
  const postgresUpdateStart = postgres.indexOf('func (p *PostgresWorkloadStore) UpdateResidencyTransition(');
  const postgresUpdateEnd = postgres.indexOf('\nfunc ', postgresUpdateStart + 1);
  requireTokens(postgres.slice(postgresUpdateStart, postgresUpdateEnd), ["body->>'idempotency_key'", "body->>'execution_fingerprint'", "body->>'fencing_token'", 'lease_origin_allocated'], 'PostgreSQL immutable origin update');
  requireTokens(residency, ['GetResidencyTransitionByIdempotencyForLease', 'AllocateResidencyTransitionWithLease'], 'lifecycle coordinator');
  requireTokens(residencyTests, ['TestLeasedHistoricalReplayFailsBeforeResidencyReconciliation', 'ErrResidencyTransitionConflict', 'TargetGeneration'], 'historical replay boundary test');
  requireTokens(residencyTests, ['TestLeasedEmptyIdempotencyKeyFailsBeforeResidencyReconciliation', 'ErrResidencyTransitionConflict', 'durable projection'], 'empty-key replay boundary test');
  const residencyReplayTestNames = ['TestLeasedHistoricalReplayFailsBeforeResidencyReconciliation', 'TestLeasedEmptyIdempotencyKeyFailsBeforeResidencyReconciliation'];
  requireTokens(residencyTests, residencyReplayTestNames.map((name) => `func ${name}(t *testing.T)`), 'lifecycle provenance boundary tests');
  const lifecycleStart = residency.indexOf('func (m *Manager) transitionModel(');
  const lifecycleEnd = residency.indexOf('\nfunc ', lifecycleStart + 1);
  if (lifecycleStart < 0 || lifecycleEnd < 0) throw new Error('missing bounded transitionModel lifecycle');
  const lifecycle = residency.slice(lifecycleStart, lifecycleEnd);
  const leasePreflight = lifecycle.indexOf('if lease != nil {');
  const emptyKeyPreflight = lifecycle.indexOf('if idempotencyKey == ""', leasePreflight);
  const emptyKeyLeaseRead = lifecycle.indexOf('GetAcceleratorLease(ctx, lease.AcceleratorID)', emptyKeyPreflight);
  const generationReconcile = lifecycle.indexOf('m.reconcileResidencyGeneration(target');
  const replayLookup = lifecycle.indexOf('GetResidencyTransitionByIdempotencyForLease');
  const earlyProjectionWrite = lifecycle.indexOf('persistResidencyProjection(ctx, projection, projection.Revision)');
  if (leasePreflight < 0 || emptyKeyPreflight < leasePreflight || emptyKeyLeaseRead < emptyKeyPreflight || replayLookup < leasePreflight || generationReconcile < leasePreflight || earlyProjectionWrite < replayLookup) {
    throw new Error('leased replay and empty-key validation must precede generation reconciliation and early projection writes');
  }
  const handoffStart = manager.indexOf('func (m *Manager) handoffAdmissionOwnedPlacementGeneration(');
  const handoffEnd = manager.indexOf('\n// Release-state fields share placementMu', handoffStart);
  if (handoffStart < 0 || handoffEnd < 0) throw new Error('missing bounded lifecycle handoff');
  const handoff = manager.slice(handoffStart, handoffEnd);
  requireTokens(handoff, ['transition.LeaseOriginAllocated', 'transition.LeaseOriginAcceleratorID != lease.AcceleratorID', 'transition.LeaseOriginWorkloadID != lease.WorkloadID', 'transition.LeaseOriginFencingToken != lease.FencingToken', 'GetAcceleratorLease(context.Background(), lease.AcceleratorID)', 'currentLease.ExpiresAt.After(time.Now())'], 'admission handoff');
  const inventory = exactTestInventory(tests, originTests, 'origin test');
  const sourceOnlyStart = verifier.indexOf('function sourceOnly() {');
  const sourceOnlyEnd = verifier.indexOf('\nasync function protocol()', sourceOnlyStart);
  if (sourceOnlyStart < 0 || sourceOnlyEnd < 0) throw new Error('missing isolated source-only verifier path');
  const sourceOnlyBody = verifier.slice(sourceOnlyStart, sourceOnlyEnd);
  if (/\bspawnSync\s*\(|\bexecFile(?:Sync)?\s*\(|\bwriteFile(?:Sync)?\s*\(|\bmkdir(?:Sync)?\s*\(|\bfetch\s*\(/.test(sourceOnlyBody)) throw new Error('source-only verifier path has a process, write, or network effect');
  const protocolStart = verifier.indexOf('\nasync function protocol() {') + 1;
  const packageStart = verifier.indexOf('const packages = [', protocolStart);
  const parserStart = verifier.indexOf('function parseGoJSON(');
  const protocolEnd = verifier.indexOf('\nfunction parseGoJSON(', protocolStart);
  const protocolBody = verifier.slice(protocolStart, protocolEnd);
  const packageInventoryTokens = ["path: './internal/store'", "path: './internal/workloads'", "run('go', ['test', '-json', pkg.path, '-count=1'"];
  const missingInventoryTokens = packageInventoryTokens.filter((token) => !protocolBody.includes(token));
  if (missingInventoryTokens.length || packageStart < 0 || parserStart < 0 || protocolBody.includes("'-run'") || protocolBody.includes('"-run"')) {
    throw new Error(`protocol verifier does not preserve the full package test inventory (missing=${missingInventoryTokens.join('|')})`);
  }
  requireTokens(protocolBody, ['protocolBudgetMs = 108_000', 'const timeout = Math.min(commandBudgetMs, remaining)', 'timeout, maxBuffer: 16 << 20', "'-timeout=44s'", '49_000'], 'bounded protocol budget');
  requireTokens(verifier, ['const maxGoTestElapsedSeconds = 45', 'event.Elapsed > maxGoTestElapsedSeconds', 'nestedPositive: true', 'slashNestedPositive: true', 'manifestControls()', 'transcriptControls()'], 'source-only protocol controls');
  requireTokens(tests, ['AllocateResidencyTransitionWithLease', 'foreign lease replay', 'origin Update', 'origin CAS', 'origin stripping Update', 'origin stripping CAS', 'rewrite Update error', 'TestPostgresLeaseOriginRechecksExpiryAfterModelAndTransitionWaits', 'TestPostgresLeaseBoundReplayRechecksExpiryAfterTransitionWait', 'missing-replay-key', 'ErrNotFound', 'expireLeaseAfterModelLock', 'expireLeaseAfterTransitionLock', 'expireLeasesOnFenceLock', 'FencingToken <= liveLease.FencingToken+10', 'TestPostgresLeaseOriginExpiresWhileWaitingForFenceSentinel', 'TestResidencyLeaseOriginUsesCanonicalVirtualResource', 'TestPostgresLeaseRenewAndReleaseSerializeOnSharedFence', 'virtual/virtual-target', 'legacy-shadow', 'math.MaxInt64', 'InsertFailureRollsBack'], 'origin tests');
  const manifest = manifestControls();
  const transcripts = transcriptControls();
  const fakeSentinel = pgFake.indexOf('if strings.HasPrefix(n, "insert into accelerator_lease_fences") && strings.Contains(n, "returning last_token")');
  const fakeLeaseRead = pgFake.indexOf('if strings.Contains(n, "from accelerator_leases")', fakeSentinel);
  if (fakeSentinel < 0 || fakeLeaseRead <= fakeSentinel) throw new Error('semantic PostgreSQL fake omits post-sentinel lease refresh/read');
  return { mode: 'source-only', files: sourceFiles.length, originInventory: inventory, lifecycleBoundaryInventory: residencyReplayTestNames, manifestControls: manifest, transcriptControls: transcripts, runtimeInventory: 'entire store and workloads package test source manifests', controls: 'provenance, lock ordering, expiry, replay, manifest schema, Go JSON parser and immutable write routes', effects: 'none' };
}

async function protocol() {
  const { spawnSync } = await import('node:child_process');
  const environment = { ...process.env, GOTOOLCHAIN: 'local', GOPROXY: 'off', GOSUMDB: 'off' };
  const protocolBudgetMs = 108_000;
  const deadline = Date.now() + protocolBudgetMs;
  const run = (command, args, label, commandBudgetMs) => {
    const remaining = deadline - Date.now();
    if (remaining <= 0) throw new Error(`${label} exceeded the total protocol budget`);
    const timeout = Math.min(commandBudgetMs, remaining);
    const result = spawnSync(command, args, { cwd: root, encoding: 'utf8', windowsHide: true, timeout, maxBuffer: 16 << 20, env: environment });
    if (result.error || result.signal || result.status !== 0 || typeof result.stdout !== 'string') throw new Error(`${label} failed (exit=${result.status ?? 'null'} signal=${result.signal ?? ''} error=${result.error?.message ?? ''}):\n${result.stdout ?? ''}\n${result.stderr ?? ''}`);
    return result.stdout;
  };
  const packages = [
    { path: './internal/store', importPath: 'vram-governor/internal/store' },
    { path: './internal/workloads', importPath: 'vram-governor/internal/workloads' },
  ];
  const results = [];
  for (const pkg of packages) {
    const listed = JSON.parse(run('go', ['list', '-json', pkg.path], `go list ${pkg.path}`, 5_000));
    if (!listed || listed.ImportPath !== pkg.importPath) throw new Error(`go list returned an invalid package identity for ${pkg.path}`);
    const testFiles = normalizeGoTestManifest(listed);
    const expected = [];
    for (const fileName of testFiles) {
      const absolute = path.resolve(root, pkg.path.slice(2), fileName);
      if (!absolute.startsWith(root + path.sep)) throw new Error(`unsafe test source from go list: ${fileName}`);
      const stat = fs.lstatSync(absolute);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.size > maxSourceBytes) throw new Error(`unbounded or non-regular test source ${fileName}`);
      const source = fs.readFileSync(absolute, 'utf8');
      expected.push(...[...source.matchAll(/^func (Test[A-Za-z0-9_]+)\(t \*testing\.T\)/gm)].map((match) => match[1]));
    }
    if (!expected.length || new Set(expected).size !== expected.length) throw new Error(`compiled test declaration inventory is empty or duplicated for ${pkg.path}`);
    const output = run('go', ['test', '-json', pkg.path, '-count=1', '-timeout=44s'], `go test ${pkg.path}`, 49_000);
    parseGoJSON(output, expected, pkg.importPath);
    results.push({ package: pkg.importPath, tests: expected.length, result: 'PASS' });
  }
  if (Date.now() > deadline) throw new Error('protocol exceeded its total bounded runtime budget');
  return { mode: 'protocol', result: 'PASS', budgetMs: protocolBudgetMs, packages: results, effects: 'bounded local test commands; network dependency resolution disabled' };
}

function parseGoJSON(output, expected, expectedPackage) {
  const states = new Map();
  const observedParents = [];
  let packageState = '';
  let packageStarted = false;
  for (const line of output.split(/\r?\n/)) {
    if (!line.trim()) continue;
    let event;
    try { event = JSON.parse(line); } catch { throw new Error('Go test emitted malformed JSON'); }
    if (!event || typeof event !== 'object' || Array.isArray(event) || event.Package !== expectedPackage || typeof event.Action !== 'string' ||
      Object.keys(event).some((key) => !['Action', 'Package', 'Test', 'Output', 'Elapsed', 'Time'].includes(key)) ||
      (event.Action === 'output' ? typeof event.Output !== 'string' : event.Output !== undefined) ||
      (event.Elapsed !== undefined && (typeof event.Elapsed !== 'number' || !Number.isFinite(event.Elapsed) || event.Elapsed < 0 || event.Elapsed > maxGoTestElapsedSeconds))) {
      throw new Error('Go test emitted a malformed, foreign, or out-of-bounds event');
    }
    if (event.Test === undefined) {
      if (event.Action === 'start') {
        if (packageStarted || packageState || observedParents.length || event.Output !== undefined || event.Elapsed !== undefined) throw new Error('Go package started more than once or out of order');
        packageStarted = true;
        packageState = 'running';
      } else if (event.Action === 'output') {
        if (packageState !== 'running') throw new Error('Go package output outside active package');
      } else if (['pass', 'fail', 'skip'].includes(event.Action)) {
        if (packageState !== 'running' || event.Action !== 'pass' || event.Elapsed === undefined) throw new Error('Go package did not pass with bounded terminal timing');
        if ([...states.values()].some((state) => state === 'running')) throw new Error('Go package ended while test descendants were still running');
        packageState = event.Action;
      } else throw new Error(`unexpected package event ${event.Action}`);
      continue;
    }
    if (packageState !== 'running' || typeof event.Test !== 'string' || !event.Test) throw new Error('Go test event outside active package or missing test name');
    const name = event.Test;
    const parent = name.split('/')[0];
    if (!expected.includes(parent)) throw new Error(`foreign Go test result ${name}`);
    if (event.Action === 'run') {
      if (states.has(name)) throw new Error(`duplicate Go test start ${name}`);
      if (name.includes('/')) {
        if (states.get(parent) !== 'running') throw new Error(`nested Go test has no active observed top-level owner ${name}`);
        let nearestObservedAncestor = name;
        while (nearestObservedAncestor.includes('/')) {
          nearestObservedAncestor = nearestObservedAncestor.slice(0, nearestObservedAncestor.lastIndexOf('/'));
          if (states.has(nearestObservedAncestor)) break;
        }
        if (!states.has(nearestObservedAncestor)) throw new Error(`nested Go test has no observed parent ${name}`);
        if (states.get(nearestObservedAncestor) !== 'running') throw new Error(`nested Go test nearest observed ancestor is not running: ${nearestObservedAncestor}`);
      }
      states.set(name, 'running');
      if (!name.includes('/')) observedParents.push(name);
    } else if (['pass', 'fail', 'skip'].includes(event.Action)) {
      if (states.get(name) !== 'running') throw new Error(`Go test terminal lacks unique run ${name}`);
      if ([...states].some(([child, state]) => child.startsWith(name + '/') && state === 'running')) throw new Error(`Go test parent ended before nested child ${name}`);
      states.set(name, event.Action);
      if (event.Action !== 'pass') throw new Error(`Go test did not pass: ${name} ${event.Action}`);
    } else if (event.Action === 'output') {
      if (states.get(name) !== 'running') throw new Error(`Go test output outside active test ${name}`);
    } else throw new Error(`unexpected Go test action ${event.Action}`);
  }
  if (!packageStarted || packageState !== 'pass' || observedParents.length !== expected.length || observedParents.some((name, index) => name !== expected[index])) {
    throw new Error(`Go package inventory was missing, failed, skipped, foreign, or out of declaration order for ${expectedPackage}`);
  }
  for (const name of expected) if (states.get(name) !== 'pass') throw new Error(`Go test lacks exact PASS: ${name}`);
}

async function main() {
  if (mode === '--mode=source-only') {
    console.log(JSON.stringify(sourceOnly()));
    console.log('residency lease origin source controls passed');
    return;
  }
  if (mode !== '--mode=protocol') throw new Error('usage: verify-residency-origin.mjs --mode=source-only|protocol');
  sourceOnly();
  const result = await protocol();
  console.log('residency lease origin verification passed');
  console.log(JSON.stringify(result));
}

main().catch((error) => {
  console.error(`FAIL ${error.message}`);
  process.exitCode = 1;
});
