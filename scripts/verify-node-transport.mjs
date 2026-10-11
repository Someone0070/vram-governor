import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== '--runtime')) {
  console.error('usage: node scripts/verify-node-transport.mjs [--runtime]');
  process.exit(2);
}

function source(relative) {
  return readFileSync(path.join(root, relative), 'utf8');
}

function requireMatch(condition, message) {
  if (!condition) throw new Error(message);
}

function functionBody(text, startDeclaration, endDeclaration) {
  const startToken = `\n${startDeclaration}`;
  const endToken = `\n${endDeclaration}`;
  const start = text.indexOf(startToken);
  const end = text.indexOf(endToken, start + startToken.length);
  requireMatch(start >= 0 && end > start && text.indexOf(startToken, start + startToken.length) < 0,
    `missing, duplicated, or unbounded source function: ${startDeclaration}`);
  return text.slice(start + 1, end + 1);
}

function parseGoImports(text) {
  const imports = [];
  let inBlock = false;
  for (const [index, rawLine] of text.split(/\r?\n/).entries()) {
    const line = rawLine.replace(/\/\/.*$/, '').trim();
    if (!line) continue;
    if (!inBlock && /^import\s+\($/.test(line)) {
      inBlock = true;
      continue;
    }
    if (inBlock && line === ')') {
      inBlock = false;
      continue;
    }
    const single = !inBlock && line.match(/^import\s+"([^"]+)"$/);
    if (single) {
      imports.push(single[1]);
      continue;
    }
    const grouped = inBlock && line.match(/^"([^"]+)"$/);
    if (grouped) {
      imports.push(grouped[1]);
      continue;
    }
    if (/^import\b/.test(line) || inBlock) {
      throw new Error(`malformed Go import at line ${index + 1}`);
    }
  }
  if (inBlock) throw new Error('unterminated Go import block');
  return imports;
}

function verifyImportParser() {
  requireMatch(JSON.stringify(parseGoImports('package p\nimport "github.com/coder/websocket"\n')) ===
    JSON.stringify(['github.com/coder/websocket']), 'Go import parser must accept the actual single-line limits import form');
  requireMatch(JSON.stringify(parseGoImports('package p\nimport (\n "bytes"\n "testing"\n)\n')) ===
    JSON.stringify(['bytes', 'testing']), 'Go import parser must accept grouped imports');
  let malformedRejected = false;
  try { parseGoImports('package p\nimport (\n "bytes" ???\n)\n'); } catch { malformedRejected = true; }
  requireMatch(malformedRejected, 'Go import parser must reject malformed import declarations');
}

function verifySourceIntegration() {
  verifyImportParser();
  const limits = source('internal/nodetransport/limits.go');
  const packageImports = parseGoImports(limits);
  requireMatch(JSON.stringify(packageImports) === JSON.stringify(['github.com/coder/websocket']),
    'shared transport package must import only coder/websocket and standard-library-free declarations');
  requireMatch(/const ControlMessageLimit int64 = 4 << 20/.test(limits) &&
    /func ApplyControlMessageLimit\(conn \*websocket\.Conn\) \{\s*conn\.SetReadLimit\(ControlMessageLimit\)/s.test(limits),
  'shared transport helper must set a positive finite 4 MiB read limit');
  requireMatch(!/SetReadLimit\(-1\)|SetReadLimit\(0\)/.test(limits), 'shared transport helper must not disable the read bound');

  const controller = functionBody(source('internal/api/ws.go'), 'func (s *Server) handleNodeWS(w http.ResponseWriter, r *http.Request) {', 'func ');
  const acceptAt = controller.indexOf('websocket.Accept(w, r, nil)');
  const controllerLimitAt = controller.indexOf('nodetransport.ApplyControlMessageLimit(conn)');
  const controllerReadAt = controller.indexOf('wsjson.Read(ctx, conn, &env)');
  requireMatch(controller.includes('if !s.checkAuth(r)') && acceptAt >= 0 &&
    acceptAt < controllerLimitAt && controllerLimitAt < controllerReadAt,
  'controller must authenticate, accept, set the shared limit, and only then read its first envelope');

  const agent = functionBody(source('internal/nodeagent/agent.go'), 'func runOnce(ctx context.Context, cfg *Config, log *slog.Logger, sampler *SystemSampler, logs func() []logging.Entry, processors ...*commandProcessor) (time.Duration, error) {', 'func sendHeartbeat(');
  const dialAt = agent.indexOf('websocket.Dial(ctx, cfg.ControllerURL');
  const agentLimitAt = agent.indexOf('nodetransport.ApplyControlMessageLimit(conn)');
  const agentReadAt = agent.indexOf('wsjson.Read(ctx, conn, &ackEnv)');
  requireMatch(agent.includes('header.Set("Authorization", "Bearer "+cfg.Token)') && dialAt >= 0 &&
    dialAt < agentLimitAt && agentLimitAt < agentReadAt,
  'agent must preserve its auth setup, dial, set the shared limit, and only then read its first envelope');

  const tests = source('internal/nodetransport/limits_test.go');
  const testImports = parseGoImports(tests);
  requireMatch(JSON.stringify(testImports) === JSON.stringify([
    'bytes', 'context', 'errors', 'fmt', 'net/http', 'net/http/httptest', 'strings', 'testing', 'time', 'github.com/coder/websocket',
  ]), 'isolated transport tests must use only standard-library and websocket dependencies');
  requireMatch(!tests.includes('vram-governor/internal/') && !limits.includes('vram-governor/internal/'),
    'isolated node transport package must not depend on application, API, agent, or observer packages');
  for (const name of [
    'TestDefaultReadLimitRejectsLegitimate64KiBControlJSON',
    'TestSharedLimitAcceptsLegitimateLargeControlJSONBothDirections',
    'TestSharedLimitAllowsExactBoundaryBothDirections',
    'TestSharedLimitRejectsBoundaryPlusOneBothDirections',
    'TestOversizeRejectionLeavesReconnectUsable',
  ]) {
    requireMatch(tests.includes(`func ${name}(t *testing.T) {`), `transport test scenario is missing: ${name}`);
  }
  requireMatch(tests.includes('context.WithTimeout(context.Background(), 8*time.Second)') &&
    tests.includes('defer server.Close()') && tests.includes('defer client.CloseNow()'),
  'websocket tests must bound exchanges and close both local endpoints');
  requireMatch(tests.includes('websocket.CloseStatus(err) != websocket.StatusMessageTooBig') &&
    tests.includes('if serverErr != nil {\n\t\t\treturn serverErr') &&
    !tests.includes('!(wantTooBig && side == clientReceives)'),
  'client oversize coverage may ignore only the expected 1009 write-close and must return every unexpected server error');
}

try {
  verifySourceIntegration();
  if (args.length === 0) {
    console.log('node transport integration source verification passed');
    process.exit(0);
  }

  const goExe = path.join(process.env.USERPROFILE ?? '', 'go', 'pkg', 'mod', 'golang.org', 'toolchain@v0.0.1-go1.23.4.windows-amd64', 'bin', 'go.exe');
  const result = spawnSync(goExe, ['test', '-count=1', './internal/nodetransport'], {
    cwd: root,
    encoding: 'utf8',
    timeout: 180_000,
    maxBuffer: 4 * 1024 * 1024,
    env: { ...process.env, GOPROXY: 'off', GOSUMDB: 'off', GOTOOLCHAIN: 'local' },
  });
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (result.error || result.status === null || result.status !== 0) {
    if (output) process.stderr.write(output);
    throw result.error ?? new Error(`isolated node transport tests exited ${result.status ?? 'without a status'}`);
  }
  console.log(output.trim());
  console.log('isolated node transport runtime verification passed');
} catch (error) {
  console.error(error?.stack ?? String(error));
  process.exitCode = 1;
}
