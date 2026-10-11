import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const unitPath = path.join(root, 'deploy', 'cmp-runtime', 'llama-server-router.conf');
const expectedModelMount = '/mnt/models/ollama';
const expectedModelSource = '/etc/vram-governor/llama-models';
const expectedProfileEnv = '/etc/vram-governor/cmp-llama-profile.env';
const expectedExecStart = [
  '/root/llama.cpp/build/bin/llama-server',
  '--host', '127.0.0.1',
  '--port', '8080',
  '--no-webui',
  '--models-dir', expectedModelSource,
  '--models-max', '1',
  '--no-models-autoload',
  '--ctx-size', '${LLAMA_CTX_SIZE}',
  '--parallel', '${LLAMA_PARALLEL}',
  '--metrics',
].join(' ');

function parseUnit(text) {
  const sections = new Map();
  let section = null;
  for (const [lineIndex, raw] of text.split(/\r?\n/).entries()) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const sectionMatch = line.match(/^\[([A-Za-z][A-Za-z0-9]*)\]$/);
    if (sectionMatch) {
      section = sectionMatch[1];
      if (sections.has(section)) throw new Error(`duplicate [${section}] section`);
      sections.set(section, []);
      continue;
    }
    const separator = line.indexOf('=');
    if (!section || separator <= 0) throw new Error(`invalid unit directive at line ${lineIndex + 1}`);
    sections.get(section).push({ key: line.slice(0, separator).trim(), value: line.slice(separator + 1).trim() });
  }
  return sections;
}

function validateRouterUnit(text) {
  const sections = parseUnit(text);
  const unit = sections.get('Unit') ?? [];
  const service = sections.get('Service') ?? [];
  assert.deepEqual([...sections.keys()], ['Unit', 'Service'], 'router unit must contain only its reviewed Unit and Service sections');
  assert.deepEqual(unit, [{ key: 'RequiresMountsFor', value: expectedModelMount }], 'model mount must be required before router startup');
  assert.equal(service.filter(({ key }) => key === 'EnvironmentFile').length, 1, 'exactly one fixed profile environment file is permitted');
  assert.deepEqual(service.filter(({ key }) => key === 'EnvironmentFile').map(({ value }) => value), [expectedProfileEnv]);
  assert.equal(service.some(({ key }) => ['Environment', 'PassEnvironment', 'UnsetEnvironment'].includes(key)), false,
    'runtime profile values must come only from the fixed profile environment file');
  const execStart = service.filter(({ key }) => key === 'ExecStart').map(({ value }) => value);
  assert.deepEqual(execStart, ['', expectedExecStart], 'fixed llama-server arguments and systemd ExecStart reset must remain unchanged');
  assert.equal(service.length, 3, 'unexpected service directives could change router behavior or authority');
  assert.deepEqual(service.map(({ key }) => key), ['EnvironmentFile', 'ExecStart', 'ExecStart']);
}

function verifyFixtures(actual) {
  validateRouterUnit(actual);
  const missingDependency = actual.replace(/^RequiresMountsFor=\/mnt\/models\/ollama\r?\n/m, '');
  assert.notEqual(missingDependency, actual);
  assert.throws(() => validateRouterUnit(missingDependency), /model mount must be required/,
    'removing the model mount dependency must fail decisively');
  const wrongDependency = actual.replace('RequiresMountsFor=/mnt/models/ollama', 'RequiresMountsFor=/mnt/models/other');
  assert.notEqual(wrongDependency, actual);
  assert.throws(() => validateRouterUnit(wrongDependency), /model mount must be required/,
    'pointing the dependency at a different mount must fail decisively');
}

const unit = readFileSync(unitPath, 'utf8');
verifyFixtures(unit);
console.log('router mount ordering configuration verification passed');
