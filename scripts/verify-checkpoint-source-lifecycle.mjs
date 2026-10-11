import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const args = process.argv.slice(2);
const allowed = new Set(['--faults', '--regressions']);
if (args.some((arg) => !allowed.has(arg)) || new Set(args).size !== args.length || (args.includes('--faults') && args.includes('--regressions'))) {
  console.error('usage: node scripts/verify-checkpoint-source-lifecycle.mjs [--faults|--regressions]');
  process.exit(2);
}

function runVerifier(route, expectedToken) {
  const result = spawnSync(process.execPath, [
    path.join(root, 'scripts/verify-checkpoint-load-custody.mjs'),
    '--remote-proxmox', ...route,
  ], { cwd: root, encoding: 'utf8', timeout: 1_200_000, maxBuffer: 32 * 1024 * 1024 });
  if (result.error) throw result.error;
  const output = `${result.stdout ?? ''}${result.stderr ?? ''}`;
  if (result.status !== 0) {
    process.stderr.write(output);
    throw new Error(`checkpoint custody verifier exited ${result.status ?? 'without a status'}`);
  }
  const tokens = output.split(/\r?\n/).filter((line) => line === expectedToken);
  if (tokens.length !== 1) throw new Error(`checkpoint custody route did not emit exactly one success token: expected=${expectedToken}, count=${tokens.length}`);
}

if (args.includes('--regressions')) {
  runVerifier([], 'checkpoint load custody verification passed');
  runVerifier(['--kernel'], 'checkpoint load custody kernel verification passed');
  runVerifier(['--faults'], 'checkpoint load custody fault verification passed');
  console.log('checkpoint source lifecycle custody regressions passed');
} else {
  const route = ['--lifecycle'];
  if (args.includes('--faults')) route.push('--faults');
  runVerifier(route, args.includes('--faults') ? 'checkpoint source lifecycle fault verification passed' : 'checkpoint source lifecycle verification passed');
  console.log(args.includes('--faults') ? 'checkpoint source lifecycle fault verification passed' : 'checkpoint source lifecycle verification passed');
}
