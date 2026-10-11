import { spawnSync } from 'node:child_process';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const original = path.join(root, 'scripts', 'verify-checkpoint-load-custody.mjs');
const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && !['--faults', '--regressions'].includes(args[0]))) {
  console.error('usage: node scripts/verify-checkpoint-staging-reuse.mjs [--faults|--regressions]');
  process.exit(2);
}

const deadline = Date.now() + 1_170_000;
function expectedMarker(verifierArgs) {
  const faults = verifierArgs.includes('--faults');
  if (verifierArgs.includes('--reuse')) return faults ? 'checkpoint staging reuse fault verification passed' : 'checkpoint staging reuse verification passed';
  if (verifierArgs.includes('--controlled-source')) return faults ? 'checkpoint controlled source fault verification passed' : 'checkpoint controlled source verification passed';
  if (verifierArgs.includes('--lifecycle')) return faults ? 'checkpoint source lifecycle fault verification passed' : 'checkpoint source lifecycle verification passed';
  if (verifierArgs.includes('--kernel')) return 'checkpoint load custody kernel verification passed';
  return faults ? 'checkpoint load custody fault verification passed' : 'checkpoint load custody verification passed';
}

function runVerifier(verifierArgs) {
  const remaining = deadline - Date.now();
  if (remaining <= 0) throw new Error('checkpoint staging reuse regression budget expired before the next selector');
  const result = spawnSync(process.execPath, [original, ...verifierArgs], {
    cwd: root,
    encoding: 'utf8',
    timeout: remaining,
    maxBuffer: 32 * 1024 * 1024,
  });
  const output = (result.stdout ?? '') + (result.stderr ?? '');
  if (result.stdout) process.stdout.write(result.stdout);
  if (result.stderr) process.stderr.write(result.stderr);
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(`custody verifier ${verifierArgs.join(' ')} exited ${result.status ?? 'without a status'}`);
  const marker = expectedMarker(verifierArgs);
  if (output.split(marker).length !== 2) throw new Error(`custody verifier ${verifierArgs.join(' ')} did not emit exactly one success marker: ${marker}`);
}

if (args[0] === '--regressions') {
  runVerifier(['--kernel', '--remote-proxmox']);
  runVerifier(['--faults', '--remote-proxmox']);
  runVerifier(['--lifecycle', '--faults', '--remote-proxmox']);
  runVerifier(['--controlled-source', '--remote-proxmox', '--faults']);
  runVerifier(['--reuse', '--remote-proxmox', '--faults']);
  console.log('checkpoint staging reuse regression verification passed');
} else {
  runVerifier(args[0] === '--faults' ? ['--reuse', '--remote-proxmox', '--faults'] : ['--reuse', '--remote-proxmox']);
}
