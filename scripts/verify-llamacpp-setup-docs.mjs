import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';

const guidePath = 'docs/llamacpp-node-setup.md';
const guide = readFileSync(guidePath, 'utf8');
const connect = readFileSync('docs/connect-gpu-nodes-to-lb.md', 'utf8');
const agent = readFileSync('docs/node-agent.md', 'utf8');
const packageReadme = readFileSync('packaging/node-agent/README.txt', 'utf8');
const rootReadme = readFileSync('README.md', 'utf8');
const build = readFileSync('scripts/build-node-agent-package.ps1', 'utf8');

for (const marker of [
  '/health', '/v1/models', '/slots', 'public_endpoint',
  'router_managed: false', 'capacity_verified: true',
  'dont_touch', 'drain', 'allowlist', 'rolls back',
  'standalone fixed server',
]) {
  assert.ok(guide.includes(marker), `guide lacks ${marker}`);
}
assert.match(guide, /Changing that fixed service manually is maintenance/);
assert.match(guide, /not\*\* a tested\s+installer/);
assert.match(guide, /does\s+not install `\/models\/load`/);
assert.match(connect, /\[the existing llama\.cpp server setup\]\(llamacpp-node-setup\.md\)/);
assert.match(agent, /\[existing-server setup checklist\]\(llamacpp-node-setup\.md\)/);
assert.match(packageReadme, /included docs\/llamacpp-node-setup\.md/);
assert.match(rootReadme, /\[Add an existing llama\.cpp server\]\(docs\/llamacpp-node-setup\.md\)/);
for (const name of ['llamacpp-node-setup.md', 'connect-gpu-nodes-to-lb.md', 'ollama-multi-profile.md']) {
  assert.ok(build.includes(`'${name}'`), `packager does not include ${name}`);
}
for (const match of guide.matchAll(/\]\(([^)]+\.md)\)/g)) {
  assert.ok(existsSync(path.join(path.dirname(guidePath), match[1])), `broken relative guide link ${match[1]}`);
}
console.log('llama.cpp setup documentation verification passed');
