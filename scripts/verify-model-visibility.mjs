import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from '../web/ui/node_modules/typescript/lib/typescript.js';

function ensure(condition, diagnostic) {
  if (!condition) throw new Error(`model visibility verification failed: ${diagnostic}`);
}

function mutateOnce(source, before, after, label) {
  ensure(source.split(before).length === 2, `${label} mutation anchor is not unique`);
  const mutant = source.replace(before, after);
  ensure(mutant !== source, `${label} mutation did not change source`);
  return mutant;
}

function expectDiagnostic(action, diagnostic, label) {
  let failure;
  try { action(); } catch (error) { failure = error; }
  ensure(failure instanceof Error && failure.message === `model visibility verification failed: ${diagnostic}`,
    `${label} did not fail at its intended guard`);
}

const helper = readFileSync('web/ui/src/modelVisibility.ts', 'utf8');
const admin = readFileSync('web/ui/src/admin.tsx', 'utf8');
const distHtml = readFileSync('web/ui/dist/admin.html', 'utf8');
const bundleMatch = /<script\b[^>]*\bsrc="\/ui\/assets\/(admin-[A-Za-z0-9_-]+\.js)"/.exec(distHtml);
ensure(bundleMatch, 'admin distribution entry does not name one fixed admin bundle');
const bundlePath = `web/ui/dist/assets/${bundleMatch[1]}`;
const embeddedAdmin = readFileSync(bundlePath, 'utf8');

const targets = [
  { id: 'fixed', resident_models: ['qwen.gguf', 'qwen.gguf'], models: ['qwen.gguf'], supports_model_lifecycle: false },
  { id: 'router', resident_models: ['hot.gguf'], models: ['hot.gguf', 'cold.gguf'], supports_model_lifecycle: true },
  { id: 'empty', models: ['unloaded.gguf'], supports_model_lifecycle: false },
];
const expectedRows = ['fixed:qwen.gguf', 'router:hot.gguf'];

function verifyObservedHelper(source) {
  const compiled = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
  }).outputText;
  const context = { exports: {} };
  try { vm.runInNewContext(compiled, context, { filename: 'modelVisibility.js' }); }
  catch { throw new Error('model visibility verification failed: resident helper execution failed'); }
  const helperFn = context.exports.observedResidentModels;
  ensure(typeof helperFn === 'function', 'resident helper export is missing');
  let rows;
  try { rows = Array.from(helperFn(targets)); }
  catch { throw new Error('model visibility verification failed: resident helper result is malformed'); }
  ensure(rows.every((row) => row && typeof row === 'object' && row.target && typeof row.target === 'object' && typeof row.model === 'string'),
    'resident helper result is malformed');
  ensure(JSON.stringify(rows.map((row) => `${row.target.id}:${row.model}`)) === JSON.stringify(expectedRows),
    'helper exposed catalog-only models as resident');
  const fixedRow = rows.find((row) => row.target?.id === 'fixed' && row.model === 'qwen.gguf');
  ensure(fixedRow?.target?.supports_model_lifecycle === false,
    'fixed target output lost read-only lifecycle capability');
  ensure(fixedRow.target === targets[0], 'fixed target output did not preserve target identity');
  const managedRow = rows.find((row) => row.target?.id === 'router' && row.model === 'hot.gguf');
  ensure(managedRow?.target?.supports_model_lifecycle === true,
    'managed target output lost lifecycle capability');
  ensure(managedRow.target === targets[1], 'managed target output did not preserve target identity');
}

function verifyPageSource(source) {
  ensure(source.includes('observedResidentModels(data.targets)'), 'Models page is not wired to the observed-resident helper');
  ensure(source.includes('title="Loaded now"') && source.includes('Observed from runtime discovery'),
    'loaded-model card does not identify runtime-observed residency');
  ensure(source.includes('observed.map(({target,model})=>'),
    'loaded-model card is not rendered from helper-returned target/model rows');
  ensure(source.includes('Currently loaded models and guarded runtime controls.'),
    'page wording is not the guarded-controls wording');
  ensure(source.includes('Externally managed runtime.'), 'source omitted externally managed runtime wording');
  ensure(source.includes('target.supports_model_lifecycle?"managed":"read-only"'),
    'loaded-model card omits the read-only capability distinction');
  ensure(source.includes('<RuntimeControlCard target={target} node={node}'),
    'Models page is not wired to its actual runtime-control card');
}

function verifyEmbeddedBundle(source) {
  for (const phrase of [
    'Loaded now',
    'Externally managed runtime.',
    'Currently loaded models and guarded runtime controls.',
    'read-only',
    'resident_models',
  ]) ensure(source.includes(phrase), 'embedded admin distribution is missing a guarded model-visibility contract phrase');
}

// Establish real positive behavior before the decisive in-memory negative controls.
verifyObservedHelper(helper);
const capabilityLeak = mutateOnce(helper, 'map(model=>({target,model}))',
  'map(model=>({target:{...target,supports_model_lifecycle:true},model}))', 'fixed-target capability corruption');
expectDiagnostic(() => verifyObservedHelper(capabilityLeak), 'fixed target output lost read-only lifecycle capability',
  'fixed-target capability mutant');
const catalogLeak = mutateOnce(helper, 'target.resident_models||[]', 'target.models||[]', 'catalog-only model guard');
expectDiagnostic(() => verifyObservedHelper(catalogLeak), 'helper exposed catalog-only models as resident', 'catalog-only helper mutant');

verifyPageSource(admin);
const stalePageWording = mutateOnce(admin, 'Currently loaded models and guarded runtime controls.',
  'Currently loaded models and direct signed runtime controls.', 'stale page wording');
expectDiagnostic(() => verifyPageSource(stalePageWording), 'page wording is not the guarded-controls wording', 'stale page wording mutant');
const missingExternallyManaged = mutateOnce(admin, 'Externally managed runtime.', 'Runtime policy status unknown.',
  'externally-managed source wording');
expectDiagnostic(() => verifyPageSource(missingExternallyManaged), 'source omitted externally managed runtime wording',
  'externally-managed source wording mutant');
const missingReadOnly = mutateOnce(admin, 'target.supports_model_lifecycle?"managed":"read-only"',
  'target.supports_model_lifecycle?"managed":"managed"', 'read-only distinction');
expectDiagnostic(() => verifyPageSource(missingReadOnly), 'loaded-model card omits the read-only capability distinction', 'read-only distinction mutant');
const missingObservedHelper = mutateOnce(admin, 'observedResidentModels(data.targets)', 'data.targets.flatMap(target=>target.models||[])',
  'observed helper wiring');
expectDiagnostic(() => verifyPageSource(missingObservedHelper), 'Models page is not wired to the observed-resident helper', 'observed helper wiring mutant');

verifyEmbeddedBundle(embeddedAdmin);
const staleBundleWording = mutateOnce(embeddedAdmin, 'Currently loaded models and guarded runtime controls.',
  'Currently loaded models and direct signed runtime controls.', 'stale bundle wording');
expectDiagnostic(() => verifyEmbeddedBundle(staleBundleWording),
  'embedded admin distribution is missing a guarded model-visibility contract phrase', 'stale bundle wording mutant');

console.log('model visibility verification passed');
