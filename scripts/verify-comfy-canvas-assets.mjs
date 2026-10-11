#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { createReadStream } from 'node:fs'
import { lstat, readFile, readdir, stat } from 'node:fs/promises'
import path from 'node:path'
import process from 'node:process'

const root = process.cwd()
const mode = process.argv[2]
const expected = new Map([
  ['web/comfy/vendor/ComfyUI_frontend-v1.51.9-source.tar.gz', { bytes: 55_919_360, sha256: 'fd8c4ef68b65d84a4125a624fa5980cad0b1c12b7ae5c58bec4b261e8863dc87' }],
  ['web/comfy/vendor/ComfyUI_frontend-v1.51.9-dist.zip', { bytes: 22_760_363, sha256: '313dfff441f6ba9d4fb6f18baadd990df34c8da149d3995091e41c5928552c99' }],
  ['web/comfy/vendor/comfyui_workflow_templates-0.11.50.tar.gz', { bytes: 18_739, sha256: '402a7310867eef9481a78d93f0164beed781f1f79eb8f58be1d85dfa77247d20' }],
  ['web/comfy/vendor/comfyui_workflow_templates_json-0.1.61.tar.gz', { bytes: 2_626_805, sha256: 'c39d2477ccf845e666f3ef1e149b2b05068298790fa02b9fd20e9a2964340b2f' }],
  ['web/comfy/vendor/comfyui_workflow_templates_media_image-0.3.160.tar.gz', { bytes: 89_352_862, sha256: '88dcf749302c6a12f5b803dfb46724b4c8acc31d1117cecff51672d9bd85eb18' }],
  ['web/comfy/vendor/comfyui_workflow_templates_media_video-0.3.101.tar.gz', { bytes: 104_340_610, sha256: '7652ed99fb9bb00b39d8905919dc81509201e335dde23a9736ba138919908476' }],
  ['web/comfy/upstream/frontend-1.51.9/pnpm-lock.yaml', { bytes: 623_093, sha256: '37c632265a683d9ee593f21d0f2d7fa5de44f840f59c2e4ce65356216d8824d3' }],
  ['configs/comfy-bootstrap/image-sdxl-base-canvas.json', { bytes: 10_997, sha256: 'a9856bb0dcf02f0a677497eeebbf664d810ad4a6d74ddd1b4ed0d84a22a5d28a' }],
  ['web/comfy/templates/image_sdxl_simple.json', { bytes: 10_997, sha256: 'a9856bb0dcf02f0a677497eeebbf664d810ad4a6d74ddd1b4ed0d84a22a5d28a' }],
  ['configs/comfy-bootstrap/video-wan22-5b-canvas.json', { bytes: 14_523, sha256: '50390798a133757075d750ab78b26274e3bf3e4a09f46aaa2f08d9559e62750b' }],
  ['web/comfy/templates/video_wan2_2_5B_ti2v.json', { bytes: 14_523, sha256: '50390798a133757075d750ab78b26274e3bf3e4a09f46aaa2f08d9559e62750b' }],
  ['web/comfy/templates/image_sdxl_simple-1.webp', { bytes: 190_310, sha256: 'edbd2ddcd6f4926a63721c390c88e56f9c4694e0830e40c50a31990718e63633' }],
  ['web/comfy/templates/video_wan2_2_5B_ti2v-1.webp', { bytes: 653_120, sha256: '972226640f44a2d9e8051da7d224058e14ea1404643f761ced8ee5454d35c593' }],
  ['configs/comfy-bootstrap/image-sdxl-base.json', { bytes: 913, sha256: '40fe6eded06014ff813ce905949d3c53cbc1fbd6cc5759c7acd82780be69a5a8' }],
  ['configs/comfy-bootstrap/image-sdxl-smoke.json', { bytes: 789, sha256: '0e8ccf12b9eb3738f4c078a99c742d9f2f2fb74be5a67fd259d66c016ebf4a44' }],
  ['configs/comfy-bootstrap/video-wan22-5b.json', { bytes: 1_344, sha256: '96133af8299f4d240f435a8d855af33298d525c7396822c5cb67052ce70ee77a' }],
  ['configs/comfy-bootstrap/video-wan22-5b-smoke.json', { bytes: 1_247, sha256: '18bfc85148b6679b17dd0fd41db3f6480c4d9bb1e75bd7a6241d83fb038429b7' }],
  ['configs/comfy-bootstrap/models.json', { bytes: 1_889, sha256: '73554ae4de040534136e63da62ca5fce05ed05f3aa35332415d2d5d49e91cdf0' }],
  ['configs/comfy-bootstrap/profiles.json', { bytes: 2_788, sha256: '2eaf84c14c63bc29df312d083bc110ab665c1b17d6bf3ea655bdc1f70f4525dd' }],
  ['configs/comfy-bootstrap/workflow-metadata.json', { bytes: 543, sha256: 'e92d80ed68da5a52f2a9926d12d84f666ba083ccd8943ef0d1d834ada8d76fae' }
])

function fail(message) {
  throw new Error(message)
}

function absolute(relative) {
  const candidate = path.resolve(root, relative)
  const relativeBack = path.relative(root, candidate)
  if (relativeBack.startsWith('..') || path.isAbsolute(relativeBack)) {
    fail(`Path escaped workspace: ${relative}`)
  }
  return candidate
}

async function hashFile(relative, maxBytes = 250_000_000) {
  const filename = absolute(relative)
  const info = await lstat(filename)
  if (!info.isFile() || info.isSymbolicLink()) fail(`Expected regular file: ${relative}`)
  if (info.size > maxBytes) fail(`File exceeds read bound: ${relative}`)
  const digest = createHash('sha256')
  for await (const chunk of createReadStream(filename)) digest.update(chunk)
  return { bytes: info.size, sha256: digest.digest('hex') }
}

async function assertPinnedFiles() {
  let total = 0
  for (const [relative, pin] of expected) {
    const measured = await hashFile(relative)
    total += measured.bytes
    if (measured.bytes !== pin.bytes || measured.sha256 !== pin.sha256) {
      fail(`Pinned input changed: ${relative}`)
    }
  }
  if (total > 300_000_000) fail('Pinned-input aggregate read bound exceeded')
  return total
}

async function walkFiles(relative, limits = { count: 10_000, bytes: 500_000_000 }) {
  const rootPath = absolute(relative)
  const result = []
  let aggregate = 0
  async function walk(directory) {
    const entries = await readdir(directory, { withFileTypes: true })
    for (const entry of entries) {
      const full = path.join(directory, entry.name)
      const info = await lstat(full)
      if (entry.isSymbolicLink()) fail(`Symlink is not allowed in shipped tree: ${full}`)
      if (entry.isDirectory()) {
        await walk(full)
        continue
      }
      if (!entry.isFile()) fail(`Non-regular shipped entry: ${full}`)
      aggregate += info.size
      if (result.length >= limits.count || aggregate > limits.bytes) {
        fail(`Shipped tree exceeds bounded inventory: ${relative}`)
      }
      result.push(path.relative(rootPath, full).replaceAll(path.sep, '/'))
    }
  }
  await walk(rootPath)
  result.sort()
  return { count: result.length, bytes: aggregate }
}

async function parseGraph(relative, expectedModels, expectedNodeTypes) {
  const raw = await readFile(absolute(relative), 'utf8')
  const graph = JSON.parse(raw)
  if (!graph || graph.version !== 0.4 || !Array.isArray(graph.nodes) || !Array.isArray(graph.links)) {
    fail(`Not a ComfyUI editable workflow graph: ${relative}`)
  }
  if (Object.hasOwn(graph, 'prompt')) fail(`API-format prompt mapping is not an editable graph: ${relative}`)
  const types = graph.nodes.map((node) => node.type)
  const models = graph.nodes.flatMap((node) => Array.isArray(node.widgets_values) ? node.widgets_values : [])
    .filter((value) => typeof value === 'string' && value.endsWith('.safetensors'))
  for (const type of expectedNodeTypes) if (!types.includes(type)) fail(`Missing node ${type} from ${relative}`)
  for (const model of expectedModels) if (!models.includes(model)) fail(`Missing selected model ${model} from ${relative}`)
  if (!graph.nodes.every((node) => Array.isArray(node.pos) && Array.isArray(node.size) && typeof node.type === 'string')) {
    fail(`Node layout/type metadata is incomplete: ${relative}`)
  }
  if (!graph.links.every((link) => Array.isArray(link) && link.length >= 6)) fail(`Malformed graph links: ${relative}`)
  return { nodes: graph.nodes.length, links: graph.links.length }
}

async function main() {
  if (mode === '--mode=assets') {
    fail('G2 is not authorized: the materialized pnpm closure has not received fresh Sol/root effect review; no build/parser was run')
  }
  if (mode !== '--mode=source-only') fail('Use --mode=source-only or --mode=assets')

  const pinnedBytes = await assertPinnedFiles()
  const packageJson = JSON.parse(await readFile(absolute('web/comfy/upstream/frontend-1.51.9/package.json'), 'utf8'))
  if (packageJson.version !== '1.51.9' || packageJson.license !== 'GPL-3.0-only') fail('Frontend source pin or license changed')
  const rootPackage = JSON.parse(await readFile(absolute('web/comfy/upstream/frontend-1.51.9/package.json'), 'utf8'))
  if (rootPackage.packageManager !== 'pnpm@11.13.1') fail('Unexpected frontend package-manager pin')

  const sdxl = await parseGraph(
    'web/comfy/templates/image_sdxl_simple.json',
    ['sd_xl_base_1.0.safetensors'],
    ['CheckpointLoaderSimple', 'CLIPTextEncode', 'KSampler', 'SaveImage']
  )
  const wan = await parseGraph(
    'web/comfy/templates/video_wan2_2_5B_ti2v.json',
    ['wan2.2_ti2v_5B_fp16.safetensors', 'umt5_xxl_fp8_e4m3fn_scaled.safetensors', 'wan2.2_vae.safetensors'],
    ['UNETLoader', 'CLIPLoader', 'VAELoader', 'Wan22ImageToVideoLatent', 'CreateVideo', 'SaveVideo']
  )
  const catalog = JSON.parse(await readFile(absolute('web/comfy/templates/index.json'), 'utf8'))
  const names = catalog.flatMap((module) => module.templates.map((template) => template.name)).sort()
  if (JSON.stringify(names) !== JSON.stringify(['image_sdxl_simple', 'video_wan2_2_5B_ti2v'])) {
    fail('Local template catalog contains missing or unselected workflows')
  }

  const launcher = await readFile(absolute('web/comfy/launcher.js'), 'utf8')
  if (/https?:\/\/|wss?:\/\/|localStorage|indexedDB/i.test(launcher)) {
    fail('Launcher contains a hard-coded remote origin or persistent credential-capable store')
  }
  if (!launcher.includes("'X-CSRF-Token'") || !launcher.includes("kind: 'ui'") || !launcher.includes('sessionStorage')) {
    fail('Launcher lost the required scoped session/CSRF boundary')
  }
  const sourceInventory = await walkFiles('web/comfy/dist')
  const sourceTree = await walkFiles('web/comfy/upstream/frontend-1.51.9')
  if (sourceInventory.count < 100 || sourceTree.count < 1_000) fail('Pinned distribution/source extraction is incomplete')

  process.stdout.write(
    `Comfy canvas asset source verification passed; pinnedBytes=${pinnedBytes}; distFiles=${sourceInventory.count}; sourceFiles=${sourceTree.count}; SDXL=${sdxl.nodes}n/${sdxl.links}l; Wan=${wan.nodes}n/${wan.links}l; buildParser=NOT_RUN\n`
  )
}

main().catch((error) => {
  process.stderr.write(`Comfy canvas asset source verification failed: ${error.message}\n`)
  process.exitCode = 1
})
