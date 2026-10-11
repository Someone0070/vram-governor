import { createHash } from 'node:crypto'
import { constants } from 'node:fs'
import { lstat, mkdir, open, readFile, realpath, readdir } from 'node:fs/promises'
import https from 'node:https'
import path from 'node:path'
import { inflateRawSync } from 'node:zlib'

const VERSION = '25.9.0'
const ARCHIVE_URL = 'https://nodejs.org/dist/v25.9.0/node-v25.9.0-win-x64.zip'
const ARCHIVE_BYTES = 37_531_403
const ARCHIVE_SHA256 = '929552b8305effac843ba7b4270c437aefb702fc3fbd73fcd1bffd35d4ac284e'
const ROOT = `node-v${VERSION}-win-x64/`
const ARCHIVE_REL = 'web/comfy/vendor/node-v25.9.0-win-x64.zip'
const TREE_REL = 'web/comfy/toolchains/node-v25.9.0-win-x64'
const MANIFEST_REL = 'web/comfy/toolchains/node-v25.9.0-win-x64-manifest.json'
const ARCHIVE_CAP = 41_943_040
const ENTRY_CAP = 8192
const FILE_CAP = 268_435_456
const EXPANDED_CAP = 536_870_912
const REQUEST_TIMEOUT_MS = 120_000
const MANIFEST_CAP = 16 * 1024 * 1024
const MAX_PATH_CHARS = 240

function fail(message) { throw new Error(message) }
function hash(bytes) { return createHash('sha256').update(bytes).digest('hex') }
function crc32(bytes) {
  let crc = 0xffffffff
  for (const byte of bytes) {
    crc ^= byte
    for (let bit = 0; bit < 8; bit++) crc = (crc >>> 1) ^ ((crc & 1) ? 0xedb88320 : 0)
  }
  return (crc ^ 0xffffffff) >>> 0
}
function need(condition, message) { if (!condition) fail(message) }
function decodeName(bytes, label) {
  try { return new TextDecoder('utf-8', { fatal: true }).decode(bytes) }
  catch { fail(`${label}: ZIP name is not strict UTF-8`) }
}

function safeMemberName(raw, directory) {
  need(raw.length > 0 && Buffer.byteLength(raw, 'utf8') <= 4096, 'ZIP path length is invalid')
  need(!raw.includes('\\') && !raw.startsWith('/') && !/^[A-Za-z]:/.test(raw), 'ZIP path is absolute, drive-qualified, or uses backslashes')
  need(!/[\u0000-\u001f\u007f-\u009f]/u.test(raw), 'ZIP path contains a control character')
  const lexical = directory && raw.endsWith('/') ? raw.slice(0, -1) : raw
  need(lexical.length > 0 && !lexical.endsWith('/') && !raw.endsWith('//'), 'ZIP path has an empty component')
  const parts = lexical.split('/')
  need(parts.every((part) => part.length > 0 && part !== '.' && part !== '..'), 'ZIP path contains an empty, dot, or traversal component')
  need(parts.every((part) => Buffer.byteLength(part, 'utf8') <= 255), 'ZIP path component exceeds 255 bytes')
  for (const part of parts) {
    need(!/[<>:"|?*]/u.test(part), 'ZIP path contains a Windows-reserved character or ADS colon')
    need(!/[. ]$/u.test(part), 'ZIP path component ends in a dot or space')
    need(!/^(CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])(?:\..*)?$/iu.test(part), 'ZIP path contains a reserved Windows device name')
  }
  const normalized = parts.map((part) => part.normalize('NFC')).join('/')
  const rootName = ROOT.slice(0, -1)
  need(normalized.startsWith(ROOT) || (directory && normalized === rootName), 'ZIP path is outside the fixed Node archive root')
  const relativeToRoot = normalized === rootName ? '' : normalized.slice(ROOT.length)
  const absoluteCandidate = path.resolve(process.cwd(), TREE_REL, ...relativeToRoot.split('/').filter(Boolean))
  need(absoluteCandidate.length <= MAX_PATH_CHARS, 'ZIP canonical path exceeds the Windows path bound')
  const collisionKey = normalized.normalize('NFKC').toLocaleUpperCase('en-US').toLocaleLowerCase('en-US')
  return { canonical: `${normalized}${directory ? '/' : ''}`, collisionKey }
}

function parseExtraFields(bytes, start, length, label) {
  const end = start + length
  let at = start
  while (at < end) {
    need(at + 4 <= end, `${label}: malformed ZIP extra field`)
    const id = bytes.readUInt16LE(at)
    const size = bytes.readUInt16LE(at + 2)
    at += 4
    need(at + size <= end, `${label}: truncated ZIP extra field`)
    need(id !== 0x0001, `${label}: ZIP64 is unsupported`)
    at += size
  }
  need(at === end, `${label}: malformed ZIP extra field extent`)
}

function inflateEntry(archive, entry) {
  const compressed = archive.subarray(entry.dataOffset, entry.dataEnd)
  let data
  try {
    if (entry.method === 0) data = Buffer.from(compressed)
    else if (entry.method === 8) {
      const result = inflateRawSync(compressed, { maxOutputLength: Math.min(FILE_CAP, entry.uncompressedSize + 1), info: true })
      need(result.engine.bytesWritten === compressed.length, 'ZIP compressed member has trailing data')
      data = result.buffer
    }
    else fail('ZIP compression method is unsupported')
  } catch (error) {
    if (error.message === 'ZIP compression method is unsupported') throw error
    fail('ZIP member decompression failed within its declared bound')
  }
  need(data.length === entry.uncompressedSize, 'ZIP member uncompressed size mismatch')
  need(crc32(data) === entry.crc32, 'ZIP member CRC32 mismatch')
  return data
}

function parseZip(archive) {
  need(Buffer.isBuffer(archive), 'ZIP input is not a byte buffer')
  need(archive.length <= ARCHIVE_CAP, 'ZIP archive exceeds the fixed compressed-byte bound')
  need(archive.length >= 22, 'ZIP end record is missing')
  const minEOCD = Math.max(0, archive.length - 22 - 0xffff)
  let eocd = -1
  for (let i = archive.length - 22; i >= minEOCD; i--) {
    if (archive.readUInt32LE(i) === 0x06054b50 && i + 22 + archive.readUInt16LE(i + 20) === archive.length) { eocd = i; break }
  }
  need(eocd >= 0, 'ZIP end record is malformed or does not reach exact EOF')
  const disk = archive.readUInt16LE(eocd + 4)
  const centralDisk = archive.readUInt16LE(eocd + 6)
  const diskCount = archive.readUInt16LE(eocd + 8)
  const count = archive.readUInt16LE(eocd + 10)
  const centralSize = archive.readUInt32LE(eocd + 12)
  const centralOffset = archive.readUInt32LE(eocd + 16)
  need(disk === 0 && centralDisk === 0 && diskCount === count, 'Multi-disk ZIP is unsupported')
  need(count !== 0xffff && centralSize !== 0xffffffff && centralOffset !== 0xffffffff, 'ZIP64 is unsupported')
  need(count > 0 && count <= ENTRY_CAP, 'ZIP entry count is outside the fixed bound')
  need(centralOffset + centralSize === eocd, 'ZIP central directory framing is inconsistent')

  const entries = []
  let cursor = centralOffset
  const names = new Set()
  const collisions = new Set()
  let expanded = 0
  for (let index = 0; index < count; index++) {
    need(cursor + 46 <= eocd && archive.readUInt32LE(cursor) === 0x02014b50, 'ZIP central directory entry is malformed')
    const madeBy = archive.readUInt16LE(cursor + 4)
    const flags = archive.readUInt16LE(cursor + 8)
    const method = archive.readUInt16LE(cursor + 10)
    const crc = archive.readUInt32LE(cursor + 16)
    const compressedSize = archive.readUInt32LE(cursor + 20)
    const uncompressedSize = archive.readUInt32LE(cursor + 24)
    const nameLength = archive.readUInt16LE(cursor + 28)
    const extraLength = archive.readUInt16LE(cursor + 30)
    const commentLength = archive.readUInt16LE(cursor + 32)
    const diskStart = archive.readUInt16LE(cursor + 34)
    const external = archive.readUInt32LE(cursor + 38)
    const localOffset = archive.readUInt32LE(cursor + 42)
    const recordEnd = cursor + 46 + nameLength + extraLength + commentLength
    need(recordEnd <= eocd, 'ZIP central directory entry exceeds its declared extent')
    need((flags & ~0x0806) === 0 && (flags & 1) === 0 && (flags & 8) === 0, 'ZIP encryption, descriptors, or unsupported flags are present')
    need(method === 0 || method === 8, 'ZIP compression method is unsupported')
    need(method === 8 || (flags & 0x0006) === 0, 'ZIP compression option flags are invalid for stored members')
    need(diskStart === 0 && compressedSize !== 0xffffffff && uncompressedSize !== 0xffffffff && localOffset !== 0xffffffff, 'Multi-disk or ZIP64 member is unsupported')
    parseExtraFields(archive, cursor + 46 + nameLength, extraLength, 'ZIP central entry')
    const name = decodeName(archive.subarray(cursor + 46, cursor + 46 + nameLength), 'ZIP central entry')
    const isDirectory = name.endsWith('/')
    const safe = safeMemberName(name, isDirectory)
    need(!names.has(name), 'ZIP duplicate member name')
    need(!collisions.has(safe.collisionKey), 'ZIP case-fold or Unicode-normalization path collision')
    names.add(name); collisions.add(safe.collisionKey)
    const mode = madeBy >>> 8 === 3 ? external >>> 16 : 0
    const fileType = mode & 0xf000
    need(fileType === 0 || fileType === 0x8000 || fileType === 0x4000, 'ZIP link or special member type is unsupported')
    need((external & 0x400) === 0, 'ZIP reparse-point member is unsupported')
    need((isDirectory && fileType !== 0x4000) || (!isDirectory && fileType !== 0x8000), 'ZIP name and member type disagree')
    need(!isDirectory || (compressedSize === 0 && uncompressedSize === 0), 'ZIP directory carries payload bytes')
    need(uncompressedSize <= FILE_CAP, 'ZIP member exceeds the per-file inflated bound')
    expanded += uncompressedSize
    need(Number.isSafeInteger(expanded) && expanded <= EXPANDED_CAP, 'ZIP aggregate inflated bound exceeded')
    entries.push({ index, name, canonical: safe.canonical, collisionKey: safe.collisionKey, directory: isDirectory, method, flags, crc32: crc, compressedSize, uncompressedSize, localOffset, external, mode, centralOffset: cursor })
    cursor = recordEnd
  }
  need(cursor === eocd, 'ZIP central directory length does not match its entries')

  const byOffset = [...entries].sort((a, b) => a.localOffset - b.localOffset)
  need(byOffset[0].localOffset === 0, 'ZIP contains bytes before its first local entry')
  for (let i = 0; i < byOffset.length; i++) {
    const entry = byOffset[i]
    const nextOffset = i + 1 < byOffset.length ? byOffset[i + 1].localOffset : centralOffset
    const at = entry.localOffset
    need(at + 30 <= centralOffset && archive.readUInt32LE(at) === 0x04034b50, 'ZIP local entry header is malformed')
    const flags = archive.readUInt16LE(at + 6)
    const method = archive.readUInt16LE(at + 8)
    const crc = archive.readUInt32LE(at + 14)
    const compressedSize = archive.readUInt32LE(at + 18)
    const uncompressedSize = archive.readUInt32LE(at + 22)
    const nameLength = archive.readUInt16LE(at + 26)
    const extraLength = archive.readUInt16LE(at + 28)
    const headerEnd = at + 30 + nameLength + extraLength
    need(headerEnd <= centralOffset, 'ZIP local entry header exceeds archive data')
    parseExtraFields(archive, at + 30 + nameLength, extraLength, 'ZIP local entry')
    const name = decodeName(archive.subarray(at + 30, at + 30 + nameLength), 'ZIP local entry')
    need(name === entry.name && flags === entry.flags && method === entry.method && crc === entry.crc32 && compressedSize === entry.compressedSize && uncompressedSize === entry.uncompressedSize, 'ZIP local and central entry fields disagree')
    entry.dataOffset = headerEnd
    entry.dataEnd = headerEnd + compressedSize
    need(entry.dataEnd <= centralOffset && entry.dataEnd === nextOffset, 'ZIP entries overlap or contain unframed bytes')
    entry.data = inflateEntry(archive, entry)
  }
  const byPath = new Map(entries.map((entry) => [entry.canonical.replace(/\/$/u, ''), entry]))
  for (const entry of entries) {
    const clean = entry.canonical.replace(/\/$/u, '')
    const parent = path.posix.dirname(clean)
    if (parent !== '.') {
      const parentEntry = byPath.get(parent)
      need(!parentEntry || parentEntry.directory, 'ZIP file/directory path collision')
    }
    if (!entry.directory) {
      for (const candidate of entries) need(candidate === entry || !candidate.canonical.replace(/\/$/u, '').startsWith(`${clean}/`), 'ZIP file is also an ancestor of another member')
    }
  }
  return { entries, expandedBytes: expanded, centralOffset, centralSize, crc32: crc32(archive) }
}

async function workspaceRoot() {
  const root = await realpath(process.cwd())
  const expected = path.resolve(process.cwd())
  need(root.toLowerCase() === expected.toLowerCase(), 'Workspace root resolves through a reparse path')
  return root
}
async function assertSafeAncestors(root, relative, allowLeaf) {
  const parts = relative.split('/')
  let current = root
  for (let i = 0; i < parts.length; i++) {
    current = path.join(current, parts[i])
    const isLeaf = i === parts.length - 1
    try {
      const info = await lstat(current, { bigint: true })
      need(!info.isSymbolicLink(), `Reparse or symlink path is forbidden: ${relative}`)
      need(!isLeaf || allowLeaf || info.isDirectory(), `Expected a directory at: ${relative}`)
    } catch (error) {
      if (error.code === 'ENOENT' && (!isLeaf || !allowLeaf)) continue
      throw error
    }
  }
}
async function directoryIdentity(full) {
  const info = await lstat(full, { bigint: true })
  need(info.isDirectory() && !info.isSymbolicLink(), `Output parent is not a real directory: ${full}`)
  return { dev: info.dev, ino: info.ino }
}
function sameIdentity(left, right) { return left.dev === right.dev && left.ino === right.ino }
async function makeDirectoryNew(full) {
  const parent = path.dirname(full)
  const before = await directoryIdentity(parent)
  await mkdir(full, { mode: 0o700 })
  const created = await directoryIdentity(full)
  const after = await directoryIdentity(parent)
  need(sameIdentity(before, after), `Output parent identity changed during directory creation: ${full}`)
  return created
}
async function readBoundedArchive(root) {
  const full = path.join(root, ...ARCHIVE_REL.split('/'))
  const before = await lstat(full, { bigint: true })
  need(before.isFile() && before.nlink === 1n && before.size === BigInt(ARCHIVE_BYTES), 'Pinned Node ZIP must be a regular single-link file of exact size')
  const handle = await open(full, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0))
  try {
    const openedBefore = await handle.stat({ bigint: true })
    need(openedBefore.isFile() && openedBefore.nlink === 1n && openedBefore.dev === before.dev && openedBefore.ino === before.ino && openedBefore.size === before.size, 'Pinned Node ZIP identity changed before reading')
    const chunks = []
    let total = 0
    while (total < ARCHIVE_BYTES) {
      const buffer = Buffer.alloc(Math.min(1024 * 1024, ARCHIVE_BYTES - total))
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null)
      if (bytesRead === 0) break
      total += bytesRead
      need(total <= ARCHIVE_BYTES, 'Pinned Node ZIP exceeded its exact read bound')
      chunks.push(buffer.subarray(0, bytesRead))
    }
    const probe = Buffer.alloc(1)
    const extra = await handle.read(probe, 0, 1, null)
    need(extra.bytesRead === 0, 'Pinned Node ZIP grew beyond its exact read bound')
    const openedAfter = await handle.stat({ bigint: true })
    const after = await lstat(full, { bigint: true })
    need(openedBefore.dev === openedAfter.dev && openedBefore.ino === openedAfter.ino && openedAfter.size === BigInt(total) && openedAfter.nlink === 1n && after.dev === openedAfter.dev && after.ino === openedAfter.ino && after.size === BigInt(total) && after.nlink === 1n, 'Pinned Node ZIP identity changed while reading')
    const bytes = Buffer.concat(chunks, total)
    need(bytes.length === ARCHIVE_BYTES && hash(bytes) === ARCHIVE_SHA256, 'Pinned Node ZIP byte count or SHA256 mismatch')
    return bytes
  } finally { await handle.close() }
}
function requestPinnedArchive() {
  need(!process.env.NODE_OPTIONS, 'Node launch options are not permitted for fixed-URL acquisition')
  need(process.env.NODE_TLS_REJECT_UNAUTHORIZED !== '0', 'TLS certificate verification is disabled in the process environment')
  need(!process.env.NODE_EXTRA_CA_CERTS && !process.env.SSL_CERT_FILE && !process.env.SSL_CERT_DIR, 'Custom certificate roots are not permitted for fixed-URL acquisition')
  need(process.env.NODE_USE_ENV_PROXY !== '1', 'Environment-selected HTTPS proxy is not permitted')
  need(process.execArgv.length === 0, 'Node command-line overrides are not permitted for fixed-URL acquisition')
  return new Promise((resolve, reject) => {
    const request = https.get(ARCHIVE_URL, { headers: { accept: 'application/zip', 'accept-encoding': 'identity' }, timeout: REQUEST_TIMEOUT_MS, maxHeaderSize: 16 * 1024 }, (response) => {
      const metadata = { status: response.statusCode, contentLength: response.headers['content-length'] ?? null, contentType: response.headers['content-type'] ?? null, url: ARCHIVE_URL }
      if (response.statusCode !== 200) { response.resume(); reject(new Error(`Fixed Node archive request returned HTTP ${response.statusCode}`)); return }
      if (response.headers.location) { response.resume(); reject(new Error('Fixed Node archive request attempted a redirect')); return }
      if (!/^(?:application\/(?:zip|octet-stream|x-zip-compressed))(?:\s*;|$)/iu.test(response.headers['content-type'] ?? '')) { response.resume(); reject(new Error('Fixed Node archive response Content-Type is missing or unexpected')); return }
      const declared = response.headers['content-length']
      if (declared !== undefined && (!/^\d+$/u.test(declared) || Number(declared) !== ARCHIVE_BYTES)) { response.resume(); reject(new Error('Fixed Node archive Content-Length disagrees with the pin')); return }
      const chunks = []
      let total = 0
      response.on('data', (chunk) => {
        total += chunk.length
        if (total > ARCHIVE_CAP) { response.destroy(new Error('Fixed Node archive response exceeded the streamed cap')); return }
        chunks.push(chunk)
      })
      response.on('end', () => {
        const bytes = Buffer.concat(chunks)
        if (bytes.length !== ARCHIVE_BYTES || hash(bytes) !== ARCHIVE_SHA256) { reject(new Error('Fixed Node archive response failed exact byte count or SHA256 verification')); return }
        resolve({ bytes, metadata })
      })
      response.on('error', reject)
    })
    request.on('timeout', () => request.destroy(new Error('Fixed Node archive request timed out')))
    request.on('error', reject)
  })
}
async function createNewFile(root, relative, bytes) {
  await assertSafeAncestors(root, relative, true)
  const full = path.join(root, ...relative.split('/'))
  const parentBefore = await directoryIdentity(path.dirname(full))
  const handle = await open(full, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (constants.O_NOFOLLOW ?? 0), 0o600)
  let opened
  try { await handle.writeFile(bytes); await handle.sync(); opened = await handle.stat({ bigint: true }) } finally { await handle.close() }
  const info = await lstat(full, { bigint: true })
  const parentAfter = await directoryIdentity(path.dirname(full))
  need(opened.dev === info.dev && opened.ino === info.ino && sameIdentity(parentBefore, parentAfter) && info.isFile() && info.nlink === 1n && info.size === BigInt(bytes.length), `Create-new output identity or size check failed: ${relative}`)
  return info
}
async function acquire() {
  const root = await workspaceRoot()
  await assertSafeAncestors(root, ARCHIVE_REL, true)
  const target = path.join(root, ...ARCHIVE_REL.split('/'))
  try { await lstat(target); fail('Pinned Node archive output already exists; create-new acquisition is forbidden') }
  catch (error) { if (error.code !== 'ENOENT') throw error }
  const result = await requestPinnedArchive()
  const info = await createNewFile(root, ARCHIVE_REL, result.bytes)
  const receipt = { schema: 'node-toolchain-acquisition-v1', url: ARCHIVE_URL, status: result.metadata.status, contentLength: result.metadata.contentLength, contentType: result.metadata.contentType, bytes: result.bytes.length, sha256: hash(result.bytes), createdFileIdentity: { dev: info.dev.toString(), ino: info.ino.toString() }, note: 'Receipt is stdout evidence only; it does not prove detached publisher signature or license/source closure.' }
  process.stdout.write(`${JSON.stringify(receipt)}\n`)
}

async function extract() {
  const root = await workspaceRoot()
  const archive = await readBoundedArchive(root)
  const parsed = parseZip(archive)
  await assertSafeAncestors(root, TREE_REL, true)
  await assertSafeAncestors(root, MANIFEST_REL, true)
  const tree = path.join(root, ...TREE_REL.split('/'))
  const manifestPath = path.join(root, ...MANIFEST_REL.split('/'))
  for (const target of [tree, manifestPath]) {
    try { await lstat(target); fail('Node extraction output already exists; merging or overwrite is forbidden') }
    catch (error) { if (error.code !== 'ENOENT') throw error }
  }
  const explicitDirectories = new Map()
  const directoryPaths = new Set()
  const explicitRoot = parsed.entries.find((entry) => entry.directory && entry.canonical === ROOT)
  for (const entry of parsed.entries) {
    const relative = entry.canonical.slice(ROOT.length).replace(/\/$/u, '')
    if (relative === '') { if (entry.directory) explicitDirectories.set('.', entry); continue }
    const parts = relative.split('/')
    for (let index = 1; index <= parts.length; index++) {
      const directory = parts.slice(0, index).join('/')
      if (entry.directory || index < parts.length) directoryPaths.add(directory)
    }
    if (entry.directory) explicitDirectories.set(relative, entry)
  }
  const orderedDirectories = [...directoryPaths].sort((a, b) => a.split('/').length - b.split('/').length || (a < b ? -1 : a > b ? 1 : 0))
  const manifestEntries = []
  manifestEntries.push({ path: '.', type: 'directory', bytes: 0, sha256: null, archiveCrc32: explicitRoot?.crc32 ?? null, archiveMemberIndex: explicitRoot?.index ?? null, archiveName: explicitRoot?.name ?? null, provenance: explicitRoot ? 'explicit-archive-root-directory' : 'extraction-root' })
  for (const entry of parsed.entries) {
    const relative = entry.canonical.slice(ROOT.length).replace(/\/$/u, '')
    if (!entry.directory) manifestEntries.push({ path: relative, type: 'file', bytes: entry.uncompressedSize, sha256: hash(entry.data), archiveCrc32: entry.crc32, archiveMemberIndex: entry.index, archiveName: entry.name })
  }
  for (const relative of orderedDirectories) {
    const explicit = explicitDirectories.get(relative)
    manifestEntries.push({ path: relative, type: 'directory', bytes: 0, sha256: null, archiveCrc32: explicit?.crc32 ?? null, archiveMemberIndex: explicit?.index ?? null, archiveName: explicit?.name ?? null, provenance: explicit ? 'explicit-archive-directory' : 'synthesized-parent-directory' })
  }
  manifestEntries.sort((a, b) => a.path < b.path ? -1 : a.path > b.path ? 1 : a.type < b.type ? -1 : 1)
  const manifest = { schema: 'node-toolchain-extracted-inventory-v1', archive: { url: ARCHIVE_URL, version: VERSION, bytes: archive.length, sha256: hash(archive), crc32: parsed.crc32, centralDirectoryBytes: parsed.centralSize, inflatedBytes: parsed.expandedBytes }, entries: manifestEntries }
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, 'utf8')
  need(bytes.length <= MANIFEST_CAP, 'Node extraction inventory manifest exceeds the fixed bound')

  // All archive, path, inflation, collision, and manifest-size checks finish before the first extraction effect.
  const toolchains = path.join(root, 'web', 'comfy', 'toolchains')
  try { await lstat(toolchains); fail('Node toolchain parent already exists; output adoption is forbidden') }
  catch (error) { if (error.code !== 'ENOENT') throw error }
  await makeDirectoryNew(toolchains)
  await makeDirectoryNew(tree)
  for (const relative of orderedDirectories) {
    const destination = path.join(tree, ...relative.split('/'))
    await makeDirectoryNew(destination)
    await assertSafeAncestors(root, path.relative(root, destination).replaceAll(path.sep, '/'), false)
  }
  for (const entry of parsed.entries) {
    if (entry.directory) continue
    const relative = entry.canonical.slice(ROOT.length)
    const output = path.join(tree, ...relative.split('/'))
    const parentRel = path.posix.dirname(relative)
    if (parentRel !== '.') {
      let at = tree
      for (const part of parentRel.split('/')) { at = path.join(at, part); await assertSafeAncestors(root, path.relative(root, at).replaceAll(path.sep, '/'), false) }
    }
    await createNewFile(root, path.relative(root, output).replaceAll(path.sep, '/'), entry.data)
    const actual = await readFile(output)
    const expected = manifestEntries.find((candidate) => candidate.path === relative)
    need(actual.length === entry.uncompressedSize && expected?.sha256 === hash(actual), 'Extracted file failed post-write digest verification')
  }
  const expectedPaths = new Map(manifestEntries.map((entry) => [entry.path, entry.type]))
  const observedPaths = new Map()
  async function inventory(directory, prefix = '.') {
    for (const item of await readdir(directory, { withFileTypes: true })) {
      const relative = prefix === '.' ? item.name : `${prefix}/${item.name}`
      const absolute = path.join(directory, item.name)
      need(item.isDirectory() || item.isFile(), 'Extracted tree contains a link or special filesystem entry')
      const kind = item.isDirectory() ? 'directory' : 'file'
      observedPaths.set(relative, kind)
      const info = await lstat(absolute, { bigint: true })
      need(info.nlink === 1n && !info.isSymbolicLink(), 'Extracted tree entry identity is unsafe')
      if (kind === 'directory') await inventory(absolute, relative)
      else {
        const row = manifestEntries.find((candidate) => candidate.path === relative)
        need(row && info.size === BigInt(row.bytes), 'Extracted tree file size differs from its complete manifest')
        const content = await readFile(absolute)
        need(row && row.bytes === content.length && row.sha256 === hash(content), 'Extracted tree file differs from its complete manifest')
      }
    }
  }
  await inventory(tree)
  need(observedPaths.size === expectedPaths.size - 1, 'Extracted tree path count differs from the complete archive inventory')
  for (const [relative, kind] of observedPaths) need(expectedPaths.get(relative) === kind, 'Extracted tree contains a missing, extra, or changed path')
  await createNewFile(root, MANIFEST_REL, bytes)
  process.stdout.write(`Verified inert Node ${VERSION} ZIP structure and wrote ${manifestEntries.length} archive inventory records; no extracted code was run\n`)
}

// Inert fixture source. This mode is not approved for implementation-time execution.
function makeStoredZip(records) {
  const locals = []; const centrals = []; let offset = 0
  for (const record of records) {
    const name = Buffer.from(record.name, 'utf8'); const data = Buffer.from(record.data ?? '', 'utf8'); const crc = crc32(data)
    const local = Buffer.alloc(30 + name.length)
    local.writeUInt32LE(0x04034b50, 0); local.writeUInt16LE(20, 4); local.writeUInt16LE(0x0800, 6); local.writeUInt16LE(0, 8)
    local.writeUInt32LE(crc, 14); local.writeUInt32LE(data.length, 18); local.writeUInt32LE(data.length, 22); local.writeUInt16LE(name.length, 26); name.copy(local, 30)
    locals.push(local, data)
    const central = Buffer.alloc(46 + name.length)
    central.writeUInt32LE(0x02014b50, 0); central.writeUInt16LE(0x0314, 4); central.writeUInt16LE(20, 6); central.writeUInt16LE(0x0800, 8); central.writeUInt16LE(0, 10)
    central.writeUInt32LE(crc, 16); central.writeUInt32LE(data.length, 20); central.writeUInt32LE(data.length, 24); central.writeUInt16LE(name.length, 28); central.writeUInt32LE(record.mode ? record.mode * 65536 : (record.name.endsWith('/') ? 0x10 : 0), 38); central.writeUInt32LE(offset, 42); name.copy(central, 46)
    centrals.push(central); offset += local.length + data.length
  }
  const centralBytes = Buffer.concat(centrals); const eocd = Buffer.alloc(22)
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(records.length, 8); eocd.writeUInt16LE(records.length, 10); eocd.writeUInt32LE(centralBytes.length, 12); eocd.writeUInt32LE(offset, 16)
  return Buffer.concat([...locals, centralBytes, eocd])
}
function expectFailure(label, action, diagnostic) {
  try { action(); fail(`${label}: fixture was accepted`) }
  catch (error) { if (error.message === `${label}: fixture was accepted`) throw error; need(error.message.includes(diagnostic), `${label}: received an unrelated diagnostic: ${error.message}`) }
}
function runSourceFixtures() {
  const valid = makeStoredZip([{ name: `${ROOT}LICENSE.txt`, data: 'Node fixture license\n' }, { name: `${ROOT}node.exe`, data: 'inert fixture bytes' }])
  const accepted = parseZip(valid)
  need(accepted.entries.length === 2 && accepted.entries[0].name === `${ROOT}LICENSE.txt`, 'Positive literal valid ZIP fixture was not accepted')
  const explicitRoot = parseZip(makeStoredZip([{ name: ROOT, data: '' }, { name: `${ROOT}node.exe`, data: 'inert' }]))
  need(explicitRoot.entries[0].directory && explicitRoot.entries[0].canonical === ROOT, 'Explicit archive-root directory positive fixture was not accepted')
  const firstCentral = accepted.entries[0].centralOffset
  const eocd = valid.length - 22
  const localNameLength = valid.readUInt16LE(26)
  const traversal = makeStoredZip([{ name: `${ROOT}../outside.txt`, data: 'x' }])
  expectFailure('path traversal', () => parseZip(traversal), 'ZIP path contains an empty, dot, or traversal component')
  for (const [label, name, diagnostic] of [
    ['drive path', 'C:/outside.txt', 'ZIP path is absolute, drive-qualified, or uses backslashes'],
    ['ADS path', `${ROOT}file:stream`, 'ZIP path contains a Windows-reserved character or ADS colon'],
    ['UNC path', `\\\\server\\share`, 'ZIP path is absolute, drive-qualified, or uses backslashes'],
    ['control path', `${ROOT}bad\u0001name`, 'ZIP path contains a control character'],
    ['device path', `${ROOT}CON.txt`, 'ZIP path contains a reserved Windows device name'],
    ['trailing dot path', `${ROOT}file.`, 'ZIP path component ends in a dot or space'],
    ['empty path component', `${ROOT}folder//file`, 'ZIP path contains an empty, dot, or traversal component'],
    ['out-of-root path', 'other-root/file', 'ZIP path is outside the fixed Node archive root']
  ]) {
    const fixture = makeStoredZip([{ name, data: 'x' }])
    expectFailure(label, () => parseZip(fixture), diagnostic)
  }
  const normalizedCollision = makeStoredZip([{ name: `${ROOT}caf\u00e9.txt`, data: 'a' }, { name: `${ROOT}cafe\u0301.txt`, data: 'b' }])
  expectFailure('Unicode normalization collision', () => parseZip(normalizedCollision), 'ZIP case-fold or Unicode-normalization path collision')
  const badCRC = Buffer.from(valid); badCRC[30 + localNameLength] ^= 1
  expectFailure('CRC mismatch', () => parseZip(badCRC), 'ZIP member CRC32 mismatch')
  const localCentralMismatch = Buffer.from(valid); localCentralMismatch.writeUInt32LE(1, 14)
  expectFailure('local/central mismatch', () => parseZip(localCentralMismatch), 'ZIP local and central entry fields disagree')
  const badLocalSignature = Buffer.from(valid); badLocalSignature.writeUInt32LE(0, 0)
  expectFailure('local signature', () => parseZip(badLocalSignature), 'ZIP local entry header is malformed')
  const badCentralSignature = Buffer.from(valid); badCentralSignature.writeUInt32LE(0, firstCentral)
  expectFailure('central signature', () => parseZip(badCentralSignature), 'ZIP central directory entry is malformed')
  const centralExtent = Buffer.from(valid); centralExtent.writeUInt32LE(valid.readUInt32LE(eocd + 12) - 1, eocd + 12)
  expectFailure('central extent', () => parseZip(centralExtent), 'ZIP central directory framing is inconsistent')
  const multiDisk = Buffer.from(valid); multiDisk.writeUInt16LE(1, eocd + 4)
  expectFailure('multi-disk', () => parseZip(multiDisk), 'Multi-disk ZIP is unsupported')
  const zip64 = Buffer.from(valid); zip64.writeUInt16LE(0xffff, eocd + 8); zip64.writeUInt16LE(0xffff, eocd + 10)
  expectFailure('ZIP64 sentinel', () => parseZip(zip64), 'ZIP64 is unsupported')
  const encrypted = Buffer.from(valid); encrypted.writeUInt16LE(0x0801, 6); encrypted.writeUInt16LE(0x0801, firstCentral + 8)
  expectFailure('encryption flag', () => parseZip(encrypted), 'ZIP encryption, descriptors, or unsupported flags are present')
  const descriptor = Buffer.from(valid); descriptor.writeUInt16LE(0x0808, 6); descriptor.writeUInt16LE(0x0808, firstCentral + 8)
  expectFailure('data descriptor flag', () => parseZip(descriptor), 'ZIP encryption, descriptors, or unsupported flags are present')
  const unsupportedMethod = Buffer.from(valid); unsupportedMethod.writeUInt16LE(12, 8); unsupportedMethod.writeUInt16LE(12, firstCentral + 10)
  expectFailure('unsupported compression', () => parseZip(unsupportedMethod), 'ZIP compression method is unsupported')
  const truncated = valid.subarray(0, valid.length - 1)
  expectFailure('truncated EOCD', () => parseZip(truncated), 'ZIP end record is malformed or does not reach exact EOF')
  const trailing = Buffer.concat([valid, Buffer.from([0])])
  expectFailure('trailing bytes', () => parseZip(trailing), 'ZIP end record is malformed or does not reach exact EOF')
  const duplicate = makeStoredZip([{ name: `${ROOT}LICENSE.txt`, data: 'a' }, { name: `${ROOT}LICENSE.txt`, data: 'b' }])
  expectFailure('duplicate name', () => parseZip(duplicate), 'ZIP duplicate member name')
  const caseCollision = makeStoredZip([{ name: `${ROOT}LICENSE.txt`, data: 'a' }, { name: `${ROOT}license.txt`, data: 'b' }])
  expectFailure('case collision', () => parseZip(caseCollision), 'ZIP case-fold or Unicode-normalization path collision')
  const foldCollision = makeStoredZip([{ name: `${ROOT}ss.txt`, data: 'a' }, { name: `${ROOT}\u00df.txt`, data: 'b' }])
  expectFailure('Unicode case-fold collision', () => parseZip(foldCollision), 'ZIP case-fold or Unicode-normalization path collision')
  const fileDirectoryCollision = makeStoredZip([{ name: `${ROOT}item`, data: 'a' }, { name: `${ROOT}item/`, data: '' }])
  expectFailure('file/directory collision', () => parseZip(fileDirectoryCollision), 'ZIP case-fold or Unicode-normalization path collision')
  const overlap = makeStoredZip([{ name: `${ROOT}a`, data: 'a' }, { name: `${ROOT}b`, data: 'b' }])
  const overlapParsed = parseZip(overlap); const overlapBytes = Buffer.from(overlap)
  overlapBytes.writeUInt32LE(0, overlapParsed.entries[1].centralOffset + 42)
  expectFailure('overlapping local members', () => parseZip(overlapBytes), 'ZIP entries overlap or contain unframed bytes')
  const centralExtraAt = firstCentral + 46 + localNameLength
  const centralExtra = Buffer.concat([valid.subarray(0, centralExtraAt), Buffer.from([1, 0, 0, 0]), valid.subarray(centralExtraAt)])
  centralExtra.writeUInt16LE(4, firstCentral + 30)
  centralExtra.writeUInt32LE(valid.readUInt32LE(eocd + 12) + 4, eocd + 4 + 12)
  expectFailure('ZIP64 central extra', () => parseZip(centralExtra), 'ZIP64 is unsupported')
  const link = makeStoredZip([{ name: `${ROOT}link`, data: 'x', mode: 0xa1ff }])
  expectFailure('symlink type', () => parseZip(link), 'ZIP link or special member type is unsupported')
  const device = makeStoredZip([{ name: `${ROOT}device`, data: 'x', mode: 0x61ff }])
  expectFailure('special-file type', () => parseZip(device), 'ZIP link or special member type is unsupported')
  const tooMany = Buffer.from(valid); tooMany.writeUInt16LE(ENTRY_CAP + 1, eocd + 8); tooMany.writeUInt16LE(ENTRY_CAP + 1, eocd + 10)
  expectFailure('entry count bound', () => parseZip(tooMany), 'ZIP entry count is outside the fixed bound')
  const tooLargeFile = Buffer.from(valid); tooLargeFile.writeUInt32LE(FILE_CAP + 1, 22); tooLargeFile.writeUInt32LE(FILE_CAP + 1, firstCentral + 24)
  expectFailure('per-file inflated bound', () => parseZip(tooLargeFile), 'ZIP member exceeds the per-file inflated bound')
  const aggregateInput = makeStoredZip([{ name: `${ROOT}a`, data: 'a' }, { name: `${ROOT}b`, data: 'b' }, { name: `${ROOT}c`, data: 'c' }])
  const aggregateParsed = parseZip(aggregateInput)
  const tooLargeAggregate = Buffer.from(aggregateInput)
  for (const entry of aggregateParsed.entries) {
    tooLargeAggregate.writeUInt32LE(Math.floor(EXPANDED_CAP / 3) + 1, entry.localOffset + 22)
    tooLargeAggregate.writeUInt32LE(Math.floor(EXPANDED_CAP / 3) + 1, entry.centralOffset + 24)
  }
  expectFailure('aggregate inflated bound', () => parseZip(tooLargeAggregate), 'ZIP aggregate inflated bound exceeded')
  expectFailure('compressed archive bound', () => parseZip(Buffer.alloc(ARCHIVE_CAP + 1)), 'ZIP archive exceeds the fixed compressed-byte bound')
  const badInflated = Buffer.from(valid); badInflated.writeUInt32LE(99, 22); badInflated.writeUInt32LE(99, accepted.entries[0].centralOffset + 24)
  expectFailure('inflated size', () => parseZip(badInflated), 'ZIP member uncompressed size mismatch')
}

async function main() {
  const mode = process.argv[2]
  if (mode === '--acquire') return acquire()
  if (mode === '--extract') return extract()
  if (mode === '--source-fixtures') return runSourceFixtures()
  fail('Usage: node acquire-node-toolchain.mjs --source-fixtures|--acquire|--extract')
}
main().catch((error) => { process.stderr.write(`Node toolchain step stopped: ${error.message}\n`); process.exitCode = 1 })
