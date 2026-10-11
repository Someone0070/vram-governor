#!/usr/bin/env node
import { createHash } from 'node:crypto'
import { lstat, mkdir, open, realpath, readdir } from 'node:fs/promises'
import { gunzipSync, gzipSync } from 'node:zlib'
import path from 'node:path'
import process from 'node:process'

const root = process.cwd()
const frontend = 'web/comfy/upstream/frontend-1.51.9'
const lockRelative = `${frontend}/pnpm-lock.yaml`
const lockSha256 = '37c632265a683d9ee593f21d0f2d7fa5de44f840f59c2e4ce65356216d8824d3'
const pnpmVersion = '11.13.1'
const registryOrigin = 'https://registry.npmjs.org'
const artifactLimit = 1_510
const metadataRequestLimit = 1_520
const tarballRequestLimit = 1_520
const aggregateRequestLimit = 3_040
const metadataByteLimit = 1_048_576
const artifactByteLimit = 64 * 1_048_576
const iconifyJsonByteLimit = 128 * 1_048_576
const aggregateArchiveByteLimit = 3 * 1_073_741_824
const perArchiveExpandedByteLimit = 512 * 1_048_576
const aggregateArchiveExpandedByteLimit = 8 * 1_073_741_824
const aggregateExpandedByteLimit = 8 * 1_073_741_824
const expandedEntryCountLimit = 1_000_000
const tarRawPathByteLimit = 4_096
const tarPathComponentByteLimit = 255
const paxPayloadByteLimit = 1_048_576
const paxRecordCountLimit = 512
const paxKeyByteLimit = 512
const paxInertValueByteLimit = 8_192
const paxVendorPropertyDepthLimit = 16
const paxIgnoreFileIndexLimit = 1_024
const inertPaxControlPattern = /[\u0000-\u001f\u007f-\u009f]/
const computedExtractionPathByteLimit = 240
const requestTimeoutMs = 60_000
const lockByteLimit = 1_000_000
const planByteLimit = 8 * 1_048_576
const acquisitionManifestByteLimit = 128 * 1_048_576
const extractedManifestByteLimit = 256 * 1_048_576
const packageJsonByteLimit = 2 * 1_048_576
const licenseTextByteLimit = 8 * 1_048_576
const aggregateLicenseTextByteLimit = 128 * 1_048_576
const licenseInspectionReportByteLimit = 256 * 1_048_576
const maxFilesystemDeviceOrInode = (1n << 64n) - 1n
const maxFilesystemMode = (1n << 32n) - 1n
const pnpmIntegrity = 'sha512-svx2g7imUlQU59E+G6KMqt3elr9m7FQL+ut+cCuB8+C+TR8pXt9/n+A5Z0Co3ORQnFgt33mJH0VD/qMtN2RfJQ=='
const pnpmTarball = 'https://registry.npmjs.org/pnpm/-/pnpm-11.13.1.tgz'
const pnpmPinSource = '.unlazy/fleet-residency-v2/comfy-pnpm-official-pin1.json'
const pnpmPinSourceSha256 = '0666a2a18f37cce20479f0f6cdb0c94ad43d70329a71f03df33217623a9fb1c2'
const pnpmPinSourceByteLimit = 4 * 1_024
const iconifyJsonException = Object.freeze({
  locator: '@iconify/json@2.2.500',
  name: '@iconify/json',
  version: '2.2.500',
  integrity: 'sha512-bATR7cvwt8wnN64lYPrd5IJQexowKut76r+TpZnmHnfatLp94TItwzLd5gd3fEC+5HW8TWE7flV7uct6qZaFWA==',
  tarball: 'https://registry.npmjs.org/@iconify/json/-/json-2.2.500.tgz',
  byteLimit: iconifyJsonByteLimit
})
const prefix = 'web/comfy/build-artifacts-v2'
const planRelative = 'web/comfy/build-artifacts-plan-v3.json'
const licenseInspectionReportRelative = `${prefix}/license-inspection-report.json`

function fail(message) {
  throw new Error(message)
}

class LicensePolicyError extends Error {
  constructor(code, message) {
    super(message)
    this.name = 'LicensePolicyError'
    this.code = code
  }
}

function licensePolicyFail(code, message) {
  throw new LicensePolicyError(code, message)
}

function hash(bytes, algorithm) {
  return createHash(algorithm).update(bytes).digest(algorithm === 'sha512' ? 'base64' : 'hex')
}

function assertArtifactIntegrity(lockIntegrity, registryIntegrity, bytes, label) {
  if (!/^sha512-[A-Za-z0-9+/]{86}==$/.test(lockIntegrity || '') || registryIntegrity !== lockIntegrity) {
    fail(`Artifact SRI differs from its fixed lock/publisher pin: ${label}`)
  }
  if (`sha512-${hash(bytes, 'sha512')}` !== lockIntegrity) fail(`Artifact bytes differ from their fixed SRI: ${label}`)
}

function archiveLimitPolicy() {
  return {
    defaultBytes: artifactByteLimit,
    aggregateBytes: aggregateArchiveByteLimit,
    exception: { ...iconifyJsonException }
  }
}

function acquisitionLimits() {
  return {
    artifactLimit, metadataRequestLimit, tarballRequestLimit, aggregateRequestLimit,
    metadataByteLimit, artifactByteLimit, iconifyJsonByteLimit, aggregateArchiveByteLimit,
    requestTimeoutMs, archiveLimitPolicy: archiveLimitPolicy()
  }
}

function archiveByteLimitFor(artifact, registryTarball) {
  const exactExceptionIdentity = artifact?.locator === iconifyJsonException.locator &&
    artifact?.name === iconifyJsonException.name && artifact?.version === iconifyJsonException.version &&
    artifact?.integrity === iconifyJsonException.integrity
  if (!exactExceptionIdentity) return artifactByteLimit
  if (registryTarball !== undefined && registryTarball !== iconifyJsonException.tarball) {
    fail(`Iconify archive exception requires the exact pinned tarball URL: ${artifact.locator}`)
  }
  return iconifyJsonException.byteLimit
}

function assertArchiveByteLimitRecord(artifact, claimedLimit, registryTarball, label) {
  const expectedLimit = archiveByteLimitFor(artifact, registryTarball)
  if (expectedLimit === iconifyJsonByteLimit && registryTarball !== iconifyJsonException.tarball) {
    fail(`${label} archive exception is not bound to the fixed tarball URL`)
  }
  if (claimedLimit !== expectedLimit) fail(`${label} archive byte limit differs from the fixed artifact policy`)
  return expectedLimit
}

function lockExpectedIdentity(expected, ordinal, label) {
  let parsedIdentity
  try { parsedIdentity = artifactIdentity(expected?.locator) } catch { fail(`${label} authenticated lock identity is malformed`) }
  if (!expected || typeof expected.locator !== 'string' || typeof expected.name !== 'string' ||
    typeof expected.version !== 'string' || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(expected.integrity) ||
    parsedIdentity.name !== expected.name || parsedIdentity.version !== expected.version) {
    fail(`${label} authenticated lock identity is malformed`)
  }
  return { ordinal, locator: expected.locator, name: expected.name, version: expected.version, integrity: expected.integrity }
}

function authenticatedExpectedArtifact(expectedArtifacts, ordinal, record, label) {
  if (!Number.isSafeInteger(ordinal) || ordinal < 0 || ordinal >= expectedArtifacts.length || record?.ordinal !== ordinal) {
    fail(`${label} ordinal mismatch`)
  }
  const expected = expectedArtifacts[ordinal]
  const expectedIdentity = lockExpectedIdentity(expected, ordinal, label)
  if (record.locator !== expected.locator) fail(`${label} locator mismatch`)
  if (record.lockIntegrity !== expected.integrity) fail(`${label} locked SRI mismatch`)
  if (record.registryIntegrity !== expected.integrity) fail(`${label} registry SRI mismatch`)
  return expectedIdentity
}

function assertCheckedPackageIdentity(ordinal, artifact, expectedIdentity, packageJson, label) {
  const identityKeys = ['ordinal', 'locator', 'name', 'version', 'integrity']
  if (!expectedIdentity || typeof expectedIdentity !== 'object' || Array.isArray(expectedIdentity) ||
    JSON.stringify(Object.keys(expectedIdentity).sort()) !== JSON.stringify([...identityKeys].sort()) ||
    !Number.isSafeInteger(expectedIdentity.ordinal) || expectedIdentity.ordinal !== ordinal ||
    typeof expectedIdentity.locator !== 'string' || typeof expectedIdentity.name !== 'string' ||
    typeof expectedIdentity.version !== 'string' || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(expectedIdentity.integrity)) {
    fail(`${label} authenticated lock identity is missing or malformed`)
  }
  let parsedIdentity
  try { parsedIdentity = artifactIdentity(expectedIdentity.locator) } catch { fail(`${label} authenticated lock identity is malformed`) }
  if (parsedIdentity.name !== expectedIdentity.name || parsedIdentity.version !== expectedIdentity.version) {
    fail(`${label} authenticated lock identity is malformed`)
  }
  if (!Number.isSafeInteger(ordinal) || artifact?.ordinal !== ordinal) fail(`${label} acquisition ordinal mismatch`)
  if (artifact?.locator !== expectedIdentity.locator) fail(`${label} locator mismatch`)
  if (artifact?.lockIntegrity !== expectedIdentity.integrity) fail(`${label} locked SRI mismatch`)
  if (artifact?.registryIntegrity !== expectedIdentity.integrity) fail(`${label} registry SRI mismatch`)
  if (packageJson?.name !== expectedIdentity.name || packageJson?.version !== expectedIdentity.version) {
    fail(`${label} package manifest identity mismatch`)
  }
  return expectedIdentity
}

function validateAcquisitionArchiveRecord(expectedArtifacts, ordinal, record, label) {
  authenticatedExpectedArtifact(expectedArtifacts, ordinal, record, label)
  const expected = expectedArtifacts[ordinal]
  let tarball
  try { tarball = new URL(record.registryTarball) } catch { fail(`${label} registry URL is invalid`) }
  if (tarball.origin !== registryOrigin || tarball.protocol !== 'https:' || tarball.username || tarball.password ||
    (expected.locator === `pnpm@${pnpmVersion}` && tarball.href !== pnpmTarball)) {
    fail(`${label} registry URL is not allowlisted`)
  }
  return assertArchiveByteLimitRecord(expected, record.archiveByteLimit, tarball.href, label)
}

function authenticatedRootIdentity(expectedIdentity) {
  const identityKeys = ['ordinal', 'locator', 'name', 'version', 'integrity']
  if (!expectedIdentity || typeof expectedIdentity !== 'object' || Array.isArray(expectedIdentity) ||
    JSON.stringify(Object.keys(expectedIdentity).sort()) !== JSON.stringify([...identityKeys].sort()) ||
    !Number.isSafeInteger(expectedIdentity.ordinal) || expectedIdentity.ordinal < 0 ||
    typeof expectedIdentity.locator !== 'string' || typeof expectedIdentity.name !== 'string' ||
    typeof expectedIdentity.version !== 'string' || !/^sha512-[A-Za-z0-9+/]{86}==$/.test(expectedIdentity.integrity)) return null
  let parsed
  try { parsed = artifactIdentity(expectedIdentity.locator) } catch { return null }
  return parsed.name === expectedIdentity.name && parsed.version === expectedIdentity.version ? expectedIdentity : null
}

function safeTypesArchiveRootComponent(archiveRoot) {
  const windowsBase = archiveRoot.split('.')[0]?.replace(/[. ]+$/g, '').toUpperCase()
  return Boolean(archiveRoot && !archiveRoot.startsWith('.') && !archiveRoot.includes('/') &&
    archiveRoot !== '.' && archiveRoot !== '..' && Buffer.byteLength(archiveRoot, 'utf8') <= tarPathComponentByteLimit &&
    !/[^\x20-\x7e]/.test(archiveRoot) && !/[<>:"|?*\u0000-\u001f]/.test(archiveRoot) &&
    !/[. ]$/.test(archiveRoot) && !/^(CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/.test(windowsBase))
}

function expectedTypesArchiveRoots(expectedIdentity) {
  const identity = authenticatedRootIdentity(expectedIdentity)
  if (!identity || !identity.name.startsWith('@types/')) return []
  const archiveRoot = identity.name.slice('@types/'.length)
  if (!safeTypesArchiveRootComponent(archiveRoot)) return []
  const roots = [archiveRoot]
  const versionMatch = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.exec(identity.version)
  if (!versionMatch || versionMatch.slice(1).some((component) => !Number.isSafeInteger(Number(component)))) return roots
  const versionedRoot = `${archiveRoot} v${versionMatch[1]}.${versionMatch[2]}`
  if (safeTypesArchiveRootComponent(versionedRoot)) roots.push(versionedRoot)
  return roots
}

function expectedOrdinaryVersionedArchiveRoot(expectedIdentity) {
  const identity = authenticatedRootIdentity(expectedIdentity)
  if (!identity || identity.name.startsWith('@') || identity.name.includes('/') ||
    !safeTypesArchiveRootComponent(identity.name)) return null
  const versionMatch = /^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/.exec(identity.version)
  if (!versionMatch || versionMatch.slice(1).some((component) => !Number.isSafeInteger(Number(component)))) return null
  const root = `${identity.name}-v${identity.version}`
  return safeTypesArchiveRootComponent(root) ? root : null
}

function asciiCaseFold(value) {
  return value.replace(/[A-Z]/g, (letter) => String.fromCharCode(letter.charCodeAt(0) + 0x20))
}

function isAuthenticatedArchiveRoot(archiveRoot, expectedIdentity) {
  if (expectedTypesArchiveRoots(expectedIdentity).includes(archiveRoot)) return true
  const expectedRoot = expectedOrdinaryVersionedArchiveRoot(expectedIdentity)
  if (!expectedRoot || typeof archiveRoot !== 'string') return false
  const nameLength = expectedIdentity.name.length
  return archiveRoot.length === expectedRoot.length &&
    asciiCaseFold(archiveRoot.slice(0, nameLength)) === asciiCaseFold(expectedIdentity.name) &&
    archiveRoot.slice(nameLength) === `-v${expectedIdentity.version}`
}

function assertSelectedArchiveRoot(expectedIdentity, archiveRoot) {
  if (archiveRoot === 'package') return archiveRoot
  if (!isAuthenticatedArchiveRoot(archiveRoot, expectedIdentity)) {
    fail(`Archive root ${JSON.stringify(archiveRoot)} is not authorized by authenticated package identity ${JSON.stringify(expectedIdentity?.name ?? null)}`)
  }
  validateTarPath(`${archiveRoot}/__archive_root_check__`, { expectedIdentity })
  return archiveRoot
}

function assertPackageArchiveRootProvenance(expectedIdentity, archiveRoot, archiveMembers) {
  assertSelectedArchiveRoot(expectedIdentity, archiveRoot)
  if (!Array.isArray(archiveMembers)) fail('Package archive-root member inventory is missing')
  assertGnuLongNameBindings(archiveMembers, expectedIdentity)
  for (const member of archiveMembers) {
    assertTarHeaderLayoutProvenance(member?.headerLayout, member?.headerPrefix)
    if (member?.type === 'pax-extension' || member?.type === 'gnu-long-name') {
      if (member.archiveRoot !== null) fail('Tar metadata member unexpectedly claims an output root')
      continue
    }
    const pathInfo = validateTarPath(member?.rawPath, {
      directory: member?.type === 'directory', expectedIdentity
    })
    const headerPathInfo = validateTarPath(member?.headerPath, {
      directory: member?.type === 'directory', expectedIdentity
    })
    if (headerPathInfo.archiveRoot !== pathInfo.archiveRoot ||
      member.archiveRoot !== pathInfo.archiveRoot || member.archiveRoot !== archiveRoot ||
      member.canonicalPath !== pathInfo.canonicalPath || member.path !== pathInfo.canonicalPath) {
      fail(`Archive member root provenance differs from its authenticated package identity: ${member?.rawPath}`)
    }
  }
}

function decodeGnuLongNamePayload(payload) {
  if (!Buffer.isBuffer(payload) || payload.length < 2 || payload.length > 4_096) {
    fail('GNU long-name payload must contain 2..4096 bytes')
  }
  const nul = payload.indexOf(0)
  if (nul <= 0 || payload.subarray(nul + 1).some((byte) => byte !== 0)) {
    fail('GNU long-name payload requires a nonempty NUL-terminated path and zero-only remainder')
  }
  let value
  try { value = new TextDecoder('utf-8', { fatal: true }).decode(payload.subarray(0, nul)) } catch {
    fail('GNU long-name path is not strict UTF-8')
  }
  if (!value) fail('GNU long-name path is empty')
  return value
}

function assertTarMemberHeaderBytes(member) {
  if (typeof member?.headerBytesHex !== 'string' || !/^(?:[0-9a-f]{2}){512}$/.test(member.headerBytesHex)) {
    fail('Tar member full header bytes are missing or malformed')
  }
  const header = Buffer.from(member.headerBytesHex, 'hex')
  if (hash(header, 'sha256') !== member.headerLayout?.headerSha256) {
    fail('Tar member full header bytes do not match the header digest')
  }
  const storedChecksum = tarOctal(header, 148, 8)
  let checksum = 0
  for (let index = 0; index < 512; index++) checksum += index >= 148 && index < 156 ? 32 : header[index]
  const headerName = tarText(header, 0, 100)
  const headerType = tarText(header, 156, 1) || '\0'
  const prefix = decodeTarHeaderLayout(header).prefix
  const headerPath = prefix ? `${prefix}/${headerName}` : headerName
  if (checksum !== storedChecksum || headerName !== member.headerName || headerType !== member.headerType ||
    headerPath !== member.headerPath || prefix !== member.headerPrefix || member.dataOffset !== member.headerOffset + 512 ||
    (member.type === 'gnu-long-name' && tarOctal(header, 124, 12) !== member.payloadBytes)) {
    fail('Tar member header annotations do not match its complete header bytes')
  }
  assertTarHeaderLayoutMatchesHeader(header, member.headerLayout)
}

function assertGnuLongNameBindings(archiveMembers, expectedIdentity) {
  if (!Array.isArray(archiveMembers)) fail('GNU long-name member inventory is missing')
  for (let index = 0; index < archiveMembers.length; index++) {
    const member = archiveMembers[index]
    if (!member || !['file', 'directory', 'pax-extension', 'gnu-long-name'].includes(member.type) ||
      !Object.hasOwn(member, 'gnuLongNameMetadataIndex') || !Object.hasOwn(member, 'gnuLongNamePath')) {
      fail('Archive member uses an unsupported type or omits GNU long-name provenance fields')
    }
    const previous = index === 0 ? null : archiveMembers[index - 1]
    const expectedOffset = previous
      ? previous.headerOffset + 512 + Math.ceil(previous.payloadBytes / 512) * 512
      : 0
    if (member.headerOffset !== expectedOffset) fail('Tar archive-member header offsets are missing or noncontiguous')
    assertTarMemberHeaderBytes(member)
    if (member?.type === 'gnu-long-name') {
      const keys = ['index', 'type', 'headerType', 'headerPrefix', 'headerLayout', 'headerName', 'headerPath', 'rawPath',
        'headerBytesHex', 'archiveRoot', 'paxPath', 'path', 'canonicalPath', 'headerOffset', 'dataOffset', 'offsetBasis', 'payloadBytes',
        'payloadSha256', 'gnuLongNameMetadataIndex', 'gnuLongNamePath', 'gnuLongNamePayloadHex', 'targetHeaderOffset']
      if (JSON.stringify(Object.keys(member).sort()) !== JSON.stringify([...keys].sort()) || member.index !== index ||
        member.headerType !== 'L' || member.archiveRoot !== null || member.paxPath !== null || member.path !== null ||
        member.canonicalPath !== null || member.rawPath !== member.headerPath || member.gnuLongNameMetadataIndex !== null ||
        member.offsetBasis !== 'uncompressed-tar-stream-bytes' ||
        !Number.isSafeInteger(member.headerOffset) || member.headerOffset < 0 || member.dataOffset !== member.headerOffset + 512 ||
        !Number.isSafeInteger(member.payloadBytes) || member.payloadBytes < 2 || member.payloadBytes > 4_096 ||
        !/^[0-9a-f]{64}$/.test(member.payloadSha256) || !/^(?:[0-9a-f]{2})+$/.test(member.gnuLongNamePayloadHex ?? '')) {
        fail('GNU long-name metadata provenance is missing or malformed')
      }
      const payload = Buffer.from(member.gnuLongNamePayloadHex, 'hex')
      const decoded = decodeGnuLongNamePayload(payload)
      if (payload.length !== member.payloadBytes || hash(payload, 'sha256') !== member.payloadSha256 ||
        decoded !== member.gnuLongNamePath || member.targetHeaderOffset !== member.headerOffset + 512 + Math.ceil(member.payloadBytes / 512) * 512) {
        fail('GNU long-name payload or immediate-target offset provenance is forged')
      }
      const target = archiveMembers[index + 1]
      if (!target || !['file', 'directory'].includes(target.type) || target.headerOffset !== member.targetHeaderOffset ||
        target.gnuLongNameMetadataIndex !== index ||
        target.gnuLongNamePath !== decoded || target.rawPath !== decoded) {
        fail('GNU long-name metadata is not reciprocally bound to its immediate target')
      }
      const targetDirectory = target.type === 'directory'
      const effective = validateTarPath(decoded, { directory: targetDirectory, expectedIdentity })
      const shortHeader = validateTarPath(target.headerPath, { directory: targetDirectory, expectedIdentity })
      if (effective.archiveRoot !== shortHeader.archiveRoot || effective.archiveRoot !== target.archiveRoot ||
        effective.canonicalPath !== target.canonicalPath) {
        fail('GNU long-name target root or canonical path provenance differs from its short header')
      }
    } else if (member && (Object.hasOwn(member, 'gnuLongNamePayloadHex') || Object.hasOwn(member, 'targetHeaderOffset'))) {
      fail('GNU long-name annotations appear on a non-metadata member')
    }
    if (member?.type !== 'gnu-long-name' && member && (member.gnuLongNameMetadataIndex !== null &&
      member.gnuLongNameMetadataIndex !== undefined)) {
      const metadata = archiveMembers[member.gnuLongNameMetadataIndex]
      if (!Number.isSafeInteger(member.gnuLongNameMetadataIndex) || metadata?.type !== 'gnu-long-name' ||
        metadata.index + 1 !== index || metadata.targetHeaderOffset !== member.headerOffset ||
        metadata.gnuLongNamePath !== member.gnuLongNamePath || member.rawPath !== member.gnuLongNamePath) {
        fail('GNU long-name target linkage is missing or forged')
      }
    } else if (member?.type !== 'gnu-long-name' && member && member.gnuLongNamePath !== null &&
      member.gnuLongNamePath !== undefined) {
      fail('GNU long-name path annotation has no metadata target')
    }
  }
}

function assertPackageAliasProvenance(ordinal, archiveMembers, files, expectedIdentity, archiveRoot) {
  if (!Array.isArray(archiveMembers) || !Array.isArray(files)) fail('Package alias provenance inventories are missing')
  assertPackageArchiveRootProvenance(expectedIdentity, archiveRoot, archiveMembers)
  const ordinalPrefix = `${packageDirectoryName(ordinal)}/`
  const fileRecords = files.filter((record) => record?.type === 'file')
  const memberToOutput = new Map()
  for (const record of fileRecords) {
    if (typeof record.path !== 'string' || !record.path.startsWith(ordinalPrefix) ||
      !Array.isArray(record.archiveMemberIndices) || record.archiveMemberIndices.length < 1 ||
      record.archiveMemberIndices.some((index, position, indices) => !Number.isSafeInteger(index) || index < 0 ||
        (position > 0 && indices[position - 1] >= index)) ||
      record.archiveMemberIndex !== record.archiveMemberIndices[0]) {
      fail(`Package file alias group has invalid primary or sorted member indices: ${record.path}`)
    }
    const relativePath = record.path.slice(ordinalPrefix.length)
    for (const index of record.archiveMemberIndices) {
      const member = archiveMembers[index]
      if (!member || member.index !== index || member.type !== 'file' || member.path !== relativePath ||
        member.outputPath !== relativePath || member.outputPrimaryArchiveMemberIndex !== record.archiveMemberIndex ||
        JSON.stringify(member.outputArchiveMemberIndices) !== JSON.stringify(record.archiveMemberIndices) || memberToOutput.has(index)) {
        fail(`Package file alias group does not bind every archive member exactly once: ${record.path}`)
      }
      memberToOutput.set(index, record.path)
    }
  }
  const archiveFiles = archiveMembers.filter((member) => member?.type === 'file')
  if (memberToOutput.size !== archiveFiles.length || archiveFiles.some((member) => memberToOutput.get(member.index) === undefined)) {
    fail('Package output inventory omits or adds a regular-file archive member alias')
  }
}

function packageInventoryRecord(checked, identityForFile, trustedExpectedIdentity) {
  const { ordinal, artifact, archiveByteLimit, archiveExpandedBytes, archiveRoot, packageJson, archiveMembers, files } = checked
  if (JSON.stringify(trustedExpectedIdentity) !== JSON.stringify(checked.expectedIdentity)) {
    fail(`Package lock identity differs from authenticated closure at ordinal ${ordinal}`)
  }
  const expectedIdentity = assertCheckedPackageIdentity(ordinal, artifact, trustedExpectedIdentity, packageJson,
    `Package at ordinal ${ordinal}`)
  if (checked.archiveMembersSha256 !== archiveMemberInventorySha256(archiveMembers)) {
    fail(`Package archive-member provenance changed at ordinal ${ordinal}`)
  }
  assertPackageAliasProvenance(ordinal, archiveMembers, files, expectedIdentity, archiveRoot)
  const measuredHeaderLayoutSha256 = headerLayoutInventorySha256(archiveMembers)
  if (checked.headerLayoutSha256 !== measuredHeaderLayoutSha256) fail(`Package header-layout provenance changed at ordinal ${ordinal}`)
  if (!Number.isSafeInteger(archiveExpandedBytes) || archiveExpandedBytes < 0 || archiveExpandedBytes > perArchiveExpandedByteLimit) {
    fail(`Package archive-expanded byte count is invalid at ordinal ${ordinal}`)
  }
  return {
    ordinal,
    locator: artifact.locator,
    archive: artifact.archive,
    archiveByteLimit,
    archiveExpandedBytes,
    archiveRoot,
    headerLayoutSha256: measuredHeaderLayoutSha256,
    archiveBytes: artifact.bytes,
    archiveSha256: artifact.sha256,
    metadata: artifact.metadata,
    metadataSha256: artifact.metadataSha256,
    packageJson,
    archiveMembers,
    files: files.map((record) => ({ ...record, identity: identityForFile(record) }))
  }
}

function addSafeInventoryTotal(total, increment, limit, label) {
  const next = total + increment
  if (!Number.isSafeInteger(total) || total < 0 || !Number.isSafeInteger(increment) || increment < 0 ||
    !Number.isSafeInteger(next) || next > limit) {
    fail(`${label} is malformed or exceeds its fixed bound`)
  }
  return next
}

function assertPackageInventoryMatches(planned, actual, createdIdentities) {
  const packageKeys = ['ordinal', 'locator', 'archive', 'archiveByteLimit', 'archiveExpandedBytes', 'archiveRoot', 'headerLayoutSha256', 'archiveBytes', 'archiveSha256',
    'metadata', 'metadataSha256', 'packageJson', 'archiveMembers', 'files']
  if (!Array.isArray(planned) || !Array.isArray(actual) || planned.length !== actual.length) {
    fail('Final package inventory count differs from its preflight plan')
  }
  const exactKeys = (value, expected) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return false
    const keys = Object.keys(value).sort()
    const wanted = [...expected].sort()
    return keys.length === wanted.length && keys.every((key, index) => key === wanted[index])
  }
  for (let index = 0; index < planned.length; index++) {
    const before = planned[index]
    const after = actual[index]
    if (!exactKeys(before, packageKeys) || !exactKeys(after, packageKeys) ||
      !Array.isArray(before.files) || !Array.isArray(after.files) ||
      before.archiveByteLimit !== after.archiveByteLimit ||
      JSON.stringify({ ...before, files: undefined }) !== JSON.stringify({ ...after, files: undefined }) ||
      before.files.length !== after.files.length) {
      fail(`Final package inventory schema or cap differs from preflight at ordinal ${index}`)
    }
    for (let fileIndex = 0; fileIndex < before.files.length; fileIndex++) {
      const plannedFile = before.files[fileIndex]
      const actualFile = after.files[fileIndex]
      const fileKeys = plannedFile.type === 'directory'
        ? ['path', 'type', 'bytes', 'provenance', 'archiveMemberIndex', 'identity']
        : plannedFile.type === 'file'
          ? ['path', 'type', 'bytes', 'sha256', 'provenance', 'archiveMemberIndex', 'archiveMemberIndices', 'identity',
            ...(Object.hasOwn(plannedFile, 'licenseOrNotice') ? ['licenseOrNotice'] : [])]
          : []
      if (fileKeys.length === 0 || !exactKeys(plannedFile, fileKeys) || !exactKeys(actualFile, fileKeys) ||
        JSON.stringify({ ...plannedFile, identity: undefined }) !== JSON.stringify({ ...actualFile, identity: undefined })) {
        fail(`Final package file inventory schema differs from preflight at ordinal ${index}`)
      }
      const expectedIdentity = createdIdentities.get(`unpacked/${actualFile.path}`)
      if (!expectedIdentity || JSON.stringify(actualFile.identity) !== JSON.stringify(expectedIdentity)) {
        fail(`Final package file identity differs from the created output at ordinal ${index}`)
      }
    }
  }
}

function reserveExtractionInventory({ preflight, sourceManifestSha256, archiveMemberCount,
  aggregateArchiveExpandedBytes, createdDirectoryCount, aggregateExpandedBytes, trustedExpectedIdentities,
  identityReservation, manifestByteLimit = extractedManifestByteLimit }) {
  if (!Array.isArray(preflight) || !Array.isArray(trustedExpectedIdentities) ||
    trustedExpectedIdentities.length !== preflight.length || !/^[0-9a-f]{64}$/.test(sourceManifestSha256) ||
    !Number.isSafeInteger(archiveMemberCount) || archiveMemberCount < 1 ||
    !Number.isSafeInteger(aggregateArchiveExpandedBytes) || aggregateArchiveExpandedBytes < 1 ||
    !Number.isSafeInteger(createdDirectoryCount) || createdDirectoryCount < 1 ||
    !Number.isSafeInteger(aggregateExpandedBytes) || aggregateExpandedBytes < 0 ||
    !identityReservation || typeof identityReservation !== 'object' ||
    !Number.isSafeInteger(manifestByteLimit) || manifestByteLimit < 1 || manifestByteLimit > extractedManifestByteLimit) {
    fail('Extraction inventory reservation inputs are incomplete or malformed')
  }
  let measuredArchiveMemberCount = 0
  let measuredArchiveExpandedBytes = 0
  for (let index = 0; index < preflight.length; index++) {
    const checked = preflight[index]
    const trustedIdentity = trustedExpectedIdentities[index]
    if (checked?.ordinal !== index || !Array.isArray(checked.archiveMembers) || !Array.isArray(checked.files) ||
      !Number.isSafeInteger(checked.archiveExpandedBytes) || checked.archiveExpandedBytes < 1 ||
      checked.archiveExpandedBytes > perArchiveExpandedByteLimit ||
      JSON.stringify(checked.expectedIdentity) !== JSON.stringify(trustedIdentity)) {
      fail(`Extraction inventory package record is incomplete or out of ordinal order at ${index}`)
    }
    assertPackageAliasProvenance(index, checked.archiveMembers, checked.files, trustedIdentity, checked.archiveRoot)
    measuredArchiveMemberCount = addSafeInventoryTotal(measuredArchiveMemberCount, checked.archiveMembers.length,
      expandedEntryCountLimit, 'Extraction archive-member total')
    measuredArchiveExpandedBytes = addSafeInventoryTotal(measuredArchiveExpandedBytes, checked.archiveExpandedBytes,
      aggregateArchiveExpandedByteLimit, 'Extraction archive-expanded total')
  }
  assertPackageArchiveExpansion(preflight, measuredArchiveExpandedBytes)
  const plannedInventory = [
    { path: 'unpacked', type: 'directory', bytes: 0, provenance: 'extraction-root', identity: identityReservation },
    ...preflight.flatMap((checked) => checked.files.map((record) => ({
      ...record,
      path: `unpacked/${record.path}`,
      identity: identityReservation
    })))
  ].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
  let measuredCreatedDirectoryCount = 0
  let measuredExpandedBytes = 0
  for (const record of plannedInventory) {
    if (!record || (record.type !== 'file' && record.type !== 'directory') ||
      !Number.isSafeInteger(record.bytes) || record.bytes < 0) {
      fail('Extraction inventory output record is malformed')
    }
    if (record.type === 'directory') {
      measuredCreatedDirectoryCount = addSafeInventoryTotal(measuredCreatedDirectoryCount, 1,
        expandedEntryCountLimit, 'Extraction created-directory total')
    } else {
      measuredExpandedBytes = addSafeInventoryTotal(measuredExpandedBytes, record.bytes,
        aggregateExpandedByteLimit, 'Extraction output-byte total')
    }
  }
  const measuredOutputPathCount = plannedInventory.length
  const measuredCombinedEntryCount = addSafeInventoryTotal(measuredArchiveMemberCount, measuredCreatedDirectoryCount,
    expandedEntryCountLimit, 'Extraction combined member/directory total')
  if (plannedInventory[0]?.path !== 'unpacked' ||
    plannedInventory.filter((record) => record.path === 'unpacked' && record.type === 'directory').length !== 1 ||
    new Set(plannedInventory.map((record) => record.path)).size !== measuredOutputPathCount ||
    measuredOutputPathCount > expandedEntryCountLimit || archiveMemberCount !== measuredArchiveMemberCount ||
    aggregateArchiveExpandedBytes !== measuredArchiveExpandedBytes || createdDirectoryCount !== measuredCreatedDirectoryCount ||
    aggregateExpandedBytes !== measuredExpandedBytes || measuredCombinedEntryCount > expandedEntryCountLimit) {
    fail('Extraction inventory reservation counters differ from complete package/output inventory')
  }
  const plannedExtraction = {
    schema: 'comfy-canvas-extracted-build-closure/v9',
    sourceManifestSha256,
    outputRoot: `${prefix}/unpacked`,
    platform: 'win32-x64',
    archiveLimitPolicy: archiveLimitPolicy(),
    extractionLimits: { perArchiveExpandedByteLimit, aggregateArchiveExpandedByteLimit, aggregateExpandedByteLimit, expandedEntryCountLimit },
    archiveMemberCount,
    aggregateArchiveExpandedBytes,
    createdDirectoryCount,
    outputPathCount: plannedInventory.length,
    aggregateExpandedBytes,
    packages: preflight.map((checked) => packageInventoryRecord(checked, () => identityReservation,
      trustedExpectedIdentities[checked.ordinal])),
    outputInventory: plannedInventory
  }
  const reservedManifestBytes = boundedCompactJsonBytes(plannedExtraction, manifestByteLimit,
    'Extracted inventory manifest reservation')
  return { plannedExtraction, plannedInventory, reservedManifestBytes }
}

function assembleFinalExtractionInventory(plannedExtraction, sourceManifestSha256, observedPlan, finalPackages, createdIdentities) {
  if (!plannedExtraction || plannedExtraction.schema !== 'comfy-canvas-extracted-build-closure/v9' ||
    !Array.isArray(plannedExtraction.packages) || plannedExtraction.packages.length < 1 ||
    !/^[0-9a-f]{64}$/.test(sourceManifestSha256) || !Array.isArray(plannedExtraction.outputInventory) ||
    !Array.isArray(observedPlan) || !Array.isArray(finalPackages)) {
    fail('Final extraction inventory inputs are incomplete or malformed')
  }
  assertPackageInventoryMatches(plannedExtraction.packages, finalPackages, createdIdentities)
  let measuredArchiveMemberCount = 0
  let measuredArchiveExpandedBytes = 0
  let measuredExpandedBytes = 0
  for (let index = 0; index < finalPackages.length; index++) {
    const checked = finalPackages[index]
    if (checked?.ordinal !== index || !Array.isArray(checked.archiveMembers) || !Array.isArray(checked.files)) {
      fail(`Final extraction package record is incomplete or out of ordinal order at ${index}`)
    }
    measuredArchiveMemberCount = addSafeInventoryTotal(measuredArchiveMemberCount, checked.archiveMembers.length,
      expandedEntryCountLimit, 'Final extraction archive-member total')
    measuredArchiveExpandedBytes = addSafeInventoryTotal(measuredArchiveExpandedBytes, checked.archiveExpandedBytes,
      aggregateArchiveExpandedByteLimit, 'Final extraction archive-expanded total')
    for (const record of checked.files) {
      if (!record || (record.type !== 'file' && record.type !== 'directory') ||
        !Number.isSafeInteger(record.bytes) || record.bytes < 0) {
        fail(`Final extraction package output record is malformed at ordinal ${index}`)
      }
      if (record.type === 'file') {
        measuredExpandedBytes = addSafeInventoryTotal(measuredExpandedBytes, record.bytes,
          aggregateExpandedByteLimit, 'Final extraction output-byte total')
      }
    }
  }
  assertPackageArchiveExpansion(finalPackages, measuredArchiveExpandedBytes)
  const completeOutputInventory = [
    { path: 'unpacked', type: 'directory', bytes: 0, provenance: 'extraction-root' },
    ...finalPackages.flatMap((checked) => checked.files.map((record) => ({ ...record, path: `unpacked/${record.path}`, identity: undefined })))
  ].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
  const observedOutputInventory = observedPlan.map((record) => ({ ...record, identity: undefined }))
  const reservedOutputInventory = plannedExtraction.outputInventory.map((record) => ({ ...record, identity: undefined }))
  const measuredCreatedDirectoryCount = completeOutputInventory.filter((record) => record.type === 'directory').length
  const measuredOutputPathCount = completeOutputInventory.length
  const measuredCombinedEntryCount = addSafeInventoryTotal(measuredArchiveMemberCount, measuredCreatedDirectoryCount,
    expandedEntryCountLimit, 'Final extraction combined member/directory total')
  if (JSON.stringify(observedOutputInventory) !== JSON.stringify(completeOutputInventory) ||
    JSON.stringify(reservedOutputInventory) !== JSON.stringify(completeOutputInventory) ||
    new Set(completeOutputInventory.map((record) => record.path)).size !== measuredOutputPathCount ||
    measuredOutputPathCount > expandedEntryCountLimit ||
    plannedExtraction.archiveMemberCount !== measuredArchiveMemberCount ||
    plannedExtraction.aggregateArchiveExpandedBytes !== measuredArchiveExpandedBytes ||
    plannedExtraction.createdDirectoryCount !== measuredCreatedDirectoryCount ||
    plannedExtraction.outputPathCount !== measuredOutputPathCount ||
    plannedExtraction.aggregateExpandedBytes !== measuredExpandedBytes || measuredCombinedEntryCount > expandedEntryCountLimit) {
    fail('Final extraction reservation counters differ from complete final package/output inventory')
  }
  if (observedPlan.length !== plannedExtraction.outputInventory.length || observedPlan.some((record, index) =>
    record.path !== plannedExtraction.outputInventory[index].path || record.type !== plannedExtraction.outputInventory[index].type ||
    record.bytes !== plannedExtraction.outputInventory[index].bytes ||
    JSON.stringify({ ...record, identity: undefined }) !== JSON.stringify({ ...plannedExtraction.outputInventory[index], identity: undefined }))) {
    fail('Final extraction output inventory differs from its complete reservation')
  }
  return { ...plannedExtraction, sourceManifestSha256, outputInventory: observedPlan, packages: finalPackages }
}

function safePath(relative) {
  if (typeof relative !== 'string' || !relative || path.isAbsolute(relative) ||
    relative.split(/[\\/]/).some((part) => !part || part === '.' || part === '..' || /[<>:"|?*\u0000-\u001f]/.test(part))) {
    fail(`Path is not a safe workspace-relative path: ${relative}`)
  }
  const absolute = path.resolve(root, relative)
  if (!pathIsContained(root, absolute) || path.resolve(root) === absolute) fail(`Path escaped workspace: ${relative}`)
  return absolute
}

function pathIsContained(base, target) {
  const resolvedBase = path.resolve(base)
  const resolvedTarget = path.resolve(target)
  const back = path.relative(resolvedBase, resolvedTarget)
  return Boolean(back) && back !== '..' && !back.startsWith(`..${path.sep}`) && !path.isAbsolute(back)
}

function isReparsePoint(info) {
  if (info.isSymbolicLink()) return true
  const attributes = info.attributes
  if (attributes === undefined || attributes === null) return false
  if (typeof attributes === 'bigint') return (attributes & 0x400n) !== 0n
  if (!Number.isSafeInteger(attributes) || attributes < 0) fail('Filesystem attributes are not safely representable')
  return (attributes & 0x400) !== 0
}

function assertPlainPathInfo(info, label) {
  if (isReparsePoint(info)) fail(`Reparse point in filesystem path: ${label}`)
}

function boundedStatNumber(value, limit, label) {
  if (typeof value !== 'bigint' || value < 0n || !Number.isSafeInteger(limit) || limit < 0 || value > BigInt(limit)) {
    fail(`${label} is not a bounded non-negative filesystem integer`)
  }
  const converted = Number(value)
  if (!Number.isSafeInteger(converted) || BigInt(converted) !== value) {
    fail(`${label} cannot be represented exactly as a bounded Number`)
  }
  return converted
}

function assertBoundedRegularFile(info, limit, label) {
  assertPlainPathInfo(info, label)
  const size = boundedStatNumber(info.size, limit, `${label} size`)
  if (!info.isFile() || typeof info.nlink !== 'bigint' || info.nlink !== 1n) {
    fail(`${label} is not a bounded regular single-link file`)
  }
  return size
}

function appendBoundedChunk(chunks, total, chunk, limit, label) {
  const next = total + chunk.byteLength
  if (!Number.isSafeInteger(next) || next > limit) fail(`${label} exceeded its ${limit}-byte limit`)
  chunks.push(Buffer.from(chunk))
  return next
}

function sameFileIdentity(left, right) {
  if (!left || !right || typeof left.dev !== 'bigint' || typeof right.dev !== 'bigint' ||
    typeof left.ino !== 'bigint' || typeof right.ino !== 'bigint' ||
    typeof left.mode !== 'bigint' || typeof right.mode !== 'bigint' ||
    typeof left.isFile !== 'function' || typeof right.isFile !== 'function' ||
    typeof left.isDirectory !== 'function' || typeof right.isDirectory !== 'function' ||
    typeof left.isSymbolicLink !== 'function' || typeof right.isSymbolicLink !== 'function') return false
  return left.dev === right.dev && left.ino === right.ino && left.mode === right.mode &&
    left.isFile() === right.isFile() && left.isDirectory() === right.isDirectory() &&
    left.isSymbolicLink() === right.isSymbolicLink()
}

function assertSameFileIdentity(left, right, label) {
  if (!sameFileIdentity(left, right)) fail(`${label} filesystem identity changed`)
}

function sameRealPath(left, right) {
  const normalize = (value) => {
    let plain = value
    if (/^\\\\\?\\UNC\\/i.test(plain)) plain = `\\\\${plain.slice(8)}`
    else plain = plain.replace(/^\\\\\?\\/, '')
    return path.normalize(plain).replace(/[\\/]+$/, '').toLowerCase()
  }
  return normalize(left) === normalize(right)
}

async function assertPathChain(absolute, { allowMissingLeaf = false } = {}) {
  const resolved = path.resolve(absolute)
  const relative = path.relative(root, resolved)
  if (!pathIsContained(root, resolved)) {
    fail(`Filesystem target is outside the owned workspace: ${resolved}`)
  }
  const rootInfo = await lstat(root, { bigint: true })
  fileIdentityRecord(rootInfo, root)
  if (!rootInfo.isDirectory() || isReparsePoint(rootInfo)) fail('Workspace root is not a plain directory')
  const rootReal = await realpath(root)
  if (!sameRealPath(rootReal, root)) fail('Workspace root resolves through a link or alias')
  let current = root
  for (const segment of relative.split(path.sep)) {
    current = path.join(current, segment)
    try {
      const info = await lstat(current, { bigint: true })
      fileIdentityRecord(info, current)
      assertPlainPathInfo(info, current)
      if (current !== resolved && !info.isDirectory()) fail(`Non-directory path ancestor: ${current}`)
    } catch (error) {
      if (error?.code === 'ENOENT' && allowMissingLeaf && current === resolved) return { exists: false, parent: path.dirname(current) }
      throw error
    }
  }
  const finalInfo = await lstat(resolved, { bigint: true })
  fileIdentityRecord(finalInfo, resolved)
  return { exists: true, info: finalInfo }
}

async function readBoundedLocal(absolute, limit, label, asText = false) {
  const beforePath = await assertPathChain(absolute)
  const beforeSize = assertBoundedRegularFile(beforePath.info, limit, label)
  const handle = await open(absolute, 'r')
  try {
    const opened = await handle.stat({ bigint: true })
    fileIdentityRecord(opened, label)
    if (!sameFileIdentity(beforePath.info, opened) || opened.nlink !== 1n ||
      boundedStatNumber(opened.size, limit, `${label} opened size`) !== beforeSize) {
      fail(`${label} changed between path inspection and open`)
    }
    const chunks = []
    let total = 0
    while (true) {
      const remaining = limit - total
      const buffer = Buffer.alloc(Math.min(64 * 1024, remaining + 1))
      const { bytesRead } = await handle.read(buffer, 0, buffer.length, null)
      if (bytesRead === 0) break
      total = appendBoundedChunk(chunks, total, buffer.subarray(0, bytesRead), limit, label)
    }
    const afterHandle = await handle.stat({ bigint: true })
    fileIdentityRecord(afterHandle, label)
    const afterPath = await assertPathChain(absolute)
    if (!sameFileIdentity(opened, afterHandle) || !sameFileIdentity(afterHandle, afterPath.info) ||
      afterHandle.nlink !== 1n || afterPath.info.nlink !== 1n ||
      boundedStatNumber(afterHandle.size, limit, `${label} final handle size`) !== total ||
      boundedStatNumber(afterPath.info.size, limit, `${label} final path size`) !== total || total !== beforeSize) {
      fail(`${label} changed while it was read`)
    }
    const bytes = Buffer.concat(chunks, total)
    if (!asText) return bytes
    try {
      return new TextDecoder('utf-8', { fatal: true }).decode(bytes)
    } catch {
      fail(`${label} is not strict UTF-8`)
    }
  } finally {
    await handle.close()
  }
}

async function assertAbsentAndSafe(absolute) {
  const result = await assertPathChain(absolute, { allowMissingLeaf: true })
  if (result.exists) fail(`Create-new target already exists and will not be adopted: ${absolute}`)
  const parent = await assertPathChain(result.parent)
  if (!parent.info.isDirectory() || isReparsePoint(parent.info)) fail(`Output parent is not a plain directory: ${result.parent}`)
  return parent.info
}

async function makeDirectoryNew(absolute) {
  const parentInfo = await assertAbsentAndSafe(absolute)
  await mkdir(absolute, { recursive: false })
  const created = await assertPathChain(absolute)
  const parentAfter = await assertPathChain(path.dirname(absolute))
  if (!created.info.isDirectory() || isReparsePoint(created.info)) {
    fail(`Directory identity changed during create-new: ${absolute}`)
  }
  assertSameFileIdentity(parentInfo, parentAfter.info, `Directory parent ${absolute}`)
  return fileIdentityRecord(created.info, absolute)
}

async function writeNewFile(absolute, bytes) {
  const parentInfo = await assertAbsentAndSafe(absolute)
  const handle = await open(absolute, 'wx')
  let openedInfo
  try {
    openedInfo = await handle.stat({ bigint: true })
    fileIdentityRecord(openedInfo, absolute)
    await handle.writeFile(bytes)
    await handle.sync()
    const writtenInfo = await handle.stat({ bigint: true })
    fileIdentityRecord(writtenInfo, absolute)
    if (!sameFileIdentity(openedInfo, writtenInfo) || writtenInfo.size !== BigInt(bytes.byteLength)) {
      fail(`File handle identity changed during create-new: ${absolute}`)
    }
  } finally {
    await handle.close()
  }
  const created = await assertPathChain(absolute)
  const parentAfter = await assertPathChain(path.dirname(absolute))
  if (!created.info.isFile() || isReparsePoint(created.info) || created.info.nlink !== 1n ||
    created.info.size !== BigInt(bytes.byteLength)) {
    fail(`File identity changed during create-new: ${absolute}`)
  }
  assertSameFileIdentity(openedInfo, created.info, `Created file ${absolute}`)
  assertSameFileIdentity(parentInfo, parentAfter.info, `Created file parent ${absolute}`)
  const reread = await readBoundedLocal(absolute, bytes.byteLength, `Create-new file verification ${absolute}`)
  if (hash(reread, 'sha256') !== hash(bytes, 'sha256')) fail(`Create-new file bytes changed after write: ${absolute}`)
  return fileIdentityRecord(created.info, absolute)
}

function fileIdentityRecord(info, label) {
  const canonical = (value, maximum, field) => {
    if (typeof value !== 'bigint' || value < 0n || value > maximum) {
      fail(`Filesystem ${field} identity is outside its exact bound: ${label}`)
    }
    const text = value.toString(10)
    if (!/^(?:0|[1-9]\d*)$/.test(text)) fail(`Filesystem ${field} identity is not canonical: ${label}`)
    return text
  }
  return {
    dev: canonical(info.dev, maxFilesystemDeviceOrInode, 'device'),
    ino: canonical(info.ino, maxFilesystemDeviceOrInode, 'inode'),
    mode: canonical(info.mode, maxFilesystemMode, 'mode')
  }
}

function maximumFileIdentityRecord() {
  return {
    dev: maxFilesystemDeviceOrInode.toString(10),
    ino: maxFilesystemDeviceOrInode.toString(10),
    mode: maxFilesystemMode.toString(10)
  }
}

function parseScalar(raw, label) {
  const value = raw.trim()
  if (!value) fail(`Empty YAML scalar: ${label}`)
  if (value.startsWith("'")) {
    if (!value.endsWith("'") || value.length < 2) fail(`Malformed single-quoted YAML scalar: ${label}`)
    return value.slice(1, -1).replaceAll("''", "'")
  }
  if (value.startsWith('"')) {
    try { return JSON.parse(value) } catch { fail(`Malformed double-quoted YAML scalar: ${label}`) }
  }
  if (/[#\[\]{}]/.test(value)) fail(`Unsupported plain YAML scalar syntax: ${label}`)
  return value
}

function splitYamlPair(text, label) {
  let quote = ''
  for (let index = 0; index < text.length; index++) {
    const char = text[index]
    if (quote === "'" && char === "'" && text[index + 1] === "'") { index++; continue }
    if (quote && char === quote) { quote = ''; continue }
    if (!quote && (char === "'" || char === '"')) { quote = char; continue }
    if (!quote && char === ':') {
      const key = parseScalar(text.slice(0, index), `${label} key`)
      const rawValue = text.slice(index + 1).trim()
      return { key, rawValue }
    }
  }
  fail(`Malformed YAML key/value: ${label}`)
}

function parseInlineMap(raw, label) {
  if (!raw.startsWith('{') || !raw.endsWith('}')) fail(`Malformed inline YAML mapping: ${label}`)
  const content = raw.slice(1, -1)
  const fields = []
  let quote = ''
  let start = 0
  for (let index = 0; index < content.length; index++) {
    const char = content[index]
    if (quote === "'" && char === "'" && content[index + 1] === "'") { index++; continue }
    if (quote && char === quote) { quote = ''; continue }
    if (!quote && (char === "'" || char === '"')) { quote = char; continue }
    if (!quote && char === ',') { fields.push(content.slice(start, index)); start = index + 1 }
  }
  if (quote) fail(`Unterminated quoted inline YAML value: ${label}`)
  if (content.trim()) fields.push(content.slice(start))
  const result = new Map()
  for (const field of fields) {
    const pair = splitYamlPair(field.trim(), label)
    if (result.has(pair.key)) fail(`Duplicate inline YAML key ${pair.key}: ${label}`)
    result.set(pair.key, parseScalar(pair.rawValue, `${label}/${pair.key}`))
  }
  return result
}

function parseLock(lockText) {
  if (typeof lockText !== 'string' || !lockText.startsWith("lockfileVersion: '9.0'")) fail('Unsupported pnpm lockfile format')
  const importers = new Map()
  const snapshots = new Map()
  const packages = new Map()
  let section = ''
  let current = ''
  let subsection = ''
  let dependency = ''
  let lastCompletedDependency = ''
  let dependencyFields = null

  for (const [lineIndex, line] of lockText.split(/\r?\n/).entries()) {
    if (!line.trim() || /^\s*#/.test(line)) continue
    const rootSection = line.match(/^(importers|packages|snapshots):$/)
    if (rootSection) {
      if (dependency) fail(`Importer dependency lacks a resolved version: ${current}/${dependency}`)
      section = rootSection[1]
      current = ''
      subsection = ''
      dependency = ''
      lastCompletedDependency = ''
      dependencyFields = null
      continue
    }
    if (!section) continue
    const indent = line.match(/^ */)[0].length
    if (line[indent] === '\t') fail(`Tab indentation is unsupported at lock line ${lineIndex + 1}`)
    const content = line.slice(indent)

    if (section === 'importers' && indent === 2) {
      if (dependency) fail(`Importer dependency lacks a resolved version: ${current}/${dependency}`)
      const pair = splitYamlPair(content, `lock line ${lineIndex + 1}`)
      current = pair.key
      if (importers.has(current)) fail(`Duplicate importer: ${current}`)
      importers.set(current, new Map())
      subsection = ''
      dependency = ''
      dependencyFields = null
      if (pair.rawValue && pair.rawValue !== '{}') fail(`Unsupported inline importer: ${current}`)
      continue
    }
    if (section === 'importers' && indent === 4) {
      if (dependency) fail(`Importer dependency lacks a resolved version: ${current}/${dependency}`)
      const pair = splitYamlPair(content, `lock line ${lineIndex + 1}`)
      subsection = pair.key
      if (!['dependencies', 'devDependencies', 'optionalDependencies'].includes(subsection)) subsection = ''
      dependency = ''
      lastCompletedDependency = ''
      continue
    }
    if (section === 'importers' && indent === 6 && subsection) {
      if (dependency) fail(`Importer dependency lacks a resolved version: ${current}/${dependency}`)
      const pair = splitYamlPair(content, `lock line ${lineIndex + 1}`)
      dependency = pair.key
      lastCompletedDependency = ''
      dependencyFields = new Map()
      const rawReference = pair.rawValue
      if (rawReference) {
        const reference = parseScalar(rawReference, `${current}/${dependency}`)
        if (importers.get(current).has(dependency)) fail(`Duplicate importer dependency: ${current}/${dependency}`)
        importers.get(current).set(dependency, reference)
        dependency = ''
      }
      continue
    }
    if (section === 'importers' && indent === 8 && dependency) {
      const pair = splitYamlPair(content, `lock line ${lineIndex + 1}`)
      if (dependencyFields.has(pair.key)) fail(`Duplicate importer dependency field: ${current}/${dependency}/${pair.key}`)
      dependencyFields.set(pair.key, pair.key === 'version'
        ? parseScalar(pair.rawValue, `${current}/${dependency}/${pair.key}`)
        : pair.rawValue)
      if (pair.key === 'version') {
        if (importers.get(current).has(dependency)) fail(`Duplicate importer dependency: ${current}/${dependency}`)
        importers.get(current).set(dependency, dependencyFields.get('version'))
        lastCompletedDependency = dependency
        dependency = ''
      }
      continue
    }
    if (section === 'importers' && indent === 8 && !dependency && subsection && lastCompletedDependency) {
      const pair = splitYamlPair(content, `lock line ${lineIndex + 1}`)
      if (pair.key === 'version') fail(`Duplicate importer resolved version: ${current}/${lastCompletedDependency}`)
      fail(`Unexpected importer field after resolved version: ${current}/${lastCompletedDependency}/${pair.key}`)
    }
    if (section === 'snapshots' && indent === 2) {
      const pair = splitYamlPair(content, `lock line ${lineIndex + 1}`)
      current = pair.key
      if (snapshots.has(current)) fail(`Duplicate snapshot locator: ${current}`)
      snapshots.set(current, new Map())
      subsection = ''
      if (pair.rawValue && pair.rawValue !== '{}') fail(`Unsupported inline snapshot: ${current}`)
      continue
    }
    if (section === 'snapshots' && indent === 4) {
      const pair = splitYamlPair(content, `lock line ${lineIndex + 1}`)
      subsection = ['dependencies', 'optionalDependencies'].includes(pair.key) ? pair.key : ''
      continue
    }
    if (section === 'snapshots' && indent === 6 && subsection) {
      const pair = splitYamlPair(content, `lock line ${lineIndex + 1}`)
      if (snapshots.get(current).has(pair.key)) fail(`Duplicate dependency edge: ${current} -> ${pair.key}`)
      snapshots.get(current).set(pair.key, parseScalar(pair.rawValue, `${current}/${pair.key}`))
      continue
    }
    if (section === 'packages' && indent === 2) {
      const pair = splitYamlPair(content, `lock line ${lineIndex + 1}`)
      current = pair.key
      if (packages.has(current)) fail(`Duplicate package locator: ${current}`)
      packages.set(current, { integrity: '', fields: new Map() })
      if (pair.rawValue && pair.rawValue !== '{}') fail(`Unsupported inline package record: ${current}`)
      continue
    }
    if (section === 'packages' && indent === 4) {
      const pair = splitYamlPair(content, `lock line ${lineIndex + 1}`)
      if (pair.key === 'resolution') {
        if (packages.get(current).fields.has(pair.key)) fail(`Duplicate package resolution record: ${current}`)
        const fields = parseInlineMap(pair.rawValue, `${current} resolution`)
        packages.get(current).integrity = fields.get('integrity') || ''
        packages.get(current).fields.set(pair.key, fields)
      }
    }
  }
  if (dependency) fail(`Importer dependency lacks a resolved version: ${current}/${dependency}`)
  if (!importers.has('.') || !snapshots.size || !packages.size) fail('Lockfile is missing required importer/package/snapshot sections')
  return { importers, snapshots, packages }
}

function peerContextGroups(locator) {
  const start = locator.indexOf('(')
  if (start < 0) return []
  if (start === 0) fail(`Malformed package locator peer suffix: ${locator}`)
  const groups = []
  let cursor = start
  while (cursor < locator.length) {
    if (locator[cursor] !== '(') fail(`Unexpected text in nested peer suffix: ${locator}`)
    const groupStart = cursor + 1
    let depth = 1
    cursor++
    for (; cursor < locator.length; cursor++) {
      if (locator[cursor] === '(') depth++
      else if (locator[cursor] === ')') depth--
      if (depth === 0) break
    }
    if (depth !== 0) fail(`Unclosed nested peer suffix: ${locator}`)
    const group = locator.slice(groupStart, cursor)
    if (!group) fail(`Empty nested peer suffix: ${locator}`)
    // Validate nested groups before allowing the outer locator to be resolved.
    peerContextGroups(group)
    groups.push(group)
    cursor++
  }
  return groups
}

function stripPeerSuffix(locator) {
  const start = locator.indexOf('(')
  if (start < 0) {
    if (locator.includes(')')) fail(`Unmatched closing peer suffix: ${locator}`)
    return locator
  }
  peerContextGroups(locator)
  return locator.slice(0, start)
}

function validatePeerContextSyntax(locator) {
  for (const context of peerContextGroups(locator)) {
    const { name, reference } = locatorParts(stripPeerSuffix(context))
    if (!name || !reference) fail(`Malformed package identity in peer context: ${context}`)
    validatePeerContextSyntax(context)
  }
}

function locatorParts(locator) {
  const delimiter = locator.startsWith('@')
    ? locator.indexOf('@', locator.indexOf('/') + 1)
    : locator.indexOf('@')
  if (delimiter <= 0) fail(`Malformed pnpm package locator: ${locator}`)
  return { name: locator.slice(0, delimiter), reference: locator.slice(delimiter + 1) }
}

function npmAliasTarget(reference) {
  const bareReference = stripPeerSuffix(reference)
  if (!bareReference.startsWith('npm:')) return null
  const target = bareReference.slice(4)
  const delimiter = target.lastIndexOf('@')
  if (delimiter <= 0 || delimiter === target.length - 1) fail(`Malformed npm alias reference: ${reference}`)
  return `${target.slice(0, delimiter)}@${target.slice(delimiter + 1)}${reference.slice(bareReference.length)}`
}

function resolveSnapshot(snapshots, packageName, reference) {
  const exact = `${packageName}@${reference}`
  if (snapshots.has(exact)) return exact
  if (snapshots.has(reference)) return reference
  const aliasTarget = npmAliasTarget(reference)
  if (aliasTarget && snapshots.has(aliasTarget)) return aliasTarget
  const base = stripPeerSuffix(exact)
  const candidateBases = new Set([base])
  if (aliasTarget) candidateBases.add(stripPeerSuffix(aliasTarget))
  const matches = [...snapshots.keys()].filter((locator) => candidateBases.has(stripPeerSuffix(locator)))
  if (matches.length === 1) return matches[0]
  if (matches.length > 1) fail(`Ambiguous peer-context snapshot for ${packageName}@${reference}`)
  return null
}

function workspaceImporterFor(importer, reference) {
  const target = reference.slice('link:'.length).replaceAll('\\', '/')
  if (!target || target.startsWith('/')) fail(`Unsafe workspace link reference: ${reference}`)
  const resolved = path.posix.normalize(path.posix.join(importer, target))
  if (resolved === '..' || resolved.startsWith('../') || path.posix.isAbsolute(resolved)) fail(`Workspace link escapes importer tree: ${reference}`)
  return resolved === '.' ? '.' : resolved
}

function packageResolutionFor(snapshot, packages) {
  const base = stripPeerSuffix(snapshot)
  if (packages.has(snapshot) && packages.get(snapshot).integrity) return snapshot
  if (packages.has(base) && packages.get(base).integrity) return base
  const { reference } = locatorParts(base)
  const aliasTarget = npmAliasTarget(reference)
  const candidateBases = new Set([base])
  if (aliasTarget) candidateBases.add(stripPeerSuffix(aliasTarget))
  const matches = [...packages.keys()].filter((locator) => candidateBases.has(stripPeerSuffix(locator)) && packages.get(locator).integrity)
  if (matches.length === 1) return matches[0]
  if (matches.length > 1) fail(`Ambiguous package resolution for snapshot ${snapshot}`)
  return null
}

function artifactIdentity(locator) {
  const { name, reference } = locatorParts(stripPeerSuffix(locator))
  if (reference.startsWith('npm:')) {
    const target = reference.slice(4)
    const separator = target.lastIndexOf('@')
    if (separator <= 0 || separator === target.length - 1) fail(`Malformed npm alias artifact locator: ${locator}`)
    return { name: target.slice(0, separator), version: target.slice(separator + 1) }
  }
  return { name, version: reference }
}

function collectClosure(lockText) {
  const { importers, snapshots, packages } = parseLock(lockText)
  const queue = [{ type: 'importer', key: '.' }]
  const visitedSnapshots = new Set()
  const visitedImporters = new Set()
  const reachable = new Map()
  const snapshotResolutions = new Map()
  while (queue.length) {
    const entry = queue.pop()
    if (entry.type === 'importer') {
      const importer = entry.key
      if (visitedImporters.has(importer)) continue
      visitedImporters.add(importer)
      const dependencies = importers.get(importer)
      if (!dependencies) fail(`Workspace importer is missing from lock: ${importer}`)
      for (const [name, reference] of dependencies) {
        if (reference.startsWith('link:')) {
          queue.push({ type: 'importer', key: workspaceImporterFor(importer, reference) })
        } else {
          queue.push({ type: 'edge', name, reference })
        }
      }
      continue
    }
    if (entry.type === 'edge') {
      const { name, reference } = entry
      if (reference.startsWith('link:')) {
        if (!entry.importer || !entry.importer.startsWith('packages/')) {
          fail(`Linked workspace edge lacks a workspace importer context: ${name}@${reference}`)
        }
        queue.push({ type: 'importer', key: workspaceImporterFor(entry.importer, reference) })
        continue
      }
      const snapshot = resolveSnapshot(snapshots, name, reference)
      if (!snapshot) fail(`No lock snapshot for ${name}@${reference}`)
      if (visitedSnapshots.has(snapshot)) continue
      visitedSnapshots.add(snapshot)
      const resolution = packageResolutionFor(snapshot, packages)
      if (!resolution) fail(`No exact registry package resolution for ${snapshot}`)
      const integrity = packages.get(resolution).integrity
      if (!/^sha512-[A-Za-z0-9+/]{86}==$/.test(integrity)) fail(`Unsupported/missing lock SHA512 SRI for ${resolution}`)
      snapshotResolutions.set(snapshot, resolution)
      if (!reachable.has(resolution)) reachable.set(resolution, { locator: resolution, integrity })
      validatePeerContextSyntax(snapshot)
      for (const [depName, depReference] of snapshots.get(snapshot)) {
        queue.push({ type: 'edge', name: depName, reference: depReference, importer: snapshot.startsWith('packages/') ? snapshot : '' })
      }
    }
  }
  const artifacts = [...reachable.values()].sort((a, b) => a.locator < b.locator ? -1 : a.locator > b.locator ? 1 : 0)
  if (artifacts.length + 1 > artifactLimit) fail(`Reachable lock closure exceeds artifact cap: ${artifacts.length + 1}`)
  const names = new Set()
  for (const artifact of artifacts) {
    const identity = artifactIdentity(artifact.locator)
    artifact.name = identity.name
    artifact.version = identity.version
    if (!artifact.name || !artifact.version || artifact.version.includes('/') || artifact.version.includes('\\')) fail(`Ambiguous package locator: ${artifact.locator}`)
    if (names.has(artifact.locator)) fail(`Duplicate reachable package resolution: ${artifact.locator}`)
    names.add(artifact.locator)
  }
  const uniqueRegistryResolutions = new Set(snapshotResolutions.values())
  if (snapshotResolutions.size !== visitedSnapshots.size || uniqueRegistryResolutions.size !== reachable.size) {
    fail('Reachable snapshot-to-registry resolution reconciliation is incomplete')
  }
  const sortedSnapshotResolutions = [...snapshotResolutions.entries()]
    .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
    .map(([snapshot, registryLocator]) => ({ snapshot, registryLocator }))
  const sortedImporters = [...visitedImporters].sort((left, right) => left < right ? -1 : left > right ? 1 : 0)
  return {
    artifacts,
    reconciliation: {
      reachableSnapshots: visitedSnapshots.size,
      workspaceImporters: visitedImporters.size,
      reachableImporterPaths: sortedImporters,
      registryArtifacts: artifacts.length,
      uniqueSnapshotRegistryResolutions: uniqueRegistryResolutions.size,
      snapshotResolutions: sortedSnapshotResolutions,
      lockPackageRecords: packages.size
    },
    snapshots: [...visitedSnapshots].sort((left, right) => left < right ? -1 : left > right ? 1 : 0)
  }
}

function metadataUrl(name, version) {
  const encodedName = encodeURIComponent(name).replace(/%40/gi, '@')
  return new URL(`/${encodedName}/${encodeURIComponent(version)}`, registryOrigin)
}

async function readBounded(response, limit, label) {
  if (!response.ok || !response.body) fail(`${label} failed with HTTP ${response.status}`)
  if (response.url && new URL(response.url).origin !== registryOrigin) fail(`${label} escaped the pinned registry host`)
  const length = Number(response.headers.get('content-length') || 0)
  if (length > limit) fail(`${label} exceeded its declared byte bound`)
  const reader = response.body.getReader()
  const chunks = []
  let bytes = 0
  while (true) {
    const { done, value } = await reader.read()
    if (done) break
    try {
      bytes = appendBoundedChunk(chunks, bytes, value, limit, label)
    } catch (error) {
      await reader.cancel()
      throw error
    }
  }
  return Buffer.concat(chunks, bytes)
}

async function registryGet(url, byteLimit, label) {
  if (url.origin !== registryOrigin || url.protocol !== 'https:' || url.username || url.password) {
    fail(`Non-allowlisted registry request: ${url.href}`)
  }
  const response = await fetch(url, {
    method: 'GET',
    redirect: 'manual',
    credentials: 'omit',
    cache: 'no-store',
    signal: AbortSignal.timeout(requestTimeoutMs),
    headers: { accept: 'application/json, application/octet-stream;q=0.9' }
  })
  if (response.status >= 300 && response.status < 400) fail(`${label} attempted a redirect`)
  return readBounded(response, byteLimit, label)
}

function archiveFilename(index, extension = '.tgz') {
  if (!Number.isSafeInteger(index) || index < 0 || index >= artifactLimit) fail(`Invalid deterministic artifact index: ${index}`)
  return `artifact-${String(index).padStart(4, '0')}${extension}`
}

function packageDirectoryName(index) {
  if (!Number.isSafeInteger(index) || index < 0 || index >= artifactLimit) fail(`Invalid package directory index: ${index}`)
  return `package-${String(index).padStart(4, '0')}`
}

function assertInjectiveMappings(artifacts) {
  const archiveNames = new Set()
  const metadataNames = new Set()
  const directoryNames = new Set()
  const locatorNames = new Set()
  for (let index = 0; index < artifacts.length; index++) {
    const locator = artifacts[index].locator
    if (typeof locator !== 'string' || !locator) fail('Artifact locator is missing before path mapping')
    const normalizedLocator = locator.normalize('NFKC').toLowerCase()
    if (locatorNames.has(normalizedLocator)) fail(`Duplicate or Windows-equivalent artifact locator: ${locator}`)
    locatorNames.add(normalizedLocator)
    const archiveName = archiveFilename(index).normalize('NFC').toLowerCase()
    const metadataName = archiveFilename(index, '.json').normalize('NFC').toLowerCase()
    const directoryName = packageDirectoryName(index).normalize('NFC').toLowerCase()
    for (const [set, value] of [[archiveNames, archiveName], [metadataNames, metadataName], [directoryNames, directoryName]]) {
      if (set.has(value) || /[<>:"|?*\u0000-\u001f]/.test(value) || /[. ]$/.test(value) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(value)) {
        fail(`Windows-unsafe or colliding generated name: ${value}`)
      }
      set.add(value)
    }
  }
}

async function preparePrefix() {
  const base = safePath(prefix)
  await makeDirectoryNew(base)
  await makeDirectoryNew(path.join(base, 'metadata'))
  await makeDirectoryNew(path.join(base, 'npm'))
  return base
}

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value, null, 2)}\n`, 'utf8')
}

function boundedJsonBytes(value, limit, label) {
  const bytes = jsonBytes(value)
  if (bytes.byteLength > limit) fail(`${label} exceeds its ${limit}-byte output limit`)
  return bytes
}

function compactJsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`, 'utf8')
}

function boundedCompactJsonBytes(value, limit, label) {
  const bytes = compactJsonBytes(value)
  if (bytes.byteLength > limit) fail(`${label} exceeds its ${limit}-byte output limit`)
  return bytes
}

function inspectionCaps(overrides = {}) {
  const caps = {
    perLicenseTextBytes: licenseTextByteLimit,
    aggregateLicenseTextBytes: aggregateLicenseTextByteLimit,
    reportBytes: licenseInspectionReportByteLimit
  }
  const maximums = {
    perLicenseTextBytes: licenseTextByteLimit,
    aggregateLicenseTextBytes: aggregateLicenseTextByteLimit,
    reportBytes: licenseInspectionReportByteLimit
  }
  const keys = Object.keys(caps)
  if (Object.keys(overrides).some((key) => !keys.includes(key))) fail('Unknown internal license-inspection cap override')
  for (const key of keys) {
    if (overrides[key] !== undefined) caps[key] = overrides[key]
    if (!Number.isSafeInteger(caps[key]) || caps[key] < 1 || caps[key] > maximums[key]) fail(`Invalid internal license-inspection cap: ${key}`)
  }
  return caps
}

function assertInspectionReportByteLimit(byteLength, cap) {
  if (!Number.isSafeInteger(byteLength) || byteLength < 0 || !Number.isSafeInteger(cap) || cap < 1 || byteLength > cap) {
    fail(`License inspection report exceeds its ${cap}-byte output limit`)
  }
}

function assertCompleteInspectionPackageInventory(parsedArchive, archiveMembers, files, ordinal, expectedIdentity) {
  if (!Array.isArray(parsedArchive?.entries) || !Array.isArray(parsedArchive?.archiveMembers) ||
    !Array.isArray(archiveMembers) || !Array.isArray(files) ||
    !Number.isSafeInteger(parsedArchive.archiveExpandedBytes) || parsedArchive.archiveExpandedBytes < 1 ||
    parsedArchive.archiveExpandedBytes > perArchiveExpandedByteLimit) {
    fail('Inspection preflight omitted archive entries, complete members, or output inventory')
  }
  if (JSON.stringify(archiveMembers) !== JSON.stringify(parsedArchive.archiveMembers)) {
    fail('Inspection preflight archive-member inventory is incomplete or changed')
  }
  if (parsedArchive.archiveMembersSha256 !== archiveMemberInventorySha256(parsedArchive.archiveMembers)) {
    fail('Inspection preflight archive-member provenance digest is missing or changed')
  }
  if (parsedArchive.headerLayoutSha256 !== headerLayoutInventorySha256(parsedArchive.archiveMembers)) {
    fail('Inspection preflight header-layout inventory is incomplete or changed')
  }
  if (JSON.stringify(parsedArchive.expectedIdentity) !== JSON.stringify(expectedIdentity ?? null)) {
    fail('Inspection preflight archive root is not bound to the authenticated package identity')
  }
  assertPackageArchiveRootProvenance(expectedIdentity, parsedArchive.archiveRoot, parsedArchive.archiveMembers)
  const outputMembers = parsedArchive.archiveMembers.filter((member) => member.type === 'file' || member.type === 'directory')
  if (outputMembers.length !== parsedArchive.entries.length) fail('Inspection preflight member-to-entry count differs')
  for (const entry of parsedArchive.entries) {
    const member = parsedArchive.archiveMembers[entry.archiveMemberIndex]
    if (!member || member.index !== entry.archiveMemberIndex || member.path !== entry.path || member.canonicalPath !== entry.path ||
      member.rawPath !== entry.rawPath || member.headerPath !== entry.headerPath || member.headerPrefix !== entry.headerPrefix ||
      JSON.stringify(member.headerLayout) !== JSON.stringify(entry.headerLayout) ||
      member.headerBytesHex !== entry.headerBytesHex ||
      member.headerName !== entry.headerName || member.paxPath !== entry.paxPath || member.type !== entry.type ||
      member.gnuLongNameMetadataIndex !== entry.gnuLongNameMetadataIndex || member.gnuLongNamePath !== entry.gnuLongNamePath ||
      member.archiveRoot !== entry.archiveRoot ||
      (entry.type === 'file' && (member.outputPath !== entry.path ||
        member.outputPrimaryArchiveMemberIndex !== entry.primaryArchiveMemberIndex ||
        JSON.stringify(member.outputArchiveMemberIndices) !== JSON.stringify(entry.archiveMemberIndices))) ||
      member.payloadBytes !== entry.bytes || (entry.type === 'file' && member.payloadSha256 !== hash(entry.data, 'sha256'))) {
      fail(`Inspection preflight archive entry is missing from full member inventory: ${entry.path}`)
    }
  }
  const completeOutput = planPackageOutputInventory(ordinal, parsedArchive.entries, expectedIdentity)
  if (JSON.stringify(files) !== JSON.stringify(completeOutput)) {
    fail('Inspection preflight prospective-output inventory is incomplete or changed')
  }
  return { archiveMemberCount: parsedArchive.archiveMembers.length, outputInventory: completeOutput }
}

function assembleInspectionPackage({ ordinal, artifact, expectedIdentity, archiveByteLimit, packageJson, licenseAssessment, parsedArchive,
  outputInventory = planPackageOutputInventory(ordinal, parsedArchive.entries, expectedIdentity) }) {
  assertCheckedPackageIdentity(ordinal, artifact, expectedIdentity, packageJson, `Inspection package at ordinal ${ordinal}`)
  if (!Number.isSafeInteger(ordinal) || ordinal < 0 || !artifact?.locator || !packageJson?.name || !packageJson?.version ||
    !Number.isSafeInteger(archiveByteLimit) || archiveByteLimit < 1 ||
    !Number.isSafeInteger(parsedArchive?.archiveExpandedBytes) || parsedArchive.archiveExpandedBytes < 1 ||
    parsedArchive.archiveExpandedBytes > perArchiveExpandedByteLimit || !Array.isArray(licenseAssessment?.texts) ||
    !Array.isArray(licenseAssessment?.issues)) fail('Inspection package preflight record is incomplete')
  const inventory = assertCompleteInspectionPackageInventory(parsedArchive, parsedArchive.archiveMembers, outputInventory, ordinal,
    expectedIdentity)
  const textAssessment = inspectLicenseText(parsedArchive.entries)
  if (JSON.stringify(textAssessment.texts) !== JSON.stringify(licenseAssessment.texts) ||
    JSON.stringify(textAssessment.issues) !== JSON.stringify(licenseAssessment.issues.filter((issue) =>
      ['missing-license-notice-text', 'invalid-utf8-license-notice', 'empty-license-notice-text'].includes(issue.code)))) {
    fail('Inspection package license-text evidence differs from the complete parsed archive')
  }
  return {
    ordinal,
    artifact,
    expectedIdentity,
    archiveByteLimit,
    archiveExpandedBytes: parsedArchive.archiveExpandedBytes,
    archiveRoot: parsedArchive.archiveRoot,
    headerLayoutSha256: parsedArchive.headerLayoutSha256,
    archiveMembersSha256: parsedArchive.archiveMembersSha256,
    packageJson: { name: packageJson.name, version: packageJson.version, license: licenseAssessment.declaration.text },
    licenseAssessment,
    archiveMembers: parsedArchive.archiveMembers,
    files: inventory.outputInventory
  }
}

function buildLicenseInspectionReport(preflight, acquisition, sourceManifestSha256, archiveMemberCount,
  aggregateArchiveExpandedBytes, expandedTotal, createdDirectoryCount, caps) {
  return {
    schema: 'comfy-canvas-license-inspection/v7',
    sourceManifestSha256,
    acquisitionManifest: `${prefix}/manifest.json`,
    lockSha256,
    packageManager: acquisition.packageManager,
    packageManagerPin: acquisition.packageManagerPin,
    closureReconciliation: acquisition.reconciliation,
    reportPath: licenseInspectionReportRelative,
    platform: 'win32-x64',
    archiveLimitPolicy: archiveLimitPolicy(),
    inspectionLimits: {
      perLicenseTextBytes: caps.perLicenseTextBytes,
      aggregateLicenseTextBytes: caps.aggregateLicenseTextBytes,
      reportBytes: caps.reportBytes,
      perArchiveExpandedByteLimit,
      aggregateArchiveExpandedByteLimit,
      aggregateExpandedByteLimit,
      expandedEntryCountLimit
    },
    archiveMemberCount,
    aggregateArchiveExpandedBytes,
    createdDirectoryCount,
    aggregateExpandedBytes: expandedTotal,
    packages: preflight.map((checked) => ({
      ordinal: checked.ordinal,
      locator: checked.artifact.locator,
      name: checked.expectedIdentity.name,
      version: checked.expectedIdentity.version,
      archiveRoot: checked.archiveRoot,
      headerLayoutSha256: checked.headerLayoutSha256,
      archive: checked.artifact.archive,
      archiveByteLimit: checked.archiveByteLimit,
      archiveExpandedBytes: checked.archiveExpandedBytes,
      archiveBytes: checked.artifact.bytes,
      archiveSha256: checked.artifact.sha256,
      lockIntegrity: checked.artifact.lockIntegrity,
      registryIntegrity: checked.artifact.registryIntegrity,
      registryTarball: checked.artifact.registryTarball,
      metadata: checked.artifact.metadata,
      metadataBytes: checked.artifact.metadataBytes,
      metadataSha256: checked.artifact.metadataSha256,
      packageJsonPath: 'package/package.json',
      declaredLicense: checked.licenseAssessment.declaration,
      licenseTexts: checked.licenseAssessment.texts,
      unresolvedIssues: checked.licenseAssessment.issues,
      archiveMembers: checked.archiveMembers,
      prospectiveOutputInventory: checked.files
    }))
  }
}

function assembleCompleteLicenseInspectionReport(preflight, acquisition, sourceManifestSha256,
  archiveMemberCount, aggregateArchiveExpandedBytes, expandedTotal, createdDirectoryCount, capOverrides = {}, trustedExpectedIdentities) {
  const caps = inspectionCaps(capOverrides)
  if (!Array.isArray(preflight) || preflight.length < 1 || preflight.length > artifactLimit ||
    !Array.isArray(trustedExpectedIdentities) || trustedExpectedIdentities.length !== preflight.length ||
    !/^[0-9a-f]{64}$/.test(sourceManifestSha256)) fail('Complete inspection preflight is absent or malformed')
  let measuredMembers = 0
  let measuredArchiveExpandedBytes = 0
  let measuredExpandedBytes = 0
  let measuredDirectories = 1
  let measuredLicenseTextBytes = 0
  const outputPaths = new Set()
  for (let index = 0; index < preflight.length; index++) {
    const checked = preflight[index]
    const expectedIdentity = trustedExpectedIdentities[index]
    if (JSON.stringify(expectedIdentity) !== JSON.stringify(checked.expectedIdentity)) {
      fail(`Complete inspection lock identity differs from authenticated closure at ordinal ${index}`)
    }
    assertCheckedPackageIdentity(index, checked.artifact, expectedIdentity,
      checked.packageJson, `Complete inspection package at ordinal ${index}`)
    if (checked.ordinal !== index || !checked.artifact?.locator || !checked.packageJson?.name || !checked.packageJson?.version ||
      !Array.isArray(checked.archiveMembers) || checked.archiveMembers.length < 1 || !Array.isArray(checked.files) ||
      !Number.isSafeInteger(checked.archiveExpandedBytes) || checked.archiveExpandedBytes < 1 ||
      checked.archiveExpandedBytes > perArchiveExpandedByteLimit ||
      !Array.isArray(checked.licenseAssessment?.texts) || !Array.isArray(checked.licenseAssessment?.issues)) {
      fail(`Complete inspection package record is missing or out of ordinal order at ${index}`)
    }
    assertPackageAliasProvenance(index, checked.archiveMembers, checked.files, expectedIdentity, checked.archiveRoot)
    if (checked.headerLayoutSha256 !== headerLayoutInventorySha256(checked.archiveMembers) ||
      checked.archiveMembersSha256 !== archiveMemberInventorySha256(checked.archiveMembers)) {
      fail(`Complete inspection header-layout inventory changed at ordinal ${index}`)
    }
    measuredMembers = addSafeInventoryTotal(measuredMembers, checked.archiveMembers.length,
      expandedEntryCountLimit, 'Inspection archive-member total')
    measuredArchiveExpandedBytes = addSafeInventoryTotal(measuredArchiveExpandedBytes, checked.archiveExpandedBytes,
      aggregateArchiveExpandedByteLimit, 'Inspection archive-expanded total')
    for (const record of checked.files) {
      if (!record?.path || outputPaths.has(record.path)) fail(`Complete inspection output path is missing or duplicated: ${record?.path}`)
      outputPaths.add(record.path)
      if (record.type === 'directory') {
        measuredDirectories = addSafeInventoryTotal(measuredDirectories, 1, expandedEntryCountLimit,
          'Inspection created-directory total')
      } else if (record.type === 'file' && Number.isSafeInteger(record.bytes) && record.bytes >= 0) {
        measuredExpandedBytes = addSafeInventoryTotal(measuredExpandedBytes, record.bytes,
          aggregateExpandedByteLimit, 'Inspection output-byte total')
      } else fail(`Complete inspection output record has an invalid type or byte count: ${record.path}`)
    }
    const licenseMemberIndices = new Set()
    const expectedLicenseMemberIndices = checked.archiveMembers
      .filter((member) => member?.type === 'file' && isLicenseOrNoticePath(member.canonicalPath))
      .map((member) => member.index)
    for (const evidence of checked.licenseAssessment.texts) {
      const member = Number.isSafeInteger(evidence?.archiveMemberIndex)
        ? checked.archiveMembers[evidence.archiveMemberIndex] : null
      if (!evidence?.path || !Number.isSafeInteger(evidence.bytes) || evidence.bytes < 0 ||
        evidence.bytes > caps.perLicenseTextBytes || !/^[0-9a-f]{64}$/.test(evidence.sha256) ||
        !member || member.index !== evidence.archiveMemberIndex || member.type !== 'file' ||
        member.canonicalPath !== evidence.path || member.payloadBytes !== evidence.bytes ||
        member.payloadSha256 !== evidence.sha256 || licenseMemberIndices.has(evidence.archiveMemberIndex) ||
        !isLicenseOrNoticePath(evidence.path) ||
        (evidence.utf8 !== null && (typeof evidence.utf8 !== 'string' || Buffer.byteLength(evidence.utf8, 'utf8') !== evidence.bytes))) {
        fail(`Inspection license evidence exceeds or violates its finite schema: ${evidence?.path}`)
      }
      licenseMemberIndices.add(evidence.archiveMemberIndex)
      measuredLicenseTextBytes += evidence.bytes
      if (!Number.isSafeInteger(measuredLicenseTextBytes) || measuredLicenseTextBytes > caps.aggregateLicenseTextBytes) {
        fail('Aggregate license/notice text inspection bound exceeded')
      }
    }
    if (licenseMemberIndices.size !== expectedLicenseMemberIndices.length ||
      expectedLicenseMemberIndices.some((index) => !licenseMemberIndices.has(index))) {
      fail(`Inspection license evidence omits or adds an archive member at ordinal ${index}`)
    }
  }
  const measuredCombinedEntryCount = addSafeInventoryTotal(measuredMembers, measuredDirectories,
    expandedEntryCountLimit, 'Inspection combined member/directory total')
  if (measuredMembers !== archiveMemberCount || measuredArchiveExpandedBytes !== aggregateArchiveExpandedBytes ||
    measuredExpandedBytes !== expandedTotal || measuredDirectories !== createdDirectoryCount ||
    measuredCombinedEntryCount > expandedEntryCountLimit || outputPaths.size > expandedEntryCountLimit ||
    measuredExpandedBytes > aggregateExpandedByteLimit) {
    fail('Complete inspection preflight counters differ from full member/output inventory')
  }
  const report = buildLicenseInspectionReport(preflight, acquisition, sourceManifestSha256,
    archiveMemberCount, measuredArchiveExpandedBytes, expandedTotal, createdDirectoryCount, caps)
  const bytes = compactJsonBytes(report)
  assertInspectionReportByteLimit(bytes.byteLength, caps.reportBytes)
  return { report, bytes, caps }
}

function assertInspectionRecheckFacts(manifestBytes, finalManifestBytes, preflight, observations, trustedExpectedIdentities) {
  if (!Buffer.isBuffer(manifestBytes) || !Buffer.isBuffer(finalManifestBytes) || !finalManifestBytes.equals(manifestBytes)) {
    fail('Acquisition manifest changed between inspection preflight and report creation')
  }
  if (!Array.isArray(observations) || observations.length !== preflight.length ||
    !Array.isArray(trustedExpectedIdentities) || trustedExpectedIdentities.length !== preflight.length) {
    fail('Inspection archive/metadata recheck count differs from complete preflight')
  }
  for (let index = 0; index < preflight.length; index++) {
    const expected = preflight[index]
    const actual = observations[index]
    const expectedIdentity = trustedExpectedIdentities[index]
    if (JSON.stringify(expectedIdentity) !== JSON.stringify(expected.expectedIdentity)) {
      fail(`Inspection archive/metadata recheck differs from complete preflight at ordinal ${index}`)
    }
    assertCheckedPackageIdentity(index, expected.artifact, expectedIdentity,
      expected.packageJson, `Inspection recheck at ordinal ${index}`)
    assertPackageAliasProvenance(index, expected.archiveMembers, expected.files, expectedIdentity, expected.archiveRoot)
    if (actual?.ordinal !== index || actual?.locator !== expected.artifact.locator ||
      actual.archiveBytes !== expected.artifact.bytes || actual.archiveSha256 !== expected.artifact.sha256 ||
      actual.archiveByteLimit !== expected.archiveByteLimit || actual.lockIntegrity !== expected.artifact.lockIntegrity ||
      actual.registryIntegrity !== expected.artifact.registryIntegrity ||
      actual.archiveSha512 !== expected.artifact.lockIntegrity ||
      actual.archiveExpandedBytes !== expected.archiveExpandedBytes ||
      actual.archiveRoot !== expected.archiveRoot ||
      actual.headerLayoutSha256 !== headerLayoutInventorySha256(expected.archiveMembers) ||
      actual.archiveMembersSha256 !== expected.archiveMembersSha256 ||
      expected.archiveMembersSha256 !== archiveMemberInventorySha256(expected.archiveMembers) ||
      actual.packageName !== expectedIdentity.name || actual.packageVersion !== expectedIdentity.version ||
      actual.metadataBytes !== expected.artifact.metadataBytes || actual.metadataSha256 !== expected.artifact.metadataSha256) {
      fail(`Inspection archive/metadata recheck differs from complete preflight at ordinal ${index}`)
    }
  }
}

function inspectionEffectPlan() {
  return {
    networkRequests: 0,
    packageCodeExecution: false,
    createNewDirectories: [],
    createNewFiles: [licenseInspectionReportRelative],
    extractionRoot: `${prefix}/unpacked`,
    extractedInventory: `${prefix}/unpacked-manifest.json`
  }
}

function assertInspectionEffectPlan(plan) {
  const allowedReportPath = 'web/comfy/build-artifacts-v2/license-inspection-report.json'
  const expectedKeys = [
    'networkRequests', 'packageCodeExecution', 'createNewDirectories', 'createNewFiles', 'extractionRoot', 'extractedInventory'
  ]
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)) {
    fail('Inspection effect plan contains unknown or missing fields')
  }
  const actualKeys = Reflect.ownKeys(plan)
  if (actualKeys.some((key) => typeof key !== 'string') ||
    JSON.stringify(actualKeys.slice().sort()) !== JSON.stringify(expectedKeys.slice().sort())) {
    fail('Inspection effect plan contains unknown or missing fields')
  }
  if (licenseInspectionReportRelative !== allowedReportPath || !Array.isArray(plan.createNewFiles) ||
    plan.createNewFiles.length !== 1 || plan.createNewFiles[0] !== allowedReportPath) {
    fail('Inspection effect plan has a different or extra report destination')
  }
  if (!Array.isArray(plan.createNewDirectories) || plan.createNewDirectories.length !== 0) {
    fail('Inspection effect plan attempts directory creation')
  }
  if (plan.networkRequests !== 0) fail('Inspection effect plan requests network access')
  if (plan.packageCodeExecution !== false) fail('Inspection effect plan permits package code execution')
  if (plan.extractionRoot !== 'web/comfy/build-artifacts-v2/unpacked' ||
    plan.extractedInventory !== 'web/comfy/build-artifacts-v2/unpacked-manifest.json') {
    fail('Inspection effect plan names a different extraction boundary')
  }
  return Object.freeze({
    networkRequests: 0,
    packageCodeExecution: false,
    createNewDirectories: Object.freeze([]),
    createNewFiles: Object.freeze([allowedReportPath]),
    extractionRoot: 'web/comfy/build-artifacts-v2/unpacked',
    extractedInventory: 'web/comfy/build-artifacts-v2/unpacked-manifest.json'
  })
}

function buildPlan(artifacts, reconciliation) {
  const items = artifacts.map((artifact) => ({
    locator: artifact.locator,
    name: artifact.name,
    version: artifact.version,
    integrity: artifact.integrity,
    archiveByteLimit: archiveByteLimitFor(artifact)
  }))
  const pnpm = { locator: `pnpm@${pnpmVersion}`, name: 'pnpm', version: pnpmVersion, integrity: pnpmIntegrity }
  items.push({ ...pnpm, archiveByteLimit: archiveByteLimitFor(pnpm) })
  return {
    schema: 'comfy-canvas-build-plan/v3',
    root: 'ComfyUI_frontend@1.51.9',
    script: 'pnpm typecheck && vite build --config vite.config.mts',
    packageManager: `pnpm@${pnpmVersion}`,
    packageManagerPin: { integrity: pnpmIntegrity, tarball: pnpmTarball, source: pnpmPinSource, sourceSha256: pnpmPinSourceSha256, authority: 'root-observed-official-registry-metadata-not-archive-proof' },
    target: 'win32-x64',
    lockSha256,
    archiveLimitPolicy: archiveLimitPolicy(),
    reconciliation,
    registryArtifactCount: artifacts.length,
    items
  }
}

async function downloadArtifacts(artifacts, reconciliation) {
  const pnpm = { name: 'pnpm', version: pnpmVersion, locator: `pnpm@${pnpmVersion}`, integrity: pnpmIntegrity }
  const all = [...artifacts, pnpm]
  if (all.length > artifactLimit || all.length > metadataRequestLimit || all.length > tarballRequestLimit) fail('Declared acquisition count bound exceeded')
  if (all.length * 2 > aggregateRequestLimit) fail('Declared aggregate request bound exceeded')
  assertInjectiveMappings(all)
  const approvedPlanBytes = await readBoundedLocal(safePath(planRelative), planByteLimit, 'Materialized build plan')
  const approvedPlan = manifestJson(approvedPlanBytes, 'Materialized build plan')
  const expectedPlan = buildPlan(artifacts, reconciliation)
  if (JSON.stringify(approvedPlan) !== JSON.stringify(expectedPlan) ||
    !approvedPlanBytes.equals(boundedJsonBytes(expectedPlan, planByteLimit, 'Build plan'))) {
    fail('Materialized plan differs from the authenticated lock closure')
  }
  const base = await preparePrefix()
  const records = []
  let aggregateBytes = 0
  for (let index = 0; index < all.length; index++) {
    const artifact = all[index]
    const metaBytes = await registryGet(metadataUrl(artifact.name, artifact.version), metadataByteLimit, `metadata ${artifact.locator}`)
    const metadata = manifestJson(metaBytes, `Registry metadata ${artifact.locator}`)
    if (metadata.name !== artifact.name || metadata.version !== artifact.version) fail(`Registry metadata identity mismatch: ${artifact.locator}`)
    const integrity = metadata.dist?.integrity
    if (!/^sha512-[A-Za-z0-9+/]{86}==$/.test(integrity || '')) fail(`Registry metadata lacks canonical SHA512 SRI: ${artifact.locator}`)
    if (integrity !== artifact.integrity) fail(`Registry SRI does not match authenticated pin: ${artifact.locator}`)
    const tarball = new URL(metadata.dist.tarball)
    if (tarball.origin !== registryOrigin || tarball.protocol !== 'https:' || tarball.username || tarball.password ||
      (artifact.locator === pnpm.locator && tarball.href !== pnpmTarball)) {
      fail(`Registry metadata supplied a non-allowlisted tarball: ${artifact.locator}`)
    }
    const archiveByteLimit = assertArchiveByteLimitRecord(
      artifact, archiveByteLimitFor(artifact), tarball.href, `Plan ${artifact.locator}`
    )
    const metaPath = path.join(base, 'metadata', archiveFilename(index, '.json'))
    await writeNewFile(metaPath, metaBytes)

    const archive = await registryGet(tarball, archiveByteLimit, `tarball ${artifact.locator}`)
    aggregateBytes += archive.byteLength
    if (aggregateBytes > aggregateArchiveByteLimit) fail('Aggregate archive byte cap exceeded')
    assertArtifactIntegrity(artifact.integrity, integrity, archive, artifact.locator)
    const archivePath = path.join(base, 'npm', archiveFilename(index))
    await writeNewFile(archivePath, archive)
    records.push({
      ordinal: index,
      locator: artifact.locator,
      lockIntegrity: artifact.integrity,
      registryIntegrity: integrity,
      registryTarball: tarball.href,
      archiveByteLimit,
      archive: path.relative(root, archivePath).replaceAll(path.sep, '/'),
      bytes: archive.byteLength,
      sha256: hash(archive, 'sha256'),
      metadata: path.relative(root, metaPath).replaceAll(path.sep, '/'),
      metadataBytes: metaBytes.byteLength,
      metadataSha256: hash(metaBytes, 'sha256')
    })
  }
  const manifest = {
    schema: 'comfy-canvas-build-acquisition/v3',
    packageManager: pnpm.locator,
    packageManagerPin: { integrity: pnpmIntegrity, tarball: pnpmTarball, source: pnpmPinSource, sourceSha256: pnpmPinSourceSha256, authority: 'root-observed-official-registry-metadata-not-archive-proof' },
    lockSha256,
    target: 'win32-x64',
    reconciliation,
    limits: acquisitionLimits(),
    networkRequests: { metadata: records.length, tarballs: records.length, aggregate: records.length * 2 },
    archiveBytes: aggregateBytes,
    artifacts: records
  }
  await writeNewFile(path.join(base, 'manifest.json'), boundedJsonBytes(manifest, acquisitionManifestByteLimit, 'Acquisition manifest'))
  process.stdout.write(`Acquired ${records.length} exact registry artifacts; reachableSnapshots=${reconciliation.reachableSnapshots}; archiveBytes=${aggregateBytes}; no package code executed\n`)
}

function tarText(header, start, length) {
  const end = header.indexOf(0, start)
  const last = end < 0 || end > start + length ? start + length : end
  if (end >= start && end < start + length && header.subarray(end + 1, start + length).some((byte) => byte !== 0)) {
    fail('Tar header field contains non-padding bytes after NUL')
  }
  try { return new TextDecoder('utf-8', { fatal: true }).decode(header.subarray(start, last)) } catch { fail('Tar header field is not strict UTF-8') }
}

function tarOctal(header, start, length) {
  const field = header.subarray(start, start + length)
  let end = field.length
  while (end > 0 && (field[end - 1] === 0 || field[end - 1] === 0x20)) end--
  const raw = field.toString('ascii', 0, end).trim()
  if (field.subarray(end).some((byte) => byte !== 0 && byte !== 0x20)) fail('Tar octal field has ambiguous padding')
  if (!raw) return 0
  if (!/^[0-7]+$/.test(raw)) fail('Tar member uses a non-octal or ambiguous size')
  return Number.parseInt(raw, 8)
}

function parseTarTimestampField(field, label) {
  if (!Buffer.isBuffer(field) || field.length !== 12) fail(`Tar header ${label} timestamp field has an invalid width`)
  if (field.every((byte) => byte === 0)) return null
  const nul = field.indexOf(0)
  if (nul >= 0 && field.subarray(nul + 1).some((byte) => byte !== 0)) {
    fail(`Tar header ${label} timestamp has non-padding bytes after NUL`)
  }
  let end = nul >= 0 ? nul : field.length
  while (end > 0 && field[end - 1] === 0x20) end--
  const digitBytes = field.subarray(0, end)
  if (digitBytes.length === 0 || digitBytes.some((byte) => byte < 0x30 || byte > 0x37)) {
    fail(`Tar header ${label} timestamp is not strict octal`)
  }
  const raw = field.toString('ascii', 0, end)
  if (!raw || (nul < 0 && field.subarray(end).some((byte) => byte !== 0x20))) {
    fail(`Tar header ${label} timestamp is not strict octal`)
  }
  const value = BigInt(`0o${raw}`)
  if (value > BigInt(Number.MAX_SAFE_INTEGER)) fail(`Tar header ${label} timestamp exceeds the safe integer bound`)
  return Number(value)
}

function decodeTarHeaderLayout(header) {
  if (!Buffer.isBuffer(header) || header.length !== 512) fail('Tar header layout decoder requires exactly 512 bytes')
  const magic = header.subarray(257, 263)
  const version = header.subarray(263, 265)
  const exactUstar = magic.equals(Buffer.from('ustar\0', 'ascii')) && version.equals(Buffer.from('00', 'ascii'))
  let prefixWidth = 155
  let layout = 'strict-prefix-155'
  let prefix
  let mtime = null
  let ctime = null
  let mtimeRawHex = Buffer.alloc(12).toString('hex')
  let ctimeRawHex = Buffer.alloc(12).toString('hex')
  if (exactUstar && header[475] === 0) {
    const prefixField = header.subarray(345, 475)
    const tail = header.subarray(500, 512)
    if (tail.some((byte) => byte !== 0)) fail('Tar USTAR short-prefix reserved tail is nonzero')
    prefix = tarText(header, 345, 130)
    const mtimeField = header.subarray(476, 488)
    const ctimeField = header.subarray(488, 500)
    mtime = parseTarTimestampField(mtimeField, 'mtime')
    ctime = parseTarTimestampField(ctimeField, 'ctime')
    prefixWidth = 130
    layout = 'ustar-short-prefix-130-with-times'
    mtimeRawHex = mtimeField.toString('hex')
    ctimeRawHex = ctimeField.toString('hex')
    if (prefixField.length !== 130) fail('Tar USTAR short-prefix field has an invalid width')
  } else {
    prefix = tarText(header, 345, 155)
  }
  return {
    layout,
    prefixWidth,
    prefix,
    mtimeRawHex,
    ctimeRawHex,
    mtime,
    ctime,
    headerSha256: hash(header, 'sha256')
  }
}

function assertTarHeaderLayoutMatchesHeader(header, layout) {
  assertTarHeaderLayoutProvenance(layout, layout?.prefix)
  if (JSON.stringify(decodeTarHeaderLayout(header)) !== JSON.stringify(layout)) {
    fail('Tar header layout annotation does not match authenticated header bytes')
  }
}

function assertTarHeaderLayoutProvenance(layout, headerPrefix) {
  const keys = ['layout', 'prefixWidth', 'prefix', 'mtimeRawHex', 'ctimeRawHex', 'mtime', 'ctime', 'headerSha256']
  if (!layout || typeof layout !== 'object' || Array.isArray(layout) ||
    JSON.stringify(Object.keys(layout).sort()) !== JSON.stringify([...keys].sort()) ||
    !['strict-prefix-155', 'ustar-short-prefix-130-with-times'].includes(layout.layout) ||
    layout.prefixWidth !== (layout.layout === 'strict-prefix-155' ? 155 : 130) ||
    typeof layout.prefix !== 'string' || Buffer.byteLength(layout.prefix, 'utf8') > layout.prefixWidth || layout.prefix !== headerPrefix ||
    !/^(?:[0-9a-f]{24})$/.test(layout.mtimeRawHex) || !/^(?:[0-9a-f]{24})$/.test(layout.ctimeRawHex) ||
    !/^[0-9a-f]{64}$/.test(layout.headerSha256) ||
    ![null, Number.isSafeInteger(layout.mtime) && layout.mtime >= 0 ? layout.mtime : undefined].includes(layout.mtime) ||
    ![null, Number.isSafeInteger(layout.ctime) && layout.ctime >= 0 ? layout.ctime : undefined].includes(layout.ctime)) {
    fail('Tar header layout provenance is missing, forged, or malformed')
  }
  const validateTime = (rawHex, value, label) => {
    const raw = Buffer.from(rawHex, 'hex')
    const decoded = parseTarTimestampField(raw, label)
    if (decoded !== value) fail(`Tar header ${label} layout provenance does not match its raw bytes`)
  }
  validateTime(layout.mtimeRawHex, layout.mtime, 'mtime')
  validateTime(layout.ctimeRawHex, layout.ctime, 'ctime')
  if (layout.layout === 'strict-prefix-155' && (layout.mtime !== null || layout.ctime !== null ||
    layout.mtimeRawHex !== '0'.repeat(24) || layout.ctimeRawHex !== '0'.repeat(24))) {
    fail('Tar standard-prefix layout unexpectedly carries short-prefix time metadata')
  }
}

function headerLayoutInventorySha256(archiveMembers) {
  if (!Array.isArray(archiveMembers) || archiveMembers.length < 1 || archiveMembers.length > expandedEntryCountLimit) {
    fail('Tar header layout inventory is missing or exceeds its member-count bound')
  }
  const inventoryHash = createHash('sha256')
  for (const member of archiveMembers) {
    assertTarHeaderLayoutProvenance(member?.headerLayout, member?.headerPrefix)
    const serialized = JSON.stringify({
      headerLayout: member.headerLayout,
      headerBytesHex: member.headerBytesHex,
      type: member.type,
      index: member.index,
      headerType: member.headerType,
      headerOffset: member.headerOffset,
      dataOffset: member.dataOffset,
      payloadBytes: member.payloadBytes,
      payloadSha256: member.payloadSha256,
      gnuLongNameMetadataIndex: member.gnuLongNameMetadataIndex ?? null,
      gnuLongNamePath: member.gnuLongNamePath ?? null,
      gnuLongNamePayloadHex: member.gnuLongNamePayloadHex ?? null,
      targetHeaderOffset: member.targetHeaderOffset ?? null
    })
    inventoryHash.update(`${Buffer.byteLength(serialized, 'utf8')}:`, 'utf8')
    inventoryHash.update(serialized, 'utf8')
    inventoryHash.update('\n', 'utf8')
  }
  return inventoryHash.digest('hex')
}

function archiveMemberInventorySha256(archiveMembers) {
  if (!Array.isArray(archiveMembers) || archiveMembers.length < 1 || archiveMembers.length > expandedEntryCountLimit) {
    fail('Tar archive-member provenance inventory is missing or exceeds its member-count bound')
  }
  const inventoryHash = createHash('sha256')
  for (const member of archiveMembers) {
    const serialized = JSON.stringify(member)
    inventoryHash.update(`${Buffer.byteLength(serialized, 'utf8')}:`, 'utf8')
    inventoryHash.update(serialized, 'utf8')
    inventoryHash.update('\n', 'utf8')
  }
  return inventoryHash.digest('hex')
}

function validateTarPath(name, { directory = false, expectedIdentity } = {}) {
  if (typeof name !== 'string' || !name || name.startsWith('/') || name.startsWith('\\') || name.includes('\\') || /^[A-Za-z]:/.test(name)) {
    fail(`Unsafe tar member path: ${name}`)
  }
  if (name.length > tarRawPathByteLimit || Buffer.byteLength(name, 'utf8') > tarRawPathByteLimit) {
    fail(`Tar member raw path exceeds its ${tarRawPathByteLimit}-byte bound`)
  }
  const rawSegments = name.split('/')
  const archiveRoot = rawSegments[0]
  if (archiveRoot !== 'package' && !isAuthenticatedArchiveRoot(archiveRoot, expectedIdentity)) {
    fail(`Unexpected npm tar root: ${name}`)
  }
  if (rawSegments.slice(1).some((part) => part === '..')) fail(`Tar member path contains parent traversal: ${name}`)
  const segments = rawSegments.slice()
  if (directory && name.endsWith('/')) segments.pop()
  if (segments.some((part) => !part)) fail(`Tar member path has an empty component: ${name}`)
  for (const part of segments) {
    if (part === '.') continue
    const windowsBase = part.split('.')[0].replace(/[. ]+$/g, '').toUpperCase()
    if (part.length > tarPathComponentByteLimit || /^(?:COM|LPT)[\u00b9\u00b2\u00b3]$/i.test(part.split('.')[0])) {
      fail(`Tar member path component exceeds its ${tarPathComponentByteLimit}-byte bound: ${name}`)
    }
    if (/[^\x20-\x7e]/.test(part) || /[<>:"|?*\u0000-\u001f]/.test(part) || /[. ]$/.test(part) ||
      /^(CON|PRN|AUX|NUL|COM[1-9\u00b9\u00b2\u00b3]|LPT[1-9\u00b9\u00b2\u00b3])$/.test(windowsBase)) {
      fail(`Ambiguous tar member path: ${name}`)
    }
  }
  const canonicalSegments = segments.filter((part, index) => index === 0 || part !== '.')
  if (!directory && canonicalSegments.length === 1) {
    fail(`Tar regular member path resolves to the archive root: ${name}`)
  }
  canonicalSegments[0] = 'package'
  const canonicalPath = canonicalSegments.join('/')
  // Construct only the validated canonical destination; no OS path normalization accepts archive input.
  const extractedPath = path.join(root, prefix, 'unpacked', packageDirectoryName(artifactLimit - 1), ...canonicalSegments)
  if (extractedPath.length > computedExtractionPathByteLimit) {
    fail(`Tar member canonical output path exceeds its ${computedExtractionPathByteLimit}-character bound: ${name}`)
  }
  return { rawPath: name, archiveRoot, canonicalPath }
}

function classifyPaxKey(key, value) {
  if (!/^[\x21-\x7e]+$/.test(key) || Buffer.byteLength(key, 'ascii') > paxKeyByteLimit) {
    fail('PAX key is not bounded printable ASCII')
  }
  if (['path', 'size', 'mtime', 'uid', 'gid', 'uname', 'gname'].includes(key)) return 'effective'
  if (['NODETAR.depth', 'NODETAR.blksize', 'NODETAR.blocks', 'SCHILY.dev', 'SCHILY.ino', 'SCHILY.nlink'].includes(key)) {
    if (!/^(0|[1-9]\d{0,19})$/.test(value) || BigInt(value) > maxFilesystemDeviceOrInode) {
      fail(`Invalid inert numeric PAX value for ${key}`)
    }
    return 'inert'
  }
  if (key === 'NODETAR.follow') {
    if (value !== 'true' && value !== 'false') fail('Invalid inert boolean PAX value for NODETAR.follow')
    return 'inert'
  }
  if (key === 'NODETAR.type') {
    if (!/^[\x20-\x7e]{1,128}$/.test(value)) fail('Invalid inert printable PAX value for NODETAR.type')
    return 'inert'
  }
  let match = /^NODETAR\.ignoreFiles\.(0|[1-9]\d{0,3})$/.exec(key)
  if (match) {
    if (Number(match[1]) > paxIgnoreFileIndexLimit) fail('PAX inert ignoreFiles index exceeds its bound')
    if (inertPaxControlPattern.test(value) || Buffer.byteLength(value, 'utf8') > paxInertValueByteLimit) {
      fail('Invalid or oversized inert PAX value for NODETAR.ignoreFiles')
    }
    return 'inert'
  }
  match = /^NODETAR\.package\.(.+)$/.exec(key)
  if (match) {
    const property = match[1]
    const segments = property.split('.')
    const segmentPattern = /^[A-Za-z0-9_$@+~!:/-]+$/
    if (segments.length > paxVendorPropertyDepthLimit || segments.some((segment) => !segment ||
      ['__proto__', 'prototype', 'constructor'].includes(segment) || !segmentPattern.test(segment))) {
      fail('Invalid inert NODETAR.package property path')
    }
    if (inertPaxControlPattern.test(value) || Buffer.byteLength(value, 'utf8') > paxInertValueByteLimit) {
      fail('Invalid or oversized inert PAX value for NODETAR.package')
    }
    return 'inert'
  }
  if (!['path', 'size', 'mtime', 'uid', 'gid', 'uname', 'gname'].includes(key)) fail(`Unsupported PAX key: ${key}`)
  return 'effective'
}

function parsePaxRecord(buffer) {
  if (!Buffer.isBuffer(buffer) || buffer.length > paxPayloadByteLimit) fail('PAX payload exceeds its byte bound')
  const values = new Map()
  let offset = 0
  while (offset < buffer.length) {
    if (values.size >= paxRecordCountLimit) fail('PAX record count exceeds its bound')
    const space = buffer.indexOf(0x20, offset)
    if (space < 0) fail('Malformed PAX record')
    for (let index = offset; index < space; index++) {
      if (buffer[index] < 0x30 || buffer[index] > 0x39) fail('Malformed or non-canonical PAX record length')
    }
    const lengthText = buffer.toString('ascii', offset, space)
    if (!/^[1-9]\d*$/.test(lengthText)) fail('Malformed or non-canonical PAX record length')
    const recordLength = Number(lengthText)
    if (!Number.isSafeInteger(recordLength) || recordLength <= space - offset + 2 || offset + recordLength > buffer.length ||
      buffer[offset + recordLength - 1] !== 0x0a) fail('PAX record bounds or terminal newline are invalid')
    let record
    try { record = new TextDecoder('utf-8', { fatal: true }).decode(buffer.subarray(space + 1, offset + recordLength - 1)) } catch { fail('PAX record is not strict UTF-8') }
    const equals = record.indexOf('=')
    if (equals <= 0) fail('Malformed PAX key/value')
    const key = record.slice(0, equals)
    const value = record.slice(equals + 1)
    if (values.has(key)) fail(`Duplicate PAX key: ${key}`)
    const classification = classifyPaxKey(key, value)
    if (classification === 'inert' && Buffer.byteLength(value, 'utf8') > paxInertValueByteLimit) {
      fail(`Inert PAX value exceeds its ${paxInertValueByteLimit}-byte bound: ${key}`)
    }
    if ((classification === 'effective' && !value) || /[\u0000-\u001f\u007f]/.test(value)) fail(`Invalid PAX value for ${key}`)
    if (['size', 'uid', 'gid'].includes(key) && !/^(0|[1-9]\d*)$/.test(value)) fail(`Invalid numeric PAX value for ${key}`)
    if (key === 'mtime' && !/^(0|[1-9]\d*)(?:\.\d+)?$/.test(value)) fail(`Invalid numeric PAX value for ${key}`)
    values.set(key, value)
    offset += recordLength
  }
  return values
}

function assertEntryArchiveRootConsistency(entries, expectedIdentity) {
  if (!Array.isArray(entries)) fail('Tar archive entries are missing for root reconciliation')
  let archiveRoot = null
  for (const entry of entries) {
    const pathInfo = validateTarPath(entry?.rawPath, {
      directory: entry?.type === 'directory', expectedIdentity
    })
    if (pathInfo.canonicalPath !== entry.path || pathInfo.archiveRoot !== entry.archiveRoot) {
      fail(`Tar archive entry root provenance differs from its validated raw path: ${entry?.rawPath}`)
    }
    if (archiveRoot !== null && archiveRoot !== pathInfo.archiveRoot) {
      fail(`Tar archive mixes effective roots: ${archiveRoot} / ${pathInfo.archiveRoot}`)
    }
    archiveRoot = pathInfo.archiveRoot
  }
  return archiveRoot
}

function collectCanonicalFileAliasGroups(entries, expectedIdentity) {
  if (!Array.isArray(entries)) fail('Canonical file alias inputs are missing')
  const groups = new Map()
  const collisionKeys = new Map()
  const directoryPaths = new Set()
  const memberIndices = new Set()
  let archiveRoot = null
  for (const entry of entries) {
    if (!entry || !Number.isSafeInteger(entry.archiveMemberIndex) || entry.archiveMemberIndex < 0 ||
      memberIndices.has(entry.archiveMemberIndex)) fail('Canonical file alias member index is missing or duplicated')
    memberIndices.add(entry.archiveMemberIndex)
    const pathInfo = validateTarPath(entry.rawPath, { directory: entry.type === 'directory', expectedIdentity })
    if (pathInfo.canonicalPath !== entry.path || pathInfo.archiveRoot !== entry.archiveRoot) {
      fail(`Canonical file alias path differs from its validated raw path: ${entry.path}`)
    }
    if (archiveRoot !== null && archiveRoot !== pathInfo.archiveRoot) {
      fail(`Tar archive mixes effective roots: ${archiveRoot} / ${pathInfo.archiveRoot}`)
    }
    archiveRoot = pathInfo.archiveRoot
    const collisionKey = entry.path.toLowerCase()
    const caseEquivalent = collisionKeys.get(collisionKey)
    if (caseEquivalent && caseEquivalent.path !== entry.path) fail(`Duplicate or case-colliding tar path: ${entry.path}`)
    if (!caseEquivalent) collisionKeys.set(collisionKey, { path: entry.path, type: entry.type })
    else if (caseEquivalent.type !== entry.type) fail(`Tar file/directory alias conflict: ${entry.path}`)
    if (entry.type === 'directory') {
      if (directoryPaths.has(entry.path)) fail(`Duplicate or case-colliding tar path: ${entry.path}`)
      directoryPaths.add(entry.path)
      continue
    }
    if (entry.type !== 'file' || !Number.isSafeInteger(entry.bytes) || entry.bytes < 0 ||
      !Buffer.isBuffer(entry.data) || entry.data.byteLength !== entry.bytes) {
      fail(`Canonical file alias has an invalid regular-file payload: ${entry.path}`)
    }
    let group = groups.get(entry.path)
    if (!group) {
      group = { path: entry.path, bytes: entry.bytes, data: entry.data, rawPaths: new Set(), entries: [] }
      groups.set(entry.path, group)
    } else {
      if (group.rawPaths.has(entry.rawPath)) fail(`Repeated raw tar file path: ${entry.rawPath}`)
      if (group.bytes !== entry.bytes) fail(`Canonical file alias size mismatch: ${entry.path}`)
      if (!group.data.equals(entry.data)) fail(`Canonical file alias payload mismatch: ${entry.path}`)
    }
    if (group.rawPaths.has(entry.rawPath)) fail(`Repeated raw tar file path: ${entry.rawPath}`)
    group.rawPaths.add(entry.rawPath)
    group.entries.push(entry)
  }
  return [...groups.values()].map((group) => {
    const archiveMemberIndices = group.entries.map((entry) => entry.archiveMemberIndex).sort((left, right) => left - right)
    const primaryArchiveMemberIndex = archiveMemberIndices[0]
    return { path: group.path, bytes: group.bytes, sha256: hash(group.data, 'sha256'),
      primaryArchiveMemberIndex, archiveMemberIndices, entries: group.entries }
  }).sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
}

function annotateCanonicalFileAliasGroups(entries, archiveMembers, expectedIdentity) {
  const groups = collectCanonicalFileAliasGroups(entries, expectedIdentity)
  for (const group of groups) {
    for (const entry of group.entries) {
      entry.primaryArchiveMemberIndex = group.primaryArchiveMemberIndex
      entry.archiveMemberIndices = [...group.archiveMemberIndices]
      const member = archiveMembers[entry.archiveMemberIndex]
      if (!member || member.type !== 'file' || member.path !== group.path || member.rawPath !== entry.rawPath) {
        fail(`Canonical file alias member provenance is incomplete: ${group.path}`)
      }
      member.outputPath = group.path
      member.outputPrimaryArchiveMemberIndex = group.primaryArchiveMemberIndex
      member.outputArchiveMemberIndices = [...group.archiveMemberIndices]
    }
  }
  return groups
}

function parseTar(archive, expectedIdentity) {
  const expanded = gunzipSync(archive, { maxOutputLength: perArchiveExpandedByteLimit })
  const entries = []
  const archiveMembers = []
  const seen = new Map()
  const pathTypes = new Map()
  let offset = 0
  let nextPax = null
  let nextGnuLongName = null
  let ended = false
  let archiveRoot = null
  while (offset + 512 <= expanded.length) {
    const header = expanded.subarray(offset, offset + 512)
    if (header.every((byte) => byte === 0)) {
      if (nextPax) fail('Tar archive ended with an unconsumed PAX record')
      if (nextGnuLongName) fail('Tar archive ended with an unconsumed GNU long-name record')
      if (offset + 1024 > expanded.length || expanded.subarray(offset, offset + 1024).some((byte) => byte !== 0)) {
        fail('Tar archive requires two complete zero end blocks')
      }
      const trailer = expanded.subarray(offset + 1024)
      if (trailer.length % 512 !== 0 || trailer.some((byte) => byte !== 0)) fail('Tar archive has partial or non-zero trailing padding')
      ended = true
      break
    }
    const storedChecksum = tarOctal(header, 148, 8)
    let checksum = 0
    for (let i = 0; i < 512; i++) checksum += i >= 148 && i < 156 ? 32 : header[i]
    if (checksum !== storedChecksum) fail('Tar header checksum mismatch')

    const headerLayout = decodeTarHeaderLayout(header)
    const headerName = tarText(header, 0, 100)
    const prefixName = headerLayout.prefix
    const pax = nextPax
    const gnuLongName = nextGnuLongName
    const headerPath = prefixName ? `${prefixName}/${headerName}` : headerName
    const paxPath = pax?.values.get('path') ?? null
    const name = gnuLongName?.path ?? paxPath ?? headerPath
    const type = tarText(header, 156, 1) || '\0'
    if (gnuLongName && (type === 'L' || type === 'x')) {
      fail('GNU long-name record cannot stack or combine with PAX metadata')
    }
    if (gnuLongName && type !== '\0' && type !== '0' && type !== '5') {
      fail(`GNU long-name record targets unsupported tar member type ${JSON.stringify(type)}`)
    }
    const size = type === 'x' || type === 'L'
      ? tarOctal(header, 124, 12)
      : pax?.values.has('size') ? Number(pax.values.get('size')) : tarOctal(header, 124, 12)
    if (!Number.isSafeInteger(size) || size < 0 || offset + 512 + size > expanded.length) fail('Tar member size is invalid')
    const dataStart = offset + 512
    const dataEnd = dataStart + size
    const paddedEnd = dataStart + Math.ceil(size / 512) * 512
    if (paddedEnd > expanded.length) fail('Tar member exceeds archive bounds')
    if (expanded.subarray(dataEnd, paddedEnd).some((byte) => byte !== 0)) {
      fail('Tar member data padding contains nonzero bytes')
    }

    if (type === 'x') {
      if (gnuLongName) fail('PAX metadata cannot follow GNU long-name metadata')
      if (nextPax) fail('Multiple PAX headers cannot target one member')
      const data = expanded.subarray(dataStart, dataEnd)
      const paxIndex = archiveMembers.length
      archiveMembers.push({
        index: paxIndex,
        type: 'pax-extension',
        headerType: type,
        headerPrefix: prefixName,
        headerLayout,
        headerBytesHex: header.toString('hex'),
        headerName,
        headerPath,
        rawPath: headerPath,
        archiveRoot: null,
        paxPath: null,
        path: null,
        canonicalPath: null,
        headerOffset: offset,
        dataOffset: dataStart,
        offsetBasis: 'uncompressed-tar-stream-bytes',
        payloadBytes: size,
        payloadSha256: hash(data, 'sha256'),
        boundToHeaderOffset: null,
        gnuLongNameMetadataIndex: null,
        gnuLongNamePath: null
      })
      if (archiveMembers.length > expandedEntryCountLimit) fail('Tar archive-member count bound exceeded')
      nextPax = { values: parsePaxRecord(data), archiveMemberIndex: paxIndex }
      offset = paddedEnd
      continue
    }
    if (type === 'L') {
      if (nextPax) fail('GNU long-name metadata cannot combine with pending PAX metadata')
      if (nextGnuLongName) fail('GNU long-name metadata cannot stack')
      const data = expanded.subarray(dataStart, dataEnd)
      const longNamePath = decodeGnuLongNamePayload(data)
      const longPathInfo = validateTarPath(longNamePath, { directory: longNamePath.endsWith('/'), expectedIdentity })
      const metadataIndex = archiveMembers.length
      archiveMembers.push({
        index: metadataIndex,
        type: 'gnu-long-name',
        headerType: type,
        headerPrefix: prefixName,
        headerLayout,
        headerBytesHex: header.toString('hex'),
        headerName,
        headerPath,
        rawPath: headerPath,
        archiveRoot: null,
        paxPath: null,
        path: null,
        canonicalPath: null,
        headerOffset: offset,
        dataOffset: dataStart,
        offsetBasis: 'uncompressed-tar-stream-bytes',
        payloadBytes: size,
        payloadSha256: hash(data, 'sha256'),
        gnuLongNameMetadataIndex: null,
        gnuLongNamePath: longNamePath,
        gnuLongNamePayloadHex: data.toString('hex'),
        targetHeaderOffset: null
      })
      if (archiveMembers.length > expandedEntryCountLimit) fail('Tar archive-member count bound exceeded')
      nextGnuLongName = { path: longNamePath, archiveMemberIndex: metadataIndex, archiveRoot: longPathInfo.archiveRoot }
      offset = paddedEnd
      continue
    }
    const effectiveHeaderName = name
    if (type === '5') {
      if (size !== 0) fail(`Tar directory member has a nonzero payload: ${name}`)
      const pathInfo = validateTarPath(effectiveHeaderName, { directory: true, expectedIdentity })
      const headerPathInfo = validateTarPath(headerPath, { directory: true, expectedIdentity })
      if (headerPathInfo.archiveRoot !== pathInfo.archiveRoot) {
        fail(`Tar header/effective path roots differ: ${headerPathInfo.archiveRoot} / ${pathInfo.archiveRoot}`)
      }
      if (gnuLongName && headerPathInfo.archiveRoot !== gnuLongName.archiveRoot) {
        fail(`Tar GNU long-name/header roots differ: ${headerPathInfo.archiveRoot} / ${gnuLongName.archiveRoot}`)
      }
      if (archiveRoot !== null && archiveRoot !== pathInfo.archiveRoot) {
        fail(`Tar archive mixes effective roots: ${archiveRoot} / ${pathInfo.archiveRoot}`)
      }
      archiveRoot = pathInfo.archiveRoot
      const directory = pathInfo.canonicalPath
      const collisionKey = directory.toLowerCase()
      if (seen.has(collisionKey)) fail(`Duplicate or case-colliding tar path: ${directory}`)
      for (const ancestor of collisionKey.split('/').slice(0, -1).map((_, index, parts) => parts.slice(0, index + 1).join('/'))) {
        if (pathTypes.get(ancestor) === 'file') fail(`Tar directory descends from file: ${directory}`)
      }
      seen.set(collisionKey, { path: directory, type: 'directory' })
      pathTypes.set(collisionKey, 'directory')
      const archiveMemberIndex = archiveMembers.length
      entries.push({
        path: directory, rawPath: pathInfo.rawPath, headerPath, headerPrefix: prefixName, headerLayout,
        headerBytesHex: header.toString('hex'), headerName, paxPath,
        type: 'directory', bytes: 0, archiveMemberIndex, headerOffset: offset, archiveRoot: pathInfo.archiveRoot,
        gnuLongNameMetadataIndex: gnuLongName?.archiveMemberIndex ?? null, gnuLongNamePath: gnuLongName?.path ?? null
      })
      archiveMembers.push({
        index: archiveMemberIndex,
        type: 'directory',
        headerType: type,
        headerPrefix: prefixName,
        headerLayout,
        headerBytesHex: header.toString('hex'),
        headerName,
        headerPath,
        rawPath: pathInfo.rawPath,
        archiveRoot: pathInfo.archiveRoot,
        paxPath,
        path: directory,
        canonicalPath: directory,
        headerOffset: offset,
        dataOffset: dataStart,
        offsetBasis: 'uncompressed-tar-stream-bytes',
        payloadBytes: size,
        payloadSha256: hash(expanded.subarray(dataStart, dataEnd), 'sha256'),
        paxHeaderIndex: pax?.archiveMemberIndex ?? null,
        gnuLongNameMetadataIndex: gnuLongName?.archiveMemberIndex ?? null,
        gnuLongNamePath: gnuLongName?.path ?? null
      })
    } else if (type === '\0' || type === '0') {
      const pathInfo = validateTarPath(effectiveHeaderName, { expectedIdentity })
      const headerPathInfo = validateTarPath(headerPath, { expectedIdentity })
      if (headerPathInfo.archiveRoot !== pathInfo.archiveRoot) {
        fail(`Tar header/effective path roots differ: ${headerPathInfo.archiveRoot} / ${pathInfo.archiveRoot}`)
      }
      if (gnuLongName && headerPathInfo.archiveRoot !== gnuLongName.archiveRoot) {
        fail(`Tar GNU long-name/header roots differ: ${headerPathInfo.archiveRoot} / ${gnuLongName.archiveRoot}`)
      }
      if (archiveRoot !== null && archiveRoot !== pathInfo.archiveRoot) {
        fail(`Tar archive mixes effective roots: ${archiveRoot} / ${pathInfo.archiveRoot}`)
      }
      archiveRoot = pathInfo.archiveRoot
      const normalized = pathInfo.canonicalPath
      const collisionKey = normalized.toLowerCase()
      const previous = seen.get(collisionKey)
      if (previous && (previous.type !== 'file' || previous.path !== normalized)) {
        fail(`Duplicate or case-colliding tar path: ${normalized}`)
      }
      const parts = collisionKey.split('/')
      for (let index = 1; index < parts.length; index++) {
        if (pathTypes.get(parts.slice(0, index).join('/')) === 'file') fail(`Tar file descends from file: ${normalized}`)
      }
      if ([...pathTypes.keys()].some((candidate) => candidate.startsWith(`${collisionKey}/`))) {
        fail(`Tar file replaces a directory: ${normalized}`)
      }
      pathTypes.set(collisionKey, 'file')
      const archiveMemberIndex = archiveMembers.length
      const entry = {
        path: normalized, rawPath: pathInfo.rawPath, headerPath, headerPrefix: prefixName, headerLayout,
        headerBytesHex: header.toString('hex'), headerName, paxPath,
        type: 'file', bytes: size, data: expanded.subarray(dataStart, dataEnd), archiveMemberIndex, headerOffset: offset,
        archiveRoot: pathInfo.archiveRoot, gnuLongNameMetadataIndex: gnuLongName?.archiveMemberIndex ?? null,
        gnuLongNamePath: gnuLongName?.path ?? null
      }
      if (previous) {
        if (previous.rawPaths.has(pathInfo.rawPath)) fail(`Repeated raw tar file path: ${pathInfo.rawPath}`)
        if (previous.bytes !== size) fail(`Canonical file alias size mismatch: ${normalized}`)
        if (!previous.data.equals(entry.data)) fail(`Canonical file alias payload mismatch: ${normalized}`)
        previous.rawPaths.add(pathInfo.rawPath)
        previous.entries.push(entry)
      } else {
        seen.set(collisionKey, { path: normalized, type: 'file', bytes: size, data: entry.data,
          rawPaths: new Set([pathInfo.rawPath]), entries: [entry] })
      }
      entries.push(entry)
      archiveMembers.push({
        index: archiveMemberIndex,
        type: 'file',
        headerType: type,
        headerPrefix: prefixName,
        headerLayout,
        headerBytesHex: header.toString('hex'),
        headerName,
        headerPath,
        rawPath: pathInfo.rawPath,
        archiveRoot: pathInfo.archiveRoot,
        paxPath,
        path: normalized,
        canonicalPath: normalized,
        headerOffset: offset,
        dataOffset: dataStart,
        offsetBasis: 'uncompressed-tar-stream-bytes',
        payloadBytes: size,
        payloadSha256: hash(expanded.subarray(dataStart, dataEnd), 'sha256'),
        paxHeaderIndex: pax?.archiveMemberIndex ?? null,
        gnuLongNameMetadataIndex: gnuLongName?.archiveMemberIndex ?? null,
        gnuLongNamePath: gnuLongName?.path ?? null
      })
    } else {
      fail(`Forbidden tar member type ${JSON.stringify(type)} at ${name}`)
    }
    if (pax) archiveMembers[pax.archiveMemberIndex].boundToHeaderOffset = offset
    if (gnuLongName) archiveMembers[gnuLongName.archiveMemberIndex].targetHeaderOffset = offset
    if (archiveMembers.length > expandedEntryCountLimit) fail('Tar archive-member count bound exceeded')
    nextPax = null
    nextGnuLongName = null
    offset = paddedEnd
  }
  if (!ended) fail('Tar archive is missing complete end-of-archive blocks')
  annotateCanonicalFileAliasGroups(entries, archiveMembers, expectedIdentity)
  assertGnuLongNameBindings(archiveMembers, expectedIdentity)
  return { entries, archiveMembers, archiveExpandedBytes: expanded.byteLength, archiveRoot,
    expectedIdentity: expectedIdentity ?? null, headerLayoutSha256: headerLayoutInventorySha256(archiveMembers),
    archiveMembersSha256: archiveMemberInventorySha256(archiveMembers) }
}

function accountArchiveExpansion(records, ordinal, archiveExpandedBytes, aggregateCap = aggregateArchiveExpandedByteLimit) {
  if (!Array.isArray(records) || ordinal !== records.length || !Number.isSafeInteger(aggregateCap) || aggregateCap < 1 ||
    !Number.isSafeInteger(archiveExpandedBytes) || archiveExpandedBytes < 1 || archiveExpandedBytes > perArchiveExpandedByteLimit) {
    fail('Archive expansion accounting record is malformed or outside its per-archive cap')
  }
  let aggregateArchiveExpandedBytes = 0
  for (let index = 0; index < records.length; index++) {
    const record = records[index]
    if (record?.ordinal !== index || !Number.isSafeInteger(record.archiveExpandedBytes) || record.archiveExpandedBytes < 1 ||
      record.archiveExpandedBytes > perArchiveExpandedByteLimit || !Number.isSafeInteger(aggregateArchiveExpandedBytes + record.archiveExpandedBytes)) {
      fail('Prior archive expansion accounting record is malformed')
    }
    aggregateArchiveExpandedBytes += record.archiveExpandedBytes
  }
  aggregateArchiveExpandedBytes += archiveExpandedBytes
  if (!Number.isSafeInteger(aggregateArchiveExpandedBytes) || aggregateArchiveExpandedBytes > aggregateCap) {
    fail('Aggregate gzip-expanded archive-byte cap exceeded')
  }
  records.push({ ordinal, archiveExpandedBytes })
  return aggregateArchiveExpandedBytes
}

function assertPackageArchiveExpansion(packages, expectedAggregate) {
  if (!Array.isArray(packages) || packages.length < 1 || packages.length > artifactLimit ||
    !Number.isSafeInteger(expectedAggregate) || expectedAggregate < 1 || expectedAggregate > aggregateArchiveExpandedByteLimit) {
    fail('Package archive-expansion aggregate is malformed or outside its fixed cap')
  }
  let measured = 0
  for (let index = 0; index < packages.length; index++) {
    const record = packages[index]
    if (record?.ordinal !== index || !Number.isSafeInteger(record.archiveExpandedBytes) ||
      record.archiveExpandedBytes < 1 || record.archiveExpandedBytes > perArchiveExpandedByteLimit ||
      !Number.isSafeInteger(measured + record.archiveExpandedBytes)) {
      fail(`Package archive-expansion record is malformed at ordinal ${index}`)
    }
    measured += record.archiveExpandedBytes
    if (measured > aggregateArchiveExpandedByteLimit) fail('Aggregate gzip-expanded archive-byte cap exceeded')
  }
  if (measured !== expectedAggregate) fail('Package archive-expansion aggregate differs from measured archive total')
  return measured
}

function planPackageOutputInventory(ordinal, entries, expectedIdentity) {
  assertEntryArchiveRootConsistency(entries, expectedIdentity)
  const ordinalRoot = packageDirectoryName(ordinal)
  const fileGroups = collectCanonicalFileAliasGroups(entries, expectedIdentity)
  for (const group of fileGroups) {
    for (const entry of group.entries) {
      if (entry.primaryArchiveMemberIndex !== group.primaryArchiveMemberIndex ||
        JSON.stringify(entry.archiveMemberIndices) !== JSON.stringify(group.archiveMemberIndices)) {
        fail(`Canonical file alias group annotation differs from its complete members: ${group.path}`)
      }
    }
  }
  const planned = new Map()
  const plannedCollisionKeys = new Map()
  const addDirectory = (relativePath, provenance, archiveMemberIndex = null) => {
    const collisionKey = relativePath.normalize('NFC').toLowerCase()
    const equivalent = plannedCollisionKeys.get(collisionKey)
    if (equivalent && equivalent.path !== relativePath) {
      fail(`Case- or normalization-colliding planned output path: ${equivalent.path} / ${relativePath}`)
    }
    const existing = planned.get(relativePath)
    if (existing?.type === 'file') fail(`Planned output directory conflicts with a file: ${relativePath}`)
    if (existing?.provenance === 'archive-explicit' && provenance === 'archive-explicit') {
      fail(`Duplicate explicit output directory: ${relativePath}`)
    }
    if (!existing || provenance === 'archive-explicit') {
      const record = { path: relativePath, type: 'directory', bytes: 0, provenance, archiveMemberIndex }
      planned.set(relativePath, record)
      plannedCollisionKeys.set(collisionKey, record)
    }
  }
  addDirectory(ordinalRoot, 'artifact-ordinal-root')
  for (const entry of entries.filter((candidate) => candidate.type === 'directory')) {
    const parts = entry.path.split('/')
    for (let depth = 1; depth <= parts.length; depth++) {
      addDirectory(`${ordinalRoot}/${parts.slice(0, depth).join('/')}`, 'synthesized-ancestor')
    }
    const outputPath = `${ordinalRoot}/${entry.path}`
    addDirectory(outputPath, 'archive-explicit', entry.archiveMemberIndex)
  }
  for (const group of fileGroups) {
    const parts = group.path.split('/')
    for (let depth = 1; depth < parts.length; depth++) {
      addDirectory(`${ordinalRoot}/${parts.slice(0, depth).join('/')}`, 'synthesized-ancestor')
    }
    const outputPath = `${ordinalRoot}/${group.path}`
    const collisionKey = outputPath.normalize('NFC').toLowerCase()
    const equivalent = plannedCollisionKeys.get(collisionKey)
    if (equivalent && equivalent.path !== outputPath) {
      fail(`Case- or normalization-colliding planned output path: ${equivalent.path} / ${outputPath}`)
    }
    if (planned.has(outputPath)) fail(`Planned output file conflicts with an existing path: ${outputPath}`)
    const record = {
      path: outputPath,
      type: 'file',
      bytes: group.bytes,
      sha256: group.sha256,
      provenance: 'archive-explicit',
      archiveMemberIndex: group.primaryArchiveMemberIndex,
      archiveMemberIndices: [...group.archiveMemberIndices]
    }
    planned.set(outputPath, record)
    plannedCollisionKeys.set(collisionKey, record)
  }
  return [...planned.values()].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
}

function selectPackageOutputEntries(entries, files, ordinal, expectedIdentity) {
  if (!Array.isArray(files)) fail('Extraction package output inventory is missing')
  assertEntryArchiveRootConsistency(entries, expectedIdentity)
  const groups = collectCanonicalFileAliasGroups(entries, expectedIdentity)
  const ordinalRoot = packageDirectoryName(ordinal)
  const fileRecords = files.filter((record) => record?.type === 'file')
  const filesByPath = new Map(fileRecords.map((record) => [record.path, record]))
  if (filesByPath.size !== fileRecords.length || fileRecords.length !== groups.length) {
    fail('Extraction file alias inventory count or uniqueness differs from the complete archive')
  }
  for (const group of groups) {
    for (const entry of group.entries) {
      if (entry.primaryArchiveMemberIndex !== group.primaryArchiveMemberIndex ||
        JSON.stringify(entry.archiveMemberIndices) !== JSON.stringify(group.archiveMemberIndices)) {
        fail(`Reparsed file alias group annotation differs from its complete members: ${group.path}`)
      }
    }
    const outputPath = `${ordinalRoot}/${group.path}`
    const record = filesByPath.get(outputPath)
    const hasExpectedSchema = record && typeof record === 'object' &&
      Object.keys(record).sort().join(',') === ['archiveMemberIndex', 'archiveMemberIndices', 'bytes', 'path', 'provenance', 'sha256', 'type',
        ...(Object.hasOwn(record, 'licenseOrNotice') ? ['licenseOrNotice'] : [])].sort().join(',')
    if (!hasExpectedSchema || record.provenance !== 'archive-explicit' || record.bytes !== group.bytes ||
      record.sha256 !== group.sha256 || record.archiveMemberIndex !== group.primaryArchiveMemberIndex ||
      JSON.stringify(record.archiveMemberIndices) !== JSON.stringify(group.archiveMemberIndices) ||
      (Object.hasOwn(record, 'licenseOrNotice') && typeof record.licenseOrNotice !== 'boolean')) {
      fail(`Extraction file alias provenance differs from its complete archive group: ${outputPath}`)
    }
  }
  const explicitDirectories = files.filter((record) => record?.type === 'directory' && record.provenance === 'archive-explicit')
  const archiveDirectories = entries.filter((entry) => entry.type === 'directory')
  if (explicitDirectories.length !== archiveDirectories.length) fail('Extraction explicit-directory inventory differs from the archive')
  for (const entry of archiveDirectories) {
    const record = filesByPath.get(`${ordinalRoot}/${entry.path}`) || files.find((candidate) => candidate.path === `${ordinalRoot}/${entry.path}`)
    if (!record || record.type !== 'directory' || record.provenance !== 'archive-explicit' ||
      record.archiveMemberIndex !== entry.archiveMemberIndex) {
      fail(`Extraction directory provenance differs from the archive: ${entry.path}`)
    }
  }
  return groups.map((group) => group.entries.find((entry) => entry.archiveMemberIndex === group.primaryArchiveMemberIndex))
}

function assertInventoryMatches(expected, actual, label) {
  const expectedByPath = new Map(expected.map((record) => [record.path, record]))
  const actualByPath = new Map(actual.map((record) => [record.path, record]))
  if (expectedByPath.size !== expected.length || actualByPath.size !== actual.length || expectedByPath.size !== actualByPath.size) {
    fail(`${label} path count or uniqueness differs from its complete plan`)
  }
  for (const [relativePath, planned] of expectedByPath) {
    const measured = actualByPath.get(relativePath)
    if (!measured || planned.type !== measured.type || planned.bytes !== measured.bytes || planned.sha256 !== measured.sha256 ||
      JSON.stringify(planned.identity) !== JSON.stringify(measured.identity)) {
      fail(`${label} path/type/identity/digest mismatch: ${relativePath}`)
    }
  }
}

const supportedSpdxLicenseIds = new Set([
  '0BSD', 'AGPL-3.0-only', 'AGPL-3.0-or-later', 'Apache-2.0', 'Artistic-2.0', 'BSD-2-Clause', 'BSD-3-Clause',
  'BSL-1.0', 'CC-BY-4.0', 'CC-BY-SA-4.0', 'CC0-1.0', 'EPL-2.0', 'EUPL-1.2', 'GPL-2.0-only',
  'GPL-2.0-or-later', 'GPL-3.0-only', 'GPL-3.0-or-later', 'ISC', 'LGPL-2.0-only', 'LGPL-2.1-only',
  'LGPL-2.1-or-later', 'LGPL-3.0-only', 'LGPL-3.0-or-later', 'MIT', 'MPL-2.0', 'OFL-1.1',
  'PostgreSQL', 'Python-2.0', 'Ruby', 'Unlicense', 'WTFPL', 'Zlib'
])
const supportedSpdxExceptionIds = new Set([
  'Autoconf-exception-3.0', 'Bison-exception-2.2', 'Classpath-exception-2.0', 'GCC-exception-3.1',
  'Linux-syscall-note', 'LLVM-exception'
])

function parseSpdxExpression(expression) {
  if (typeof expression !== 'string' || expression.length === 0 || expression.length > 512 || expression !== expression.trim()) {
    licensePolicyFail('unsupported-declaration', 'Package license metadata is not a bounded supported SPDX string')
  }
  if (/^SEE LICENSE IN ([A-Za-z0-9._+/-]+)$/.test(expression)) {
    licensePolicyFail('unresolved-license-reference', 'SEE LICENSE IN requires separate per-artifact license review and is not supported by this acquisition source')
  }
  const tokens = expression.match(/\(|\)|[A-Za-z0-9][A-Za-z0-9.+-]*/g) || []
  if (tokens.join('') !== expression.replace(/\s+/g, '')) licensePolicyFail('unsupported-declaration', `Unsupported SPDX license expression: ${expression}`)
  let position = 0
  const parsePrimary = () => {
    if (tokens[position] === '(') {
      position++
      parseOr()
      if (tokens[position] !== ')') licensePolicyFail('invalid-declaration', `Unbalanced SPDX license expression: ${expression}`)
      position++
      return
    }
    const identifier = tokens[position]
    if (!identifier || ['AND', 'OR', 'WITH', ')'].includes(identifier) || identifier === 'UNLICENSED' || identifier === 'NONE' || identifier === 'NOASSERTION') {
      licensePolicyFail('invalid-declaration', `Invalid SPDX license identifier in ${expression}`)
    }
    if (!supportedSpdxLicenseIds.has(identifier)) licensePolicyFail('unsupported-license-identifier', `Unsupported SPDX license identifier in the frozen subset: ${identifier}`)
    position++
    if (tokens[position] === 'WITH') {
      position++
      const exception = tokens[position]
      if (!exception || ['AND', 'OR', 'WITH', ')'].includes(exception)) licensePolicyFail('invalid-declaration', `Invalid SPDX exception in ${expression}`)
      if (!supportedSpdxExceptionIds.has(exception)) licensePolicyFail('unsupported-exception-identifier', `Unsupported SPDX exception identifier in the frozen subset: ${exception}`)
      position++
    }
  }
  const parseAnd = () => {
    parsePrimary()
    while (tokens[position] === 'AND') { position++; parsePrimary() }
  }
  const parseOr = () => {
    parseAnd()
    while (tokens[position] === 'OR') { position++; parseAnd() }
  }
  parseOr()
  if (position !== tokens.length) licensePolicyFail('invalid-declaration', `Trailing token in SPDX license expression: ${expression}`)
  return { kind: 'spdx', expression }
}

function declaredLicense(packageJson, registryMetadata) {
  let candidate = packageJson.license
  let source = 'packageJson.license'
  if (candidate === undefined || candidate === null) { candidate = packageJson.licenses; source = 'packageJson.licenses' }
  if (candidate === undefined || candidate === null) { candidate = registryMetadata.license; source = 'registryMetadata.license' }
  const raw = candidate
  if (Array.isArray(candidate)) {
    if (!candidate.length || candidate.some((entry) => !entry || typeof entry !== 'object' || Array.isArray(entry) || typeof entry.type !== 'string')) {
      licensePolicyFail('invalid-declaration', `Package license array is malformed: ${packageJson.name}`)
    }
    candidate = candidate.map((entry) => entry.type).join(' OR ')
  }
  if (typeof candidate !== 'string') licensePolicyFail('missing-declaration', `Package license metadata is missing or unsupported: ${packageJson.name}`)
  const parsed = parseSpdxExpression(candidate)
  return { source, raw, text: candidate, parsed, status: 'SUPPORTED_SUBSET' }
}

function isLicenseOrNoticePath(relativePath) {
  const basename = path.posix.basename(relativePath)
  return /^(?:license|copying|notice)(?:[._ -][A-Za-z0-9._ -]+)?$|^third[._ -]?party(?:[._ -]?notices?)(?:\.[A-Za-z0-9._-]+)?$/i.test(basename)
}

function inspectLicenseText(entries) {
  const licenseFiles = entries.filter((entry) => entry.type === 'file' && isLicenseOrNoticePath(entry.path))
  const issues = []
  if (!licenseFiles.length) issues.push({ code: 'missing-license-notice-text', message: 'Package archive contains no license/notice text' })
  const memberIndices = new Set()
  const texts = licenseFiles.map((entry) => {
    if (!Number.isSafeInteger(entry.archiveMemberIndex) || entry.archiveMemberIndex < 0 || memberIndices.has(entry.archiveMemberIndex)) {
      fail(`License/notice archive-member index is missing or duplicated: ${entry.path}`)
    }
    memberIndices.add(entry.archiveMemberIndex)
    if (entry.bytes > licenseTextByteLimit) fail(`License/notice text exceeds its per-file inspection bound: ${entry.path}`)
    const evidence = { path: entry.path, archiveMemberIndex: entry.archiveMemberIndex,
      bytes: entry.bytes, sha256: hash(entry.data, 'sha256'), utf8: null }
    try { evidence.utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(entry.data) } catch {
      issues.push({ code: 'invalid-utf8-license-notice', path: entry.path, message: 'License/notice is not strict UTF-8 text' })
      return evidence
    }
    if (!evidence.utf8.trim()) issues.push({ code: 'empty-license-notice-text', path: entry.path, message: 'License/notice text is empty' })
    return evidence
  })
  return { texts, issues }
}

function verifyLicenseText(entries) {
  const licenseFiles = entries.filter((entry) => entry.type === 'file' && entry.bytes > 0 &&
    isLicenseOrNoticePath(entry.path))
  if (!licenseFiles.length) fail('Package archive contains no non-empty license/notice text')
  const memberIndices = new Set()
  for (const entry of licenseFiles) {
    if (!Number.isSafeInteger(entry.archiveMemberIndex) || entry.archiveMemberIndex < 0 || memberIndices.has(entry.archiveMemberIndex)) {
      fail(`License/notice archive-member index is missing or duplicated: ${entry.path}`)
    }
    memberIndices.add(entry.archiveMemberIndex)
    let text
    try { text = new TextDecoder('utf-8', { fatal: true }).decode(entry.data) } catch { fail(`License/notice is not strict UTF-8 text: ${entry.path}`) }
    if (!text.trim()) fail(`License/notice text is empty: ${entry.path}`)
  }
  return licenseFiles.map((entry) => ({ path: entry.path, archiveMemberIndex: entry.archiveMemberIndex }))
}

function assessLicense(packageJson, registryMetadata, entries, { inspectionOnly = false } = {}) {
  let declaration
  const issues = []
  if (!inspectionOnly) {
    declaration = declaredLicense(packageJson, registryMetadata)
    const texts = verifyLicenseText(entries)
    return { declaration, texts, issues }
  }
  try { declaration = declaredLicense(packageJson, registryMetadata) } catch (error) {
    if (!(error instanceof LicensePolicyError)) throw error
    issues.push({ code: error.code, message: error.message })
    declaration = {
      source: packageJson.license != null ? 'packageJson.license' : packageJson.licenses != null ? 'packageJson.licenses' : 'registryMetadata.license',
      raw: packageJson.license ?? packageJson.licenses ?? registryMetadata.license ?? null,
      text: null,
      parsed: null,
      status: 'UNRESOLVED'
    }
  }
  const textAssessment = inspectLicenseText(entries)
  issues.push(...textAssessment.issues)
  return { declaration, texts: textAssessment.texts, issues }
}

function assertUniqueJsonKeys(text, label) {
  let position = 0
  const skipSpace = () => { while (/[\u0009\u000a\u000d\u0020]/.test(text[position] || '')) position++ }
  const parseStringToken = () => {
    const start = position
    if (text[position++] !== '"') fail(`Malformed JSON string in ${label}`)
    while (position < text.length) {
      const char = text[position++]
      if (char === '"') {
        try { return JSON.parse(text.slice(start, position)) } catch { fail(`Malformed JSON string in ${label}`) }
      }
      if (char === '\\') {
        if (position >= text.length) fail(`Truncated JSON escape in ${label}`)
        const escaped = text[position++]
        if (escaped === 'u') {
          const hex = text.slice(position, position + 4)
          if (!/^[0-9A-Fa-f]{4}$/.test(hex)) fail(`Malformed JSON Unicode escape in ${label}`)
          position += 4
        } else if (!'"\\/bfnrt'.includes(escaped)) fail(`Malformed JSON escape in ${label}`)
      } else if (char < ' ') fail(`Control character in JSON string in ${label}`)
    }
    fail(`Unterminated JSON string in ${label}`)
  }
  const parseValue = (depth = 0) => {
    if (depth > 128) fail(`JSON nesting exceeds the validation bound in ${label}`)
    skipSpace()
    const char = text[position]
    if (char === '"') { parseStringToken(); return }
    if (char === '{') {
      position++
      skipSpace()
      const keys = new Set()
      if (text[position] === '}') { position++; return }
      while (true) {
        skipSpace()
        if (text[position] !== '"') fail(`Expected JSON object key in ${label}`)
        const key = parseStringToken()
        if (keys.has(key)) fail(`Duplicate JSON object key ${key} in ${label}`)
        keys.add(key)
        skipSpace()
        if (text[position++] !== ':') fail(`Expected JSON colon in ${label}`)
        parseValue(depth + 1)
        skipSpace()
        const separator = text[position++]
        if (separator === '}') return
        if (separator !== ',') fail(`Expected JSON object separator in ${label}`)
      }
    }
    if (char === '[') {
      position++
      skipSpace()
      if (text[position] === ']') { position++; return }
      while (true) {
        parseValue(depth + 1)
        skipSpace()
        const separator = text[position++]
        if (separator === ']') return
        if (separator !== ',') fail(`Expected JSON array separator in ${label}`)
      }
    }
    const rest = text.slice(position)
    const number = rest.match(/^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/)
    if (number) { position += number[0].length; return }
    for (const literal of ['true', 'false', 'null']) {
      if (rest.startsWith(literal)) { position += literal.length; return }
    }
    fail(`Invalid JSON value in ${label}`)
  }
  parseValue()
  skipSpace()
  if (position !== text.length) fail(`Trailing data in ${label}`)
}

function manifestJson(bytes, label) {
  let text
  try { text = new TextDecoder('utf-8', { fatal: true }).decode(bytes) } catch { fail(`${label} is not strict UTF-8 JSON`) }
  assertUniqueJsonKeys(text, label)
  try { return JSON.parse(text) } catch { fail(`${label} is not valid JSON`) }
}

async function validatePnpmPinSource() {
  const bytes = await readBoundedLocal(safePath(pnpmPinSource), pnpmPinSourceByteLimit, 'Authenticated pnpm metadata pin')
  if (hash(bytes, 'sha256') !== pnpmPinSourceSha256) fail('Authenticated pnpm metadata pin evidence changed')
  const pin = manifestJson(bytes, 'Authenticated pnpm metadata pin')
  if (pin.kind !== 'ROOT_OBSERVED_OFFICIAL_REGISTRY_METADATA_PIN_NOT_ARCHIVE_PROOF' || pin.name !== 'pnpm' ||
    pin.version !== pnpmVersion || pin.metadataSource !== `${registryOrigin}/pnpm/${pnpmVersion}` ||
    pin.integrity !== pnpmIntegrity || pin.tarball !== pnpmTarball) {
    fail('Authenticated pnpm metadata pin does not match the explicit package-manager SRI')
  }
  return pin
}

async function ensureOutputDirectories(base, relativeParts) {
  let current = base
  let currentIdentity
  for (const segment of relativeParts) {
    if (!segment || segment === '.' || segment === '..' || /[<>:"|?*\u0000-\u001f]/.test(segment) || /[. ]$/.test(segment)) {
      fail(`Unsafe output directory segment: ${segment}`)
    }
    current = path.join(current, segment)
    const existing = await assertPathChain(current, { allowMissingLeaf: true })
    if (!existing.exists) {
      currentIdentity = await makeDirectoryNew(current)
    } else {
      if (!existing.info.isDirectory()) fail(`Output directory collides with a file: ${current}`)
      currentIdentity = fileIdentityRecord(existing.info, current)
    }
  }
  return { path: current, identity: currentIdentity }
}

async function inventoryOutputTree(destinationRoot) {
  const records = []
  let expandedBytes = 0
  const visit = async (absolute, relativePath) => {
    const current = await assertPathChain(absolute)
    assertPlainPathInfo(current.info, absolute)
    const identity = fileIdentityRecord(current.info, absolute)
    if (current.info.isDirectory()) {
      records.push({ path: relativePath, type: 'directory', bytes: 0, identity })
      if (records.length > expandedEntryCountLimit) fail('Final output tree-entry bound exceeded')
      const names = await readdir(absolute)
      names.sort((left, right) => left < right ? -1 : left > right ? 1 : 0)
      for (const name of names) await visit(path.join(absolute, name), `${relativePath}/${name}`)
      return
    }
    if (!current.info.isFile()) fail(`Unsupported output tree entry type: ${absolute}`)
    const bytes = await readBoundedLocal(absolute, perArchiveExpandedByteLimit, `Final extracted output ${relativePath}`)
    expandedBytes += bytes.byteLength
    if (!Number.isSafeInteger(expandedBytes) || expandedBytes > aggregateExpandedByteLimit) {
      fail('Final output tree exceeds the aggregate expanded-byte bound')
    }
    records.push({ path: relativePath, type: 'file', bytes: bytes.byteLength, sha256: hash(bytes, 'sha256'), identity })
    if (records.length > expandedEntryCountLimit) fail('Final output tree-entry bound exceeded')
  }
  await visit(destinationRoot, 'unpacked')
  return records.sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0)
}

function fixtureMustFail(label, action) {
  let failed = false
  try { action() } catch { failed = true }
  if (!failed) fail(`Source fixture unexpectedly accepted: ${label}`)
}

function fixtureMustFailWith(label, expectedMessage, action) {
  let observedMessage
  try { action() } catch (error) { observedMessage = error?.message }
  if (observedMessage !== expectedMessage) {
    fail(`Source fixture did not fail for the expected reason: ${label}`)
  }
}

function fixtureTarHeader(name, dataLength, type = '0', headerPrefix = '', layoutFixture = {}) {
  const header = Buffer.alloc(512)
  const nameBytes = Buffer.from(name, 'ascii')
  const prefixBytes = Buffer.from(headerPrefix, 'ascii')
  if (nameBytes.length > 100 || prefixBytes.length > 155) fail('Fixture tar path exceeds ustar name/prefix fields')
  nameBytes.copy(header, 0)
  prefixBytes.copy(header, 345)
  Buffer.from('0000644\0', 'ascii').copy(header, 100)
  Buffer.from('0000000\0', 'ascii').copy(header, 108)
  Buffer.from('0000000\0', 'ascii').copy(header, 116)
  Buffer.from(`${dataLength.toString(8).padStart(11, '0')}\0`, 'ascii').copy(header, 124)
  Buffer.from('00000000000\0', 'ascii').copy(header, 136)
  header.fill(0x20, 148, 156)
  header[156] = type.charCodeAt(0)
  Buffer.from('ustar\0', 'ascii').copy(header, 257)
  Buffer.from('00', 'ascii').copy(header, 263)
  if (layoutFixture.shortPrefix) {
    if (prefixBytes.length > 130) fail('Fixture short USTAR prefix exceeds 130 bytes')
    header.fill(0, 345, 500)
    prefixBytes.copy(header, 345)
    if (layoutFixture.separator !== undefined) header[475] = layoutFixture.separator
    if (layoutFixture.mtimeHex) Buffer.from(layoutFixture.mtimeHex, 'hex').copy(header, 476)
    if (layoutFixture.ctimeHex) Buffer.from(layoutFixture.ctimeHex, 'hex').copy(header, 488)
    if (layoutFixture.tailHex) Buffer.from(layoutFixture.tailHex, 'hex').copy(header, 500)
  }
  if (layoutFixture.magic !== undefined) Buffer.from(layoutFixture.magic, 'ascii').copy(header, 257)
  if (layoutFixture.version !== undefined) Buffer.from(layoutFixture.version, 'ascii').copy(header, 263)
  let checksum = 0
  for (const byte of header) checksum += byte
  Buffer.from(`${checksum.toString(8).padStart(6, '0')}\0 `, 'ascii').copy(header, 148)
  return header
}

function fixtureTarRaw(entries, trailingBlocks = 2) {
  const chunks = []
  for (const entry of entries) {
    const data = Buffer.from(entry.data || '', 'utf8')
    chunks.push(fixtureTarHeader(entry.headerName || entry.path, data.length, entry.type || '0', entry.headerPrefix || '', entry.headerLayoutFixture || {}))
    chunks.push(data)
    const padding = (512 - (data.length % 512)) % 512
    if (padding) chunks.push(Buffer.alloc(padding))
  }
  chunks.push(Buffer.alloc(512 * trailingBlocks))
  return Buffer.concat(chunks)
}

function fixtureTar(entries, trailingBlocks = 2) {
  return gzipSync(fixtureTarRaw(entries, trailingBlocks))
}

function fixturePaxRecord(key, value, newline = true) {
  const body = Buffer.from(`${key}=${value}${newline ? '\n' : ''}`, 'utf8')
  let length = body.length + 2
  while (true) {
    const next = body.length + String(length).length + 1
    if (next === length) break
    length = next
  }
  return Buffer.concat([Buffer.from(`${length} `, 'ascii'), body])
}

function fixturePaxRecords(records) {
  return Buffer.concat(records.map(([key, value]) => fixturePaxRecord(key, value)))
}

function fixturePaxRawRecord(key, rawValue) {
  const body = Buffer.concat([Buffer.from(`${key}=`, 'ascii'), rawValue, Buffer.from('\n', 'ascii')])
  let length = body.length + 2
  while (true) {
    const next = body.length + String(length).length + 1
    if (next === length) break
    length = next
  }
  return Buffer.concat([Buffer.from(`${length} `, 'ascii'), body])
}

function runSourceFixtures() {
  const sri = `sha512-${'A'.repeat(86)}==`
  const lock = [
    "lockfileVersion: '9.0'", 'importers:', '  .:', '    dependencies:', "      '@floating-ui/vue':", '        specifier: 1.1.11',
    '        version: 1.1.11(vue@3.5.41(typescript@6.0.3))', '      local:', '        specifier: workspace:*',
    '        version: link:packages/local', '  packages/local:', '    dependencies:', '      alias:', '        specifier: npm:real@1.2.3',
    '        version: npm:real@1.2.3', '    optionalDependencies:', '      optional:', '        specifier: 2.0.0', '        version: 2.0.0',
    'packages:', "  '@floating-ui/vue@1.1.11':", `    resolution: {integrity: ${sri}}`, '  vue@3.5.41:',
    `    resolution: {integrity: ${sri}}`, '  typescript@6.0.3:', `    resolution: {integrity: ${sri}}`, '  real@1.2.3:',
    `    resolution: {integrity: ${sri}}`, '  optional@2.0.0:', `    resolution: {integrity: ${sri}}`, 'snapshots:',
    "  '@floating-ui/vue@1.1.11(vue@3.5.41(typescript@6.0.3))':", '    dependencies:',
    '      vue: 3.5.41(typescript@6.0.3)', '  vue@3.5.41(typescript@6.0.3):', '    dependencies:',
    '      typescript: 6.0.3', '  typescript@6.0.3: {}', '  real@1.2.3: {}', '  optional@2.0.0: {}', ''
  ].join('\n')
  const floatingPeerSnapshot = '@floating-ui/vue@1.1.11(vue@3.5.41(typescript@6.0.3))'
  const qualifiedVueSnapshot = 'vue@3.5.41(typescript@6.0.3)'
  const positiveClosure = collectClosure(lock)
  const expectedPositiveSnapshots = [floatingPeerSnapshot, 'optional@2.0.0', 'real@1.2.3', 'typescript@6.0.3', qualifiedVueSnapshot]
  const expectedPositiveArtifacts = ['@floating-ui/vue@1.1.11', 'optional@2.0.0', 'real@1.2.3', 'typescript@6.0.3', 'vue@3.5.41']
  const expectedPositiveMappings = [
    { snapshot: floatingPeerSnapshot, registryLocator: '@floating-ui/vue@1.1.11' },
    { snapshot: 'optional@2.0.0', registryLocator: 'optional@2.0.0' },
    { snapshot: 'real@1.2.3', registryLocator: 'real@1.2.3' },
    { snapshot: 'typescript@6.0.3', registryLocator: 'typescript@6.0.3' },
    { snapshot: qualifiedVueSnapshot, registryLocator: 'vue@3.5.41' }
  ]
  if (JSON.stringify(positiveClosure.snapshots) !== JSON.stringify(expectedPositiveSnapshots) ||
    JSON.stringify(positiveClosure.artifacts.map((artifact) => artifact.locator)) !== JSON.stringify(expectedPositiveArtifacts) ||
    JSON.stringify(positiveClosure.reconciliation.snapshotResolutions) !== JSON.stringify(expectedPositiveMappings) ||
    positiveClosure.reconciliation.reachableSnapshots !== 5 ||
    positiveClosure.reconciliation.uniqueSnapshotRegistryResolutions !== 5 ||
    positiveClosure.reconciliation.workspaceImporters !== 2 ||
    JSON.stringify(positiveClosure.reconciliation.reachableImporterPaths) !== JSON.stringify(['.', 'packages/local'])) {
    fail('Nested peer/workspace/alias/optional closure fixture did not reconcile')
  }
  const floatingDependencyBlock = `  '${floatingPeerSnapshot}':\n    dependencies:\n      vue: 3.5.41(typescript@6.0.3)`
  const qualifiedVueDependencyBlock = `  ${qualifiedVueSnapshot}:\n    dependencies:\n      typescript: 6.0.3`
  if (!lock.includes(floatingDependencyBlock) || !lock.includes(qualifiedVueDependencyBlock)) {
    fail('Peer-label-only control could not isolate the actual resolved fixture edges')
  }
  const peerLabelOnlyLock = lock
    .replace(floatingDependencyBlock, `  '${floatingPeerSnapshot}': {}`)
    .replace(qualifiedVueDependencyBlock, `  ${qualifiedVueSnapshot}: {}`)
  if (!peerLabelOnlyLock.includes(`version: 1.1.11(vue@3.5.41(typescript@6.0.3))`) ||
    !peerLabelOnlyLock.includes(`  '${floatingPeerSnapshot}': {}`) ||
    !peerLabelOnlyLock.includes(`  ${qualifiedVueSnapshot}: {}`) ||
    !peerLabelOnlyLock.includes('  typescript@6.0.3: {}')) {
    fail('Peer-label-only control did not preserve nested labels and unreachable snapshot records')
  }
  const peerLabelOnlyClosure = collectClosure(peerLabelOnlyLock)
  const expectedLabelOnlySnapshots = [floatingPeerSnapshot, 'optional@2.0.0', 'real@1.2.3']
  const expectedLabelOnlyArtifacts = ['@floating-ui/vue@1.1.11', 'optional@2.0.0', 'real@1.2.3']
  const expectedLabelOnlyMappings = [
    { snapshot: floatingPeerSnapshot, registryLocator: '@floating-ui/vue@1.1.11' },
    { snapshot: 'optional@2.0.0', registryLocator: 'optional@2.0.0' },
    { snapshot: 'real@1.2.3', registryLocator: 'real@1.2.3' }
  ]
  if (JSON.stringify(peerLabelOnlyClosure.snapshots) !== JSON.stringify(expectedLabelOnlySnapshots) ||
    JSON.stringify(peerLabelOnlyClosure.artifacts.map((artifact) => artifact.locator)) !== JSON.stringify(expectedLabelOnlyArtifacts) ||
    JSON.stringify(peerLabelOnlyClosure.reconciliation.snapshotResolutions) !== JSON.stringify(expectedLabelOnlyMappings) ||
    peerLabelOnlyClosure.reconciliation.reachableSnapshots !== 3 ||
    peerLabelOnlyClosure.reconciliation.uniqueSnapshotRegistryResolutions !== 3 ||
    peerLabelOnlyClosure.reconciliation.workspaceImporters !== 2 ||
    JSON.stringify(peerLabelOnlyClosure.reconciliation.reachableImporterPaths) !== JSON.stringify(['.', 'packages/local'])) {
    fail('Peer-context labels alone invented a resolved dependency edge')
  }
  const vitest20_9 = '4.1.10(@types/node@25.9.5)(@vitest/coverage-v8@4.1.10)(@vitest/ui@4.1.10)(happy-dom@20.9.0)(jsdom@29.1.1)(vite@8.2.1(@types/node@25.9.5)(esbuild@0.28.1)(jiti@2.7.0)(terser@5.49.0)(tsx@4.23.1)(yaml@2.9.0))'
  const vitest20_10_6 = '4.1.10(@types/node@25.9.5)(@vitest/coverage-v8@4.1.10)(@vitest/ui@4.1.10)(happy-dom@20.10.6)(jsdom@29.1.1)(vite@8.2.1(@types/node@25.9.5)(esbuild@0.28.1)(jiti@2.7.0)(terser@5.49.0)(tsx@4.23.1)(yaml@2.9.0))'
  const vitestContextLock = [
    "lockfileVersion: '9.0'", 'importers:', '  .:', '    dependencies:', "      '@vitest/coverage-v8':", '        specifier: 4.1.10',
    '        version: 4.1.10(vitest@4.1.10)', "      '@vitest/ui':", '        specifier: 4.1.10',
    '        version: 4.1.10(vitest@4.1.10)', "      '@comfyorg/object-info-parser':", '        specifier: workspace:*',
    '        version: link:packages/object-info-parser', '  packages/object-info-parser:', '    devDependencies:',
    '      vitest:', '        specifier: 4.1.10', `        version: ${vitest20_10_6}`, 'packages:', "  '@vitest/coverage-v8@4.1.10':",
    `    resolution: {integrity: ${sri}}`, "  '@vitest/ui@4.1.10':", `    resolution: {integrity: ${sri}}`,
    '  vitest@4.1.10:', `    resolution: {integrity: ${sri}}`, '  happy-dom@20.9.0:',
    `    resolution: {integrity: ${sri}}`, '  happy-dom@20.10.6:', `    resolution: {integrity: ${sri}}`,
    'snapshots:', "  '@vitest/coverage-v8@4.1.10(vitest@4.1.10)':", '    dependencies:',
    `      vitest: ${vitest20_9}`, "  '@vitest/ui@4.1.10(vitest@4.1.10)':", '    dependencies:',
    `      vitest: ${vitest20_9}`, `  vitest@${vitest20_9}:`, '    dependencies:',
    '      happy-dom: 20.9.0', `  vitest@${vitest20_10_6}:`, '    dependencies:',
    '      happy-dom: 20.10.6', '  happy-dom@20.9.0: {}', '  happy-dom@20.10.6: {}', ''
  ].join('\n')
  const vitestClosure = collectClosure(vitestContextLock)
  const vitestContexts = vitestClosure.snapshots.filter((snapshot) => snapshot.startsWith('vitest@4.1.10('))
  const vitestRegistryMappings = vitestClosure.reconciliation.snapshotResolutions
    .filter(({ snapshot }) => snapshot.startsWith('vitest@4.1.10('))
  if (vitestContexts.length !== 2 ||
    !vitestContexts.includes(`vitest@${vitest20_9}`) ||
    !vitestContexts.includes(`vitest@${vitest20_10_6}`) ||
    vitestClosure.snapshots.includes('vitest@4.1.10') ||
    vitestRegistryMappings.length !== 2 || vitestRegistryMappings.some(({ registryLocator }) => registryLocator !== 'vitest@4.1.10') ||
    vitestClosure.reconciliation.reachableSnapshots !== 6 ||
    vitestClosure.reconciliation.uniqueSnapshotRegistryResolutions !== 5 ||
    vitestClosure.artifacts.length !== 5) {
    fail('Positive vitest two-context resolved-edge fixture did not preserve both contexts')
  }
  const ambiguousVitestLock = [
    "lockfileVersion: '9.0'", 'importers:', '  .:', '    dependencies:', '      coverage:', '        specifier: 1.0.0',
    '        version: 1.0.0', 'packages:', '  coverage@1.0.0:', `    resolution: {integrity: ${sri}}`, 'snapshots:',
    '  coverage@1.0.0:', '    dependencies:', '      vitest: 4.1.10', '  vitest@4.1.10(happy-dom@15.0.0): {}',
    '  vitest@4.1.10(happy-dom@20.0.0): {}', ''
  ].join('\n')
  fixtureMustFail('genuinely unresolved ambiguous dependency', () => collectClosure(ambiguousVitestLock))
  if (stripPeerSuffix('@floating-ui/vue@1.1.11(vue@3.5.41(typescript@6.0.3))') !== '@floating-ui/vue@1.1.11') {
    fail('Balanced nested peer suffix fixture did not retain the exact resolution locator')
  }
  const aliasIdentity = artifactIdentity('alias@npm:real@1.2.3')
  if (aliasIdentity.name !== 'real' || aliasIdentity.version !== '1.2.3') fail('Npm alias registry identity fixture did not resolve the true package')
  fixtureMustFail('malformed nested peer suffix', () => stripPeerSuffix('pkg@1.0.0(peer@2.0.0'))
  fixtureMustFail('unmatched nested peer suffix close', () => stripPeerSuffix('pkg@1.0.0)'))
  fixtureMustFail('missing graph edge', () => collectClosure(lock.replace('        version: 2.0.0', '        version: 9.9.9')))
  fixtureMustFail('duplicate importer resolved version', () => parseLock(lock.replace(
    '        version: 2.0.0',
    '        version: 2.0.0\n        version: 2.0.0'
  )))
  fixtureMustFail('duplicate package resolution record', () => parseLock(lock.replace(
    `    resolution: {integrity: ${sri}}`,
    `    resolution: {integrity: ${sri}}\n    resolution: {integrity: ${sri}}`
  )))
  fixtureMustFail('duplicate graph edge', () => parseLock(lock.replace(
    '  optional@2.0.0: {}',
    '  optional@2.0.0:\n    dependencies:\n      child: 1.0.0\n      child: 1.0.0'
  )))
  const fixtureBytes = Buffer.from('fixture')
  const fixtureSRI = `sha512-${hash(fixtureBytes, 'sha512')}`
  const compactLockFixture = (name, version, archive, label) => {
    const integrity = `sha512-${hash(archive, 'sha512')}`
    const lock = [
      "lockfileVersion: '9.0'", 'importers:', '  .:', '    dependencies:', `      '${name}':`, `        specifier: ${version}`,
      `        version: ${version}`, 'packages:', `  '${name}@${version}':`, `    resolution: {integrity: ${integrity}}`,
      'snapshots:', `  '${name}@${version}': {}`, ''
    ].join('\n')
    const artifacts = collectClosure(lock).artifacts
    const artifact = {
      ordinal: 0, locator: `${name}@${version}`, lockIntegrity: integrity, registryIntegrity: integrity,
      registryTarball: `https://registry.npmjs.org/${name}/-/${name.slice(name.lastIndexOf('/') + 1)}-${version}.tgz`,
      archiveByteLimit: artifactByteLimit, archive: `${label}.tgz`, bytes: archive.byteLength, sha256: hash(archive, 'sha256'),
      metadata: `${label}.json`, metadataBytes: 2, metadataSha256: 'a'.repeat(64)
    }
    if (JSON.stringify(Object.keys(artifact).sort()) !== JSON.stringify([...fetchedRecordKeys].sort())) {
      fail(`${label} fixture did not retain the exact compact fetched-record schema`)
    }
    return { artifacts, artifact, identity: authenticatedExpectedArtifact(artifacts, 0, artifact, label) }
  }
  assertArtifactIntegrity(fixtureSRI, fixtureSRI, fixtureBytes, 'positive fixture')
  fixtureMustFail('registry integrity mismatch', () => assertArtifactIntegrity(fixtureSRI, `sha512-${'B'.repeat(86)}==`, fixtureBytes, 'fixture'))
  fixtureMustFail('archive integrity mismatch', () => assertArtifactIntegrity(fixtureSRI, fixtureSRI, Buffer.from('different'), 'fixture'))
  fixtureMustFail('bounded read growth', () => appendBoundedChunk([], 2, Buffer.from('x'), 2, 'fixture'))
  assertBoundedRegularFile({ isSymbolicLink: () => false, attributes: 0n, isFile: () => true, nlink: 1n, size: 2n }, 2, 'positive file fixture')
  fixtureMustFail('bounded local input size', () => assertBoundedRegularFile({ isSymbolicLink: () => false, attributes: 0n, isFile: () => true, nlink: 1n, size: 3n }, 2, 'fixture'))
  const identityStat = (dev, ino, mode = 0o100644n) => ({
    dev, ino, mode, isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false
  })
  const adjacentIdentityA = identityStat(1n, 9_007_199_254_740_992n)
  const adjacentIdentityB = identityStat(1n, 9_007_199_254_740_993n)
  if (!sameFileIdentity(adjacentIdentityA, identityStat(1n, 9_007_199_254_740_992n))) {
    fail('Exact identical BigInt filesystem identity was rejected')
  }
  if (sameFileIdentity(adjacentIdentityA, adjacentIdentityB)) fail('Adjacent inodes above 2^53 collapsed to one identity')
  const exactIdentity = fileIdentityRecord(adjacentIdentityB, 'positive exact identity fixture')
  if (exactIdentity.ino !== '9007199254740993') fail('BigInt inode was not serialized exactly as canonical decimal')
  const identityRoundTrip = JSON.parse(JSON.stringify(exactIdentity))
  if (identityRoundTrip.ino !== '9007199254740993' || BigInt(identityRoundTrip.ino) !== adjacentIdentityB.ino) {
    fail('Canonical JSON identity round-trip lost exact inode value')
  }
  fixtureMustFail('changed opened identity rejected', () => assertSameFileIdentity(adjacentIdentityA, adjacentIdentityB, 'opened fixture'))
  fixtureMustFail('changed parent identity rejected', () => assertSameFileIdentity(identityStat(4n, 8n), identityStat(4n, 9n), 'parent fixture'))
  const identityReservation = maximumFileIdentityRecord()
  const maxIdentity = fileIdentityRecord(identityStat(maxFilesystemDeviceOrInode, maxFilesystemDeviceOrInode, maxFilesystemMode), 'maximum identity fixture')
  const reservationBytes = Buffer.byteLength(JSON.stringify(identityReservation), 'utf8')
  if (JSON.stringify(maxIdentity) !== JSON.stringify(identityReservation) ||
    Buffer.byteLength(JSON.stringify(exactIdentity), 'utf8') > reservationBytes) {
    fail('Maximum-width filesystem identity reservation does not cover final serialization')
  }
  fixtureMustFail('numeric filesystem identity rejected', () => fileIdentityRecord({ dev: 1, ino: 1n, mode: 0n }, 'fixture'))
  fixtureMustFail('malformed filesystem identity rejected', () => fileIdentityRecord({ dev: '1', ino: 1n, mode: 0n }, 'fixture'))
  fixtureMustFail('filesystem identity beyond uint64 rejected', () => fileIdentityRecord({ dev: maxFilesystemDeviceOrInode + 1n, ino: 1n, mode: 0n }, 'fixture'))
  fixtureMustFail('filesystem mode beyond uint32 rejected', () => fileIdentityRecord({ dev: 1n, ino: 1n, mode: maxFilesystemMode + 1n }, 'fixture'))
  fixtureMustFail('unsafe size conversion rejected', () => boundedStatNumber(BigInt(Number.MAX_SAFE_INTEGER) + 1n, Number.MAX_SAFE_INTEGER, 'fixture'))
  fixtureMustFail('numeric size input rejected', () => boundedStatNumber(2, 2, 'fixture'))
  fixtureMustFail('negative size input rejected', () => boundedStatNumber(-1n, 2, 'fixture'))
  const iconifyFixture = { ...iconifyJsonException }
  const ordinaryArchiveFixture = { locator: 'ordinary@1.0.0', name: 'ordinary', version: '1.0.0', integrity: fixtureSRI }
  const pnpmArchiveFixture = { locator: `pnpm@${pnpmVersion}`, name: 'pnpm', version: pnpmVersion, integrity: pnpmIntegrity }
  if (archiveByteLimitFor(iconifyFixture) !== 128 * 1_048_576 ||
    assertArchiveByteLimitRecord(iconifyFixture, iconifyJsonByteLimit, iconifyJsonException.tarball, 'positive Iconify record') !== 128 * 1_048_576 ||
    archiveByteLimitFor({ ...iconifyFixture, archiveByteLimit: 1_073_741_824 }, iconifyJsonException.tarball) !== iconifyJsonByteLimit ||
    archiveByteLimitFor(ordinaryArchiveFixture) !== 64 * 1_048_576 ||
    archiveByteLimitFor(pnpmArchiveFixture) !== 64 * 1_048_576) {
    fail('Positive fixed Iconify archive cap or ordinary 64 MiB cap fixture failed')
  }
  const acquisitionFixtureArtifacts = [iconifyFixture, ordinaryArchiveFixture, pnpmArchiveFixture]
  const fetchedIconifyRecord = {
    ordinal: 0,
    locator: iconifyFixture.locator,
    lockIntegrity: iconifyFixture.integrity,
    registryIntegrity: iconifyFixture.integrity,
    registryTarball: iconifyJsonException.tarball,
    archiveByteLimit: iconifyJsonByteLimit,
    archive: `${prefix}/npm/0000-iconify.tgz`,
    bytes: 1,
    sha256: 'fixture-archive-sha256',
    metadata: `${prefix}/metadata/0000-iconify.json`,
    metadataBytes: 1,
    metadataSha256: 'fixture-metadata-sha256'
  }
  const fetchedRecordKeys = ['ordinal', 'locator', 'lockIntegrity', 'registryIntegrity', 'registryTarball', 'archiveByteLimit',
    'archive', 'bytes', 'sha256', 'metadata', 'metadataBytes', 'metadataSha256']
  if (JSON.stringify(Object.keys(fetchedIconifyRecord).sort()) !== JSON.stringify([...fetchedRecordKeys].sort())) {
    fail('Positive fetched acquisition-record fixture differs from the actual record field shape')
  }
  if (validateAcquisitionArchiveRecord(acquisitionFixtureArtifacts, 0, fetchedIconifyRecord, 'fixture preflight') !== iconifyJsonByteLimit ||
    validateAcquisitionArchiveRecord(acquisitionFixtureArtifacts, 0, fetchedIconifyRecord, 'fixture recheck') !== iconifyJsonByteLimit) {
    fail('Actual fetched Iconify record did not retain its trusted 128 MiB preflight/recheck cap')
  }
  const fetchedOrdinaryRecord = {
    ...fetchedIconifyRecord,
    ordinal: 1,
    locator: ordinaryArchiveFixture.locator,
    lockIntegrity: ordinaryArchiveFixture.integrity,
    registryIntegrity: ordinaryArchiveFixture.integrity,
    registryTarball: 'https://registry.npmjs.org/ordinary/-/ordinary-1.0.0.tgz',
    archiveByteLimit: artifactByteLimit
  }
  if (validateAcquisitionArchiveRecord(acquisitionFixtureArtifacts, 1, fetchedOrdinaryRecord, 'ordinary preflight') !== artifactByteLimit ||
    validateAcquisitionArchiveRecord(acquisitionFixtureArtifacts, 1, fetchedOrdinaryRecord, 'ordinary recheck') !== artifactByteLimit) {
    fail('Actual fetched ordinary record did not retain its trusted 64 MiB preflight/recheck cap')
  }
  fixtureMustFailWith('fetched record ordinal mismatch', 'fixture ordinal mismatch', () =>
    validateAcquisitionArchiveRecord(acquisitionFixtureArtifacts, 0, { ...fetchedIconifyRecord, ordinal: 1 }, 'fixture'))
  fixtureMustFailWith('fetched record locator mismatch', 'fixture locator mismatch', () =>
    validateAcquisitionArchiveRecord(acquisitionFixtureArtifacts, 0, { ...fetchedIconifyRecord, locator: ordinaryArchiveFixture.locator }, 'fixture'))
  fixtureMustFailWith('fetched record locked SRI mismatch', 'fixture locked SRI mismatch', () =>
    validateAcquisitionArchiveRecord(acquisitionFixtureArtifacts, 0, { ...fetchedIconifyRecord, lockIntegrity: fixtureSRI }, 'fixture'))
  fixtureMustFailWith('fetched record registry SRI mismatch', 'fixture registry SRI mismatch', () =>
    validateAcquisitionArchiveRecord(acquisitionFixtureArtifacts, 0, { ...fetchedIconifyRecord, registryIntegrity: fixtureSRI }, 'fixture'))
  fixtureMustFailWith('fetched record URL mismatch',
    'Iconify archive exception requires the exact pinned tarball URL: @iconify/json@2.2.500', () =>
      validateAcquisitionArchiveRecord(acquisitionFixtureArtifacts, 0, { ...fetchedIconifyRecord, registryTarball: `${iconifyJsonException.tarball}?unreviewed=1` }, 'fixture'))
  fixtureMustFailWith('fetched record cap mismatch', 'fixture archive byte limit differs from the fixed artifact policy', () =>
    validateAcquisitionArchiveRecord(acquisitionFixtureArtifacts, 0, { ...fetchedIconifyRecord, archiveByteLimit: artifactByteLimit }, 'fixture'))
  const packageRecordFixtureData = Buffer.from('x')
  const packageRecordFixtureArchive = parseTar(fixtureTar([{ path: 'package/example.js', data: packageRecordFixtureData }]))
  const packageRecordFixtureFiles = planPackageOutputInventory(0, packageRecordFixtureArchive.entries)
  const actualPackageIdentity = fileIdentityRecord(identityStat(7n, 10n), 'actual package fixture identity')
  const checkedPackageFixture = {
    ordinal: 0,
    artifact: fetchedIconifyRecord,
    expectedIdentity: authenticatedExpectedArtifact(acquisitionFixtureArtifacts, 0, fetchedIconifyRecord, 'fixture package'),
    archiveByteLimit: iconifyJsonByteLimit,
    archiveExpandedBytes: packageRecordFixtureArchive.archiveExpandedBytes,
    archiveRoot: packageRecordFixtureArchive.archiveRoot,
    headerLayoutSha256: headerLayoutInventorySha256(packageRecordFixtureArchive.archiveMembers),
    archiveMembersSha256: archiveMemberInventorySha256(packageRecordFixtureArchive.archiveMembers),
    packageJson: { name: iconifyFixture.name, version: iconifyFixture.version, license: 'MIT' },
    archiveMembers: packageRecordFixtureArchive.archiveMembers,
    files: packageRecordFixtureFiles
  }
  const packageFixtureIdentity = checkedPackageFixture.expectedIdentity
  fixtureMustFailWith('package reservation missing trusted identity',
    'Package at ordinal 0 authenticated lock identity is missing or malformed',
    () => assertCheckedPackageIdentity(0, fetchedIconifyRecord, undefined, checkedPackageFixture.packageJson, 'Package at ordinal 0'))
  fixtureMustFailWith('package reservation wrong trusted name',
    'Package at ordinal 0 authenticated lock identity is malformed',
    () => assertCheckedPackageIdentity(0, fetchedIconifyRecord, { ...packageFixtureIdentity, name: 'other-package' },
      checkedPackageFixture.packageJson, 'Package at ordinal 0'))
  fixtureMustFailWith('package reservation wrong trusted version',
    'Package at ordinal 0 authenticated lock identity is malformed',
    () => assertCheckedPackageIdentity(0, fetchedIconifyRecord, { ...packageFixtureIdentity, version: '0.0.0' },
      checkedPackageFixture.packageJson, 'Package at ordinal 0'))
  fixtureMustFailWith('package reservation wrong trusted ordinal',
    'Package at ordinal 0 authenticated lock identity is missing or malformed',
    () => assertCheckedPackageIdentity(0, fetchedIconifyRecord, { ...packageFixtureIdentity, ordinal: 1 },
      checkedPackageFixture.packageJson, 'Package at ordinal 0'))
  fixtureMustFailWith('package reservation wrong trusted locator', 'Package at ordinal 0 locator mismatch',
    () => assertCheckedPackageIdentity(0, fetchedIconifyRecord,
      { ...packageFixtureIdentity, locator: `${packageFixtureIdentity.locator}(fixture-peer@1.0.0)` },
      checkedPackageFixture.packageJson, 'Package at ordinal 0'))
  fixtureMustFailWith('package reservation wrong trusted SRI', 'Package at ordinal 0 locked SRI mismatch',
    () => assertCheckedPackageIdentity(0, fetchedIconifyRecord,
      { ...packageFixtureIdentity, integrity: `sha512-${'B'.repeat(86)}==` },
      checkedPackageFixture.packageJson, 'Package at ordinal 0'))
  fixtureMustFailWith('package reservation compact locator mismatch', 'Package at ordinal 0 locator mismatch',
    () => assertCheckedPackageIdentity(0, { ...fetchedIconifyRecord, locator: ordinaryArchiveFixture.locator },
      packageFixtureIdentity, checkedPackageFixture.packageJson, 'Package at ordinal 0'))
  fixtureMustFailWith('package reservation compact ordinal mismatch', 'Package at ordinal 0 acquisition ordinal mismatch',
    () => assertCheckedPackageIdentity(0, { ...fetchedIconifyRecord, ordinal: 1 }, packageFixtureIdentity,
      checkedPackageFixture.packageJson, 'Package at ordinal 0'))
  fixtureMustFailWith('package reservation compact lock SRI mismatch', 'Package at ordinal 0 locked SRI mismatch',
    () => assertCheckedPackageIdentity(0, { ...fetchedIconifyRecord, lockIntegrity: fixtureSRI }, packageFixtureIdentity,
      checkedPackageFixture.packageJson, 'Package at ordinal 0'))
  fixtureMustFailWith('package reservation compact registry SRI mismatch', 'Package at ordinal 0 registry SRI mismatch',
    () => assertCheckedPackageIdentity(0, { ...fetchedIconifyRecord, registryIntegrity: fixtureSRI }, packageFixtureIdentity,
      checkedPackageFixture.packageJson, 'Package at ordinal 0'))
  fixtureMustFailWith('package reservation manifest mismatch', 'Package at ordinal 0 package manifest identity mismatch',
    () => assertCheckedPackageIdentity(0, fetchedIconifyRecord, packageFixtureIdentity,
      { ...checkedPackageFixture.packageJson, version: '0.0.0' }, 'Package at ordinal 0'))
  const plannedPackageFixture = packageInventoryRecord(checkedPackageFixture, () => identityReservation, packageFixtureIdentity)
  const finalPackageFixture = packageInventoryRecord(checkedPackageFixture, () => actualPackageIdentity, packageFixtureIdentity)
  fixtureMustFailWith('reservation builder rejects substituted lock identity',
    'Package lock identity differs from authenticated closure at ordinal 0',
    () => packageInventoryRecord(checkedPackageFixture, () => identityReservation,
      { ...packageFixtureIdentity, locator: `${packageFixtureIdentity.locator}(fixture-peer@1.0.0)` }))
  const packageFixtureIdentities = new Map(packageRecordFixtureFiles.map((record) =>
    [`unpacked/${record.path}`, actualPackageIdentity]))
  if (JSON.stringify(plannedPackageFixture.files[0].identity) === JSON.stringify(actualPackageIdentity)) {
    fail('Package fixture did not distinguish reserved and actual filesystem identities')
  }
  assertPackageInventoryMatches([plannedPackageFixture], [finalPackageFixture], packageFixtureIdentities)
  const changedHeaderLayoutMembers = checkedPackageFixture.archiveMembers.map((member, index) => index === 0
    ? { ...member, headerLayout: { ...member.headerLayout, headerSha256: '0'.repeat(64) } } : member)
  fixtureMustFailWith('package reservation rejects header-layout tamper at whole-member guard',
    'Package archive-member provenance changed at ordinal 0',
    () => packageInventoryRecord({ ...checkedPackageFixture, archiveMembers: changedHeaderLayoutMembers },
      () => identityReservation, checkedPackageFixture.expectedIdentity))
  fixtureMustFailWith('package reservation isolates changed header-layout provenance',
    'Tar member full header bytes do not match the header digest',
    () => packageInventoryRecord({ ...checkedPackageFixture,
      archiveMembers: changedHeaderLayoutMembers,
      archiveMembersSha256: archiveMemberInventorySha256(changedHeaderLayoutMembers)
    }, () => identityReservation, checkedPackageFixture.expectedIdentity))
  const packageRecordFailure = 'Final package inventory schema or cap differs from preflight at ordinal 0'
  const missingPackageCap = { ...finalPackageFixture }
  delete missingPackageCap.archiveByteLimit
  fixtureMustFailWith('final package cap omission', packageRecordFailure, () =>
    assertPackageInventoryMatches([plannedPackageFixture], [missingPackageCap], packageFixtureIdentities))
  fixtureMustFailWith('final package cap tamper', packageRecordFailure, () =>
    assertPackageInventoryMatches([plannedPackageFixture], [{ ...finalPackageFixture, archiveByteLimit: artifactByteLimit }], packageFixtureIdentities))
  fixtureMustFailWith('unvalidated final package field', packageRecordFailure, () =>
    assertPackageInventoryMatches([plannedPackageFixture], [{ ...finalPackageFixture, unreviewed: true }], packageFixtureIdentities))
  fixtureMustFailWith('preflight package cap omission', packageRecordFailure, () => {
    const omitted = { ...plannedPackageFixture }
    delete omitted.archiveByteLimit
    assertPackageInventoryMatches([omitted], [finalPackageFixture], packageFixtureIdentities)
  })
  const policyPlan = buildPlan([iconifyFixture, ordinaryArchiveFixture], {})
  const arithmeticCapBoundary = artifactByteLimit + 1
  if (policyPlan.items[0]?.archiveByteLimit !== iconifyJsonByteLimit ||
    policyPlan.items[1]?.archiveByteLimit !== artifactByteLimit ||
    policyPlan.items[2]?.archiveByteLimit !== artifactByteLimit ||
    policyPlan.archiveLimitPolicy?.defaultBytes !== artifactByteLimit ||
    policyPlan.archiveLimitPolicy?.aggregateBytes !== aggregateArchiveByteLimit ||
    JSON.stringify(policyPlan.archiveLimitPolicy?.exception) !== JSON.stringify(iconifyJsonException) ||
    aggregateArchiveByteLimit !== 3 * 1_073_741_824 || artifactByteLimit !== 64 * 1_048_576 ||
    arithmeticCapBoundary <= artifactByteLimit || arithmeticCapBoundary > iconifyJsonByteLimit) {
    fail('Deterministic plan did not retain the exact exception and unchanged aggregate/default caps')
  }
  fixtureMustFail('Iconify exception wrong tarball URL', () => archiveByteLimitFor(iconifyFixture, `${iconifyJsonException.tarball}?other=1`))
  if (archiveByteLimitFor({ ...iconifyFixture, version: '2.2.501' }) !== artifactByteLimit ||
    archiveByteLimitFor({ ...iconifyFixture, integrity: fixtureSRI }) !== artifactByteLimit ||
    archiveByteLimitFor({ ...iconifyFixture, name: 'ordinary' }) !== artifactByteLimit) {
    fail('Wrong Iconify name/version/SRI did not fall back to the ordinary cap')
  }
  if (archiveByteLimitFor({ ...ordinaryArchiveFixture, archiveByteLimit: iconifyJsonByteLimit }) !== artifactByteLimit) {
    fail('Caller-supplied larger ordinary cap changed the effective archive bound')
  }
  fixtureMustFail('claimed ordinary larger archive cap rejected', () => assertArchiveByteLimitRecord(
    ordinaryArchiveFixture, iconifyJsonByteLimit, 'https://registry.npmjs.org/ordinary/-/ordinary-1.0.0.tgz', 'fixture'
  ))
  fixtureMustFail('caller-supplied larger Iconify archive cap rejected', () => assertArchiveByteLimitRecord(
    { ...iconifyFixture, archiveByteLimit: 1_073_741_824 }, 1_073_741_824,
    iconifyJsonException.tarball, 'fixture'
  ))
  fixtureMustFail('symbolic-link ancestor', () => assertPlainPathInfo({ isSymbolicLink: () => true }, 'fixture'))
  fixtureMustFail('junction/reparse ancestor', () => assertPlainPathInfo({ isSymbolicLink: () => false, attributes: 0x400 }, 'fixture'))
  if (!pathIsContained(root, path.join(root, 'web', 'comfy')) || pathIsContained(root, path.resolve(root, '..', 'escape'))) {
    fail('Workspace containment fixtures did not distinguish owned and escaped paths')
  }
  assertInjectiveMappings([{ locator: 'a@1.0.0' }, { locator: 'b@1.0.0' }])
  fixtureMustFail('Windows-equivalent locator collision', () => assertInjectiveMappings([{ locator: 'Pkg@1.0.0' }, { locator: 'pkg@1.0.0' }]))

  const validTar = fixtureTar([{ path: 'package/example.txt', data: 'ok' }])
  if (parseTar(validTar).entries[0]?.path !== 'package/example.txt') fail('Positive complete-tar fixture was rejected')
  const longUstarPrefix = `package/${'d'.repeat(123)}`
  const longPrefixArchive = parseTar(fixtureTar([{ path: 'file.txt', headerPrefix: longUstarPrefix, data: 'long-prefix' }]))
  if (longPrefixArchive.entries[0]?.headerLayout.layout !== 'strict-prefix-155' ||
    longPrefixArchive.entries[0]?.headerLayout.prefixWidth !== 155 ||
    longPrefixArchive.entries[0]?.headerPrefix !== longUstarPrefix) {
    fail('Positive conventional USTAR prefix longer than 130 bytes was not retained')
  }
  const emptyTimeLayoutTar = fixtureTar([{ path: 'package/empty-time.txt', data: 'empty',
    headerLayoutFixture: { shortPrefix: true } }])
  const emptyTimeLayout = parseTar(emptyTimeLayoutTar).archiveMembers[0]?.headerLayout
  if (emptyTimeLayout?.layout !== 'ustar-short-prefix-130-with-times' || emptyTimeLayout.prefixWidth !== 130 ||
    emptyTimeLayout.mtime !== null || emptyTimeLayout.ctime !== null || emptyTimeLayout.mtimeRawHex !== '0'.repeat(24) ||
    emptyTimeLayout.ctimeRawHex !== '0'.repeat(24)) fail('Positive zero-time short USTAR layout was not retained')
  const mtimeRaw = Buffer.from('00000001234\0', 'ascii')
  const ctimeRaw = Buffer.from('00000000077\0', 'ascii')
  const metadataLayoutRaw = fixtureTarRaw([
    { path: 'docs/', headerPrefix: 'package', type: '5', headerLayoutFixture: { shortPrefix: true } },
    { path: 'PaxHeader-layout', type: 'x', data: fixturePaxRecord('path', 'package/./package.json').toString('utf8') },
    { path: 'fallback-package.json', headerPrefix: 'package', data: '{"name":"fixture-package"}',
      headerLayoutFixture: { shortPrefix: true, mtimeHex: mtimeRaw.toString('hex'), ctimeHex: ctimeRaw.toString('hex') } },
    { path: 'LICENSE', headerPrefix: 'package', data: 'MIT\n', headerLayoutFixture: { shortPrefix: true } }
  ])
  const metadataLayoutArchive = parseTar(gzipSync(metadataLayoutRaw))
  const timedHeaderMember = metadataLayoutArchive.archiveMembers[2]
  const timedEntry = metadataLayoutArchive.entries.find((entry) => entry.path === 'package/package.json')
  if (metadataLayoutArchive.archiveRoot !== 'package' || metadataLayoutArchive.archiveMembers[0]?.type !== 'directory' ||
    metadataLayoutArchive.archiveMembers[1]?.type !== 'pax-extension' ||
    metadataLayoutArchive.archiveMembers[1]?.headerLayout.layout !== 'ustar-short-prefix-130-with-times' ||
    timedHeaderMember?.headerLayout.layout !== 'ustar-short-prefix-130-with-times' ||
    timedHeaderMember.headerLayout.mtime !== 668 || timedHeaderMember.headerLayout.ctime !== 63 ||
    timedHeaderMember.headerLayout.mtimeRawHex !== mtimeRaw.toString('hex') ||
    timedHeaderMember.headerLayout.ctimeRawHex !== ctimeRaw.toString('hex') ||
    timedHeaderMember.headerLayout.headerSha256 !== hash(metadataLayoutRaw.subarray(timedHeaderMember.headerOffset,
      timedHeaderMember.headerOffset + 512), 'sha256') ||
    JSON.stringify(timedEntry?.headerLayout) !== JSON.stringify(timedHeaderMember.headerLayout) ||
    timedEntry?.paxPath !== 'package/./package.json' || timedHeaderMember.headerPath !== 'package/fallback-package.json' ||
    metadataLayoutArchive.archiveMembers[0]?.headerLayout.layout !== 'ustar-short-prefix-130-with-times' ||
    metadataLayoutArchive.archiveMembers[3]?.headerLayout.layout !== 'ustar-short-prefix-130-with-times') {
    fail('Positive metadata USTAR layout lost directory, file, PAX, timestamp, or header-digest provenance')
  }
  const shortLayoutFixture = (headerLayoutFixture) => fixtureTar([{ path: 'package/example.txt', data: 'x', headerLayoutFixture }])
  fixtureMustFailWith('short-prefix layout requires exact USTAR magic', 'Tar header field contains non-padding bytes after NUL',
    () => parseTar(shortLayoutFixture({ shortPrefix: true, magic: 'notust',
      mtimeHex: Buffer.from('00000000001\0', 'ascii').toString('hex') })))
  fixtureMustFailWith('short-prefix layout requires exact USTAR version', 'Tar header field contains non-padding bytes after NUL',
    () => parseTar(shortLayoutFixture({ shortPrefix: true, version: '01',
      mtimeHex: Buffer.from('00000000001\0', 'ascii').toString('hex') })))
  fixtureMustFailWith('short-prefix separator byte must be zero', 'Tar header field contains non-padding bytes after NUL',
    () => parseTar(shortLayoutFixture({ shortPrefix: true, separator: 1 })))
  fixtureMustFailWith('short-prefix reserved tail must be zero', 'Tar USTAR short-prefix reserved tail is nonzero',
    () => parseTar(shortLayoutFixture({ shortPrefix: true, tailHex: '01' })))
  fixtureMustFailWith('short-prefix field rejects hidden bytes after NUL', 'Tar header field contains non-padding bytes after NUL',
    () => parseTar(fixtureTar([{ path: 'package/example.txt', data: 'x', headerPrefix: 'package\0hidden',
      headerLayoutFixture: { shortPrefix: true } }])))
  fixtureMustFailWith('short-prefix time rejects signs', 'Tar header mtime timestamp is not strict octal',
    () => parseTar(shortLayoutFixture({ shortPrefix: true, mtimeHex: Buffer.from('+0000000000\0', 'ascii').toString('hex') })))
  fixtureMustFailWith('short-prefix time rejects base256', 'Tar header mtime timestamp is not strict octal',
    () => parseTar(shortLayoutFixture({ shortPrefix: true, mtimeHex: Buffer.from([0x80, ...Array(11).fill(0)]).toString('hex') })))
  const maximumWidthOctalTime = Buffer.from('777777777777', 'ascii')
  if (parseTarTimestampField(maximumWidthOctalTime, 'mtime') !== 0o777777777777 ||
    !Number.isSafeInteger(parseTarTimestampField(maximumWidthOctalTime, 'mtime'))) {
    fail('Maximum-width strict octal time was not retained as a safe finite value')
  }
  for (const label of ['mtime', 'ctime']) {
    for (const position of [0, 5]) {
      for (let highDigit = 0xb0; highDigit <= 0xb7; highDigit++) {
        const rawTime = Buffer.from('00000000000\0', 'ascii')
        rawTime[position] = highDigit
        const fixtureField = `${label}Hex`
        fixtureMustFailWith(`short-prefix ${label} rejects raw high-bit digit 0x${highDigit.toString(16)} at ${position}`,
          `Tar header ${label} timestamp is not strict octal`,
          () => parseTar(shortLayoutFixture({ shortPrefix: true, [fixtureField]: rawTime.toString('hex') })))
      }
    }
  }
  fixtureMustFailWith('short-prefix time rejects over-width overflow encoding',
    'Tar header mtime timestamp field has an invalid width',
    () => parseTarTimestampField(Buffer.from('7777777777778', 'ascii'), 'mtime'))
  fixtureMustFailWith('short-prefix time rejects non-padding after NUL', 'Tar header mtime timestamp has non-padding bytes after NUL',
    () => parseTar(shortLayoutFixture({ shortPrefix: true, mtimeHex: Buffer.from('0000000001\0X', 'ascii').toString('hex') })))
  const forgedHeaderArchive = parseTar(emptyTimeLayoutTar)
  const forgedHeaderRaw = Buffer.from(fixtureTarRaw([{ path: 'package/empty-time.txt', data: 'empty',
    headerLayoutFixture: { shortPrefix: true } }]).subarray(0, 512))
  fixtureMustFailWith('header digest annotation must match complete header bytes',
    'Tar header layout annotation does not match authenticated header bytes',
    () => assertTarHeaderLayoutMatchesHeader(forgedHeaderRaw, { ...forgedHeaderArchive.archiveMembers[0].headerLayout,
      headerSha256: '0'.repeat(64) }))
  fixtureMustFailWith('header layout identity annotation must match complete header bytes',
    'Tar header layout annotation does not match authenticated header bytes',
    () => assertTarHeaderLayoutMatchesHeader(forgedHeaderRaw, { ...forgedHeaderArchive.archiveMembers[0].headerLayout,
      layout: 'strict-prefix-155', prefixWidth: 155 }))
  fixtureMustFailWith('decoded timestamp annotation must match raw bytes', 'Tar header mtime layout provenance does not match its raw bytes',
    () => assertTarHeaderLayoutProvenance({ ...timedHeaderMember.headerLayout, mtime: 1 }, timedHeaderMember.headerPrefix))
  const typesPackageName = '@types/argparse'
  const typesPackageJsonBytes = Buffer.from(JSON.stringify({ name: typesPackageName, version: '1.0.38', license: 'MIT' }), 'utf8')
  const typesLicenseBytes = Buffer.from('MIT license\n', 'utf8')
  const typesPackageJsonPax = fixturePaxRecord('path', 'argparse/./package.json')
  const typesRootTar = fixtureTar([
    { path: 'argparse/', type: '5' },
    { path: 'PaxHeader-types-package', type: 'x', data: typesPackageJsonPax.toString('utf8') },
    { path: 'argparse/fallback-package.json', data: typesPackageJsonBytes },
    { path: 'argparse/./LICENSE', data: typesLicenseBytes },
    { path: 'argparse/lib/', type: '5' },
    { path: 'argparse/lib/index.d.ts', data: 'export interface Args {}\n' },
    { path: 'argparse/lib/./index.d.ts', data: 'export interface Args {}\n' }
  ])
  const typesSRI = `sha512-${hash(typesRootTar, 'sha512')}`
  const typesFixtureLock = [
    "lockfileVersion: '9.0'", 'importers:', '  .:', '    dependencies:', "      '@types/argparse':", '        specifier: 1.0.38',
    '        version: 1.0.38', 'packages:', "  '@types/argparse@1.0.38':", `    resolution: {integrity: ${typesSRI}}`,
    'snapshots:', "  '@types/argparse@1.0.38': {}", ''
  ].join('\n')
  const typesExpectedArtifacts = collectClosure(typesFixtureLock).artifacts
  const typesArtifact = {
    ordinal: 0, locator: '@types/argparse@1.0.38', lockIntegrity: typesSRI, registryIntegrity: typesSRI,
    registryTarball: 'https://registry.npmjs.org/@types/argparse/-/argparse-1.0.38.tgz', archiveByteLimit: artifactByteLimit,
    archive: 'types-argparse.tgz', bytes: typesRootTar.byteLength, sha256: hash(typesRootTar, 'sha256'),
    metadata: 'types-argparse.json', metadataBytes: 3, metadataSha256: 'e'.repeat(64)
  }
  if (JSON.stringify(Object.keys(typesArtifact).sort()) !== JSON.stringify([...fetchedRecordKeys].sort())) {
    fail('Alternate @types fixture does not use the exact compact fetched-record shape')
  }
  const typesArchiveIdentity = authenticatedExpectedArtifact(typesExpectedArtifacts, 0, typesArtifact, 'types fixture')
  const typesRootArchive = parseTar(typesRootTar, typesArchiveIdentity)
  const ordinaryNamedArchive = parseTar(validTar)
  const typesConventionalTar = fixtureTar([
    { path: 'package/package.json', data: typesPackageJsonBytes },
    { path: 'package/LICENSE', data: typesLicenseBytes }
  ])
  const typesConventionalBinding = compactLockFixture(typesPackageName, '1.0.38', typesConventionalTar, 'conventional @types root')
  const typesConventionalArchive = parseTar(typesConventionalTar, typesConventionalBinding.identity)
  const typesRootOutput = planPackageOutputInventory(0, typesRootArchive.entries, typesArchiveIdentity)
  const typesRootSelected = selectPackageOutputEntries(typesRootArchive.entries, typesRootOutput, 0, typesArchiveIdentity)
  const typesRootAliasOutput = typesRootOutput.find((record) => record.path === 'package-0000/package/lib/index.d.ts')
  if (typesRootArchive.archiveRoot !== 'argparse' || JSON.stringify(typesRootArchive.expectedIdentity) !== JSON.stringify(typesArchiveIdentity) ||
    ordinaryNamedArchive.archiveRoot !== 'package' || ordinaryNamedArchive.expectedIdentity !== null ||
    typesConventionalArchive.archiveRoot !== 'package' || JSON.stringify(typesConventionalArchive.expectedIdentity) !== JSON.stringify(typesConventionalBinding.identity) ||
    typesRootArchive.entries.length !== 6 || typesRootArchive.archiveMembers.length !== 7 ||
    typesRootArchive.archiveMembers[0]?.type !== 'directory' || typesRootArchive.archiveMembers[0]?.canonicalPath !== 'package' ||
    !typesRootOutput.some((record) => record.path === 'package-0000/package' && record.type === 'directory') ||
    typesRootArchive.archiveMembers.filter((member) => member.type === 'file' || member.type === 'directory').some((member) => member.archiveRoot !== 'argparse') ||
    typesRootArchive.archiveMembers.find((member) => member.type === 'pax-extension')?.archiveRoot !== null ||
    typesRootArchive.entries.some((entry) => entry.path === 'package'
      ? entry.type !== 'directory' : !entry.path.startsWith('package/')) ||
    typesRootArchive.entries.find((entry) => entry.path === 'package/package.json')?.rawPath !== 'argparse/./package.json' ||
    typesRootArchive.entries.find((entry) => entry.path === 'package/package.json')?.paxPath !== 'argparse/./package.json' ||
    typesRootArchive.archiveMembers.find((member) => member.paxPath === 'argparse/./package.json')?.headerPath !== 'argparse/fallback-package.json' ||
    typesRootOutput.filter((record) => record.type === 'file').length !== 3 ||
    typesRootAliasOutput?.archiveMemberIndex !== 5 || JSON.stringify(typesRootAliasOutput.archiveMemberIndices) !== JSON.stringify([5, 6]) ||
    typesRootSelected.length !== 3 || typesRootSelected.some((entry) => entry.archiveRoot !== 'argparse') ||
    typesRootSelected.find((entry) => entry.path === 'package/lib/index.d.ts')?.archiveMemberIndex !== 5) {
    fail('@types single-root fixture lost original root/PAX provenance or canonical primary-only output mapping')
  }
  const markdownRootTar = fixtureTar([
    { path: 'markdown-it v13.0/', type: '5' },
    { path: 'PaxHeader-versioned-types', type: 'x', data: fixturePaxRecord('path', 'markdown-it v13.0/LICENSE').toString('utf8') },
    { path: 'markdown-it v13.0/LICENSE-fallback', data: typesLicenseBytes },
    { path: 'markdown-it v13.0/package.json', data: JSON.stringify({ name: '@types/markdown-it', version: '13.0.9', license: 'MIT' }) }
  ])
  const markdownRootBinding = compactLockFixture('@types/markdown-it', '13.0.9', markdownRootTar, 'markdown-it root')
  const markdownRootArchive = parseTar(markdownRootTar, markdownRootBinding.identity)
  const nodeRootTar = fixtureTar([{ path: 'node v25.9/LICENSE', data: typesLicenseBytes }])
  const nodeRootBinding = compactLockFixture('@types/node', '25.9.5', nodeRootTar, 'node root')
  const nodeRootArchive = parseTar(nodeRootTar, nodeRootBinding.identity)
  if (markdownRootArchive.archiveRoot !== 'markdown-it v13.0' ||
    markdownRootArchive.entries.find((entry) => entry.path === 'package/LICENSE')?.rawPath !== 'markdown-it v13.0/LICENSE' ||
    markdownRootArchive.archiveMembers[0]?.canonicalPath !== 'package' ||
    markdownRootArchive.archiveMembers[1]?.archiveRoot !== null ||
    nodeRootArchive.archiveRoot !== 'node v25.9' ||
    JSON.stringify(expectedTypesArchiveRoots(markdownRootBinding.identity)) !== JSON.stringify(['markdown-it', 'markdown-it v13.0']) ||
    JSON.stringify(expectedTypesArchiveRoots(nodeRootBinding.identity)) !== JSON.stringify(['node', 'node v25.9'])) {
    fail('Positive lock-derived versioned @types roots lost exact version, PAX, directory, or canonical output provenance')
  }
  fixtureMustFailWith('mixed bare and versioned roots remain rejected',
    'Tar archive mixes effective roots: markdown-it / markdown-it v13.0',
    () => parseTar(fixtureTar([{ path: 'markdown-it/LICENSE', data: typesLicenseBytes },
      { path: 'markdown-it v13.0/README.md', data: 'fixture\n' }]), markdownRootBinding.identity))
  for (const unsupportedRoot of ['markdown-it v14.0', 'markdown-it v13.1', 'markdown-it v13.0.9', 'Markdown-it v13.0', 'markdown-it  v13.0',
    'markdown-it v013.0', 'markdown-it v13.00', 'markdown-it v13.0.0']) {
    fixtureMustFailWith(`versioned @types root rejects non-derived spelling ${unsupportedRoot}`,
      `Unexpected npm tar root: ${unsupportedRoot}/LICENSE`,
      () => parseTar(fixtureTar([{ path: `${unsupportedRoot}/LICENSE`, data: typesLicenseBytes }]), markdownRootBinding.identity))
  }
  fixtureMustFailWith('ordinary package cannot authorize versioned @types root',
    'Unexpected npm tar root: markdown-it v13.0/LICENSE',
    () => {
      const ordinaryVersionedTar = fixtureTar([{ path: 'markdown-it v13.0/LICENSE', data: typesLicenseBytes }])
      parseTar(ordinaryVersionedTar, compactLockFixture('markdown-it', '13.0.9', ordinaryVersionedTar, 'ordinary markdown-it').identity)
    })
  fixtureMustFailWith('missing trusted version cannot authorize versioned @types root',
    'Unexpected npm tar root: markdown-it v13.0/LICENSE',
    () => parseTar(fixtureTar([{ path: 'markdown-it v13.0/LICENSE', data: typesLicenseBytes }]),
      { ...markdownRootBinding.identity, version: undefined }))
  fixtureMustFailWith('forged version locator cannot authorize versioned @types root',
    'Unexpected npm tar root: markdown-it v13.1/LICENSE',
    () => parseTar(fixtureTar([{ path: 'markdown-it v13.1/LICENSE', data: typesLicenseBytes }]),
      { ...markdownRootBinding.identity, version: '13.1.9' }))
  for (const malformedVersion of ['013.0.9', '13.00.9', '9007199254740992.0.0']) {
    fixtureMustFailWith(`noncanonical or unsafe expected version cannot authorize root: ${malformedVersion}`,
      'Unexpected npm tar root: markdown-it v13.0/LICENSE',
      () => {
        const malformedVersionTar = fixtureTar([{ path: 'markdown-it v13.0/LICENSE', data: typesLicenseBytes }])
        const malformedBinding = compactLockFixture('@types/markdown-it', malformedVersion, malformedVersionTar,
          `malformed @types version ${malformedVersion}`)
        parseTar(malformedVersionTar, malformedBinding.identity)
      })
  }
  const alternateRootOnlyTar = fixtureTar([{ path: 'argparse/LICENSE', data: typesLicenseBytes }])
  const alternateRootIdentity = compactLockFixture('@types/argparse', '1.0.38', alternateRootOnlyTar, 'alternate argparse').identity
  const wrongTypesIdentity = compactLockFixture('@types/other', '1.0.38', alternateRootOnlyTar, 'wrong @types identity').identity
  const ordinaryArgparseIdentity = compactLockFixture('argparse', '1.0.38', alternateRootOnlyTar, 'ordinary argparse').identity
  fixtureMustFailWith('alternate root without authenticated package identity', 'Unexpected npm tar root: argparse/LICENSE',
    () => parseTar(alternateRootOnlyTar))
  fixtureMustFailWith('alternate root bound to wrong @types identity', 'Unexpected npm tar root: argparse/LICENSE',
    () => parseTar(alternateRootOnlyTar, wrongTypesIdentity))
  fixtureMustFailWith('case-changed @types basename', 'Unexpected npm tar root: Argparse/LICENSE',
    () => parseTar(fixtureTar([{ path: 'Argparse/LICENSE', data: typesLicenseBytes }]), typesArchiveIdentity))
  fixtureMustFailWith('ordinary package cannot authorize @types root', 'Unexpected npm tar root: argparse/LICENSE',
    () => parseTar(alternateRootOnlyTar, ordinaryArgparseIdentity))
  const unsafeTypesTar = fixtureTar([{ path: 'CON/LICENSE', data: typesLicenseBytes }])
  const unsafeTypesBinding = compactLockFixture('@types/CON', '1.0.38', unsafeTypesTar, 'unsafe basename @types').identity
  fixtureMustFailWith('unsafe @types alternate root', 'Unexpected npm tar root: CON/LICENSE',
    () => parseTar(unsafeTypesTar, unsafeTypesBinding))
  if (parseTar(fixtureTar([{ path: 'package/LICENSE', data: typesLicenseBytes }]), unsafeTypesBinding).archiveRoot !== 'package') {
    fail('Unsafe optional @types basename incorrectly disabled the conventional package root')
  }
  fixtureMustFailWith('mixed package and @types roots', 'Tar archive mixes effective roots: package / argparse',
    () => parseTar(fixtureTar([{ path: 'package/first.js', data: 'a' }, { path: 'argparse/second.js', data: 'b' }]), typesArchiveIdentity))
  fixtureMustFailWith('cross-root duplicate alias', 'Tar archive mixes effective roots: package / argparse',
    () => parseTar(fixtureTar([{ path: 'package/a.js', data: 'same' }, { path: 'argparse/a.js', data: 'same' }]), typesArchiveIdentity))
  fixtureMustFailWith('PAX effective second root', 'Tar archive mixes effective roots: package / argparse',
    () => parseTar(fixtureTar([
      { path: 'package/first.js', data: 'a' },
      { path: 'PaxHeader-alt-root', type: 'x', data: fixturePaxRecord('path', 'argparse/second.js').toString('utf8') },
      { path: 'argparse/second-fallback.js', data: 'b' }
    ]), typesArchiveIdentity))
  fixtureMustFailWith('PAX effective unauthorized root', 'Unexpected npm tar root: unrelated/file.js',
    () => parseTar(fixtureTar([
      { path: 'PaxHeader-unauthorized-root', type: 'x', data: fixturePaxRecord('path', 'unrelated/file.js').toString('utf8') },
      { path: 'package/fallback.js', data: 'x' }
    ]), typesArchiveIdentity))
  fixtureMustFailWith('PAX header cannot disguise a second output root',
    'Tar header/effective path roots differ: package / argparse',
    () => parseTar(fixtureTar([
      { path: 'PaxHeader-header-root', type: 'x', data: fixturePaxRecord('path', 'argparse/effective.js').toString('utf8') },
      { path: 'package/fallback.js', data: 'x' }
    ]), typesArchiveIdentity))
  fixtureMustFailWith('alternate-root traversal remains blocked', 'Tar member path contains parent traversal: argparse/../escape',
    () => parseTar(fixtureTar([{ path: 'argparse/../escape', data: 'x' }]), typesArchiveIdentity))
  fixtureMustFailWith('alternate-root empty component remains blocked', 'Tar member path has an empty component: argparse//empty',
    () => parseTar(fixtureTar([{ path: 'argparse//empty', data: 'x' }]), typesArchiveIdentity))
  fixtureMustFailWith('alternate-root absolute path remains blocked', 'Unsafe tar member path: /argparse/escape',
    () => parseTar(fixtureTar([{ path: '/argparse/escape', data: 'x' }]), typesArchiveIdentity))
  fixtureMustFailWith('alternate-root drive path remains blocked', 'Unsafe tar member path: C:/argparse/escape',
    () => parseTar(fixtureTar([{ path: 'C:/argparse/escape', data: 'x' }]), typesArchiveIdentity))
  fixtureMustFailWith('alternate-root backslash remains blocked', 'Unsafe tar member path: argparse\\\\escape',
    () => parseTar(fixtureTar([{ path: 'argparse\\\\escape', data: 'x' }]), typesArchiveIdentity))
  fixtureMustFailWith('alternate-root Windows device remains blocked', 'Ambiguous tar member path: argparse/CON.txt',
    () => parseTar(fixtureTar([{ path: 'argparse/CON.txt', data: 'x' }]), typesArchiveIdentity))
  fixtureMustFailWith('alternate-root ADS remains blocked', 'Ambiguous tar member path: argparse/stream:meta',
    () => parseTar(fixtureTar([{ path: 'argparse/stream:meta', data: 'x' }]), typesArchiveIdentity))
  fixtureMustFailWith('forged alternate-root entry annotation',
    'Tar archive entry root provenance differs from its validated raw path: argparse/./LICENSE',
    () => planPackageOutputInventory(0, typesRootArchive.entries.map((entry) => entry.path === 'package/LICENSE'
      ? { ...entry, archiveRoot: 'package' } : entry), typesArchiveIdentity))
  for (const rootOnlyPath of ['argparse', 'argparse/.', 'argparse/./.', 'package', 'package/.']) {
    fixtureMustFailWith(`root-only regular member is rejected before output planning: ${rootOnlyPath}`,
      `Tar regular member path resolves to the archive root: ${rootOnlyPath}`,
      () => parseTar(fixtureTar([{ path: rootOnlyPath, data: 'not a directory' }]), typesArchiveIdentity))
  }
  const hiddenTypesTar = fixtureTar([{ path: '.hidden/LICENSE', data: typesLicenseBytes }])
  const hiddenTypesBinding = compactLockFixture('@types/.hidden', '1.0.38', hiddenTypesTar, 'leading-dot @types').identity
  fixtureMustFailWith('leading-dot @types alternate root is not authorized', 'Unexpected npm tar root: .hidden/LICENSE',
    () => parseTar(hiddenTypesTar, hiddenTypesBinding))
  if (parseTar(fixtureTar([{ path: 'package/LICENSE', data: typesLicenseBytes }]), hiddenTypesBinding).archiveRoot !== 'package') {
    fail('Leading-dot optional @types basename incorrectly disabled the conventional package root')
  }
  const validTarRaw = gunzipSync(validTar)
  const ordinaryPadding = fixtureTarRaw([{ path: 'package/ordinary.txt', data: 'ordinary' }])
  if (!parseTar(gzipSync(ordinaryPadding)).entries.some((entry) => entry.path === 'package/ordinary.txt')) {
    fail('Positive non-block-sized ordinary member padding fixture was rejected')
  }
  const badOrdinaryPadding = Buffer.from(ordinaryPadding)
  badOrdinaryPadding[512 + Buffer.byteLength('ordinary')] = 1
  fixtureMustFail('nonzero ordinary member padding', () => parseTar(gzipSync(badOrdinaryPadding)))
  if (parseTar(gzipSync(Buffer.concat([validTarRaw, Buffer.alloc(512)]))).entries[0]?.path !== 'package/example.txt') fail('Complete zero-block tar padding was rejected')
  fixtureMustFail('missing two-block tar EOF', () => parseTar(gzipSync(validTarRaw.subarray(0, validTarRaw.length - 1024))))
  fixtureMustFail('one-block tar EOF', () => parseTar(gzipSync(validTarRaw.subarray(0, validTarRaw.length - 512))))
  fixtureMustFail('partial tar trailer', () => parseTar(gzipSync(Buffer.concat([validTarRaw, Buffer.from([0])]))))
  fixtureMustFail('non-zero tar padding', () => parseTar(gzipSync(Buffer.concat([validTarRaw, Buffer.alloc(512).fill(1)]))))
  const paxRecord = fixturePaxRecord('path', 'package/a/b.js')
  const paxEntries = [{ path: 'PaxHeader', type: 'x', data: paxRecord.toString('utf8') }, { path: 'package/original.txt', data: 'ok' }]
  const paxTar = fixtureTar(paxEntries)
  const parsedPaxTar = parseTar(paxTar)
  if (!parsedPaxTar.entries.some((entry) => entry.path === 'package/a/b.js')) fail('Positive one-member PAX fixture was rejected')
  const paxMember = parsedPaxTar.archiveMembers[0]
  const boundMember = parsedPaxTar.archiveMembers[1]
  if (parsedPaxTar.archiveMembers.length !== 2 || paxMember?.type !== 'pax-extension' ||
    paxMember.payloadBytes !== paxRecord.length || paxMember.payloadSha256 !== hash(paxRecord, 'sha256') ||
    paxMember.headerOffset !== 0 || paxMember.dataOffset !== 512 || paxMember.boundToHeaderOffset !== boundMember?.headerOffset ||
    boundMember?.paxHeaderIndex !== paxMember.index) {
    fail('PAX archive-member provenance and exact binding were not retained')
  }
  if (boundMember?.headerName !== 'package/original.txt' || boundMember.headerPath !== 'package/original.txt' ||
    boundMember.rawPath !== 'package/a/b.js' || boundMember.paxPath !== 'package/a/b.js' ||
    boundMember.path !== 'package/a/b.js' || boundMember.canonicalPath !== 'package/a/b.js') {
    fail('PAX effective path and raw header provenance were not separately retained')
  }
  const inertPaxRecords = [
    ['NODETAR.depth', '1'], ['NODETAR.follow', 'true'], ['NODETAR.type', 'SymbolicLink'],
    ['NODETAR.blksize', '4096'], ['NODETAR.blocks', '8'], ['NODETAR.ignoreFiles.0', 'fixture-ignore'],
    ['NODETAR.package.name', 'attacker-package'], ['NODETAR.package.version', '99.0.0'],
    ['NODETAR.package.description', ''], ['NODETAR.package.repository', 'café-Ā'],
    ['NODETAR.ignoreFiles.1', ''], ['NODETAR.ignoreFiles.2', 'é-Ā'],
    ['NODETAR.package.dependencies.@fixture/dep', '1.2.3'],
    ['NODETAR.package.license', 'LicenseRef-forged'], ['NODETAR.package.scripts.preinstall', 'run-untrusted-command'],
    ['SCHILY.dev', '16777220'], ['SCHILY.ino', '40154246'], ['SCHILY.nlink', '1']
  ]
  const inertPaxBytes = fixturePaxRecords(inertPaxRecords)
  const inertVendorTar = fixtureTar([
    { path: 'vendor-metadata', type: 'x', data: inertPaxBytes },
    { path: 'package/ordinary.txt', data: 'header-authoritative-payload' }
  ])
  const inertVendorBinding = compactLockFixture('fixture-package', '1.0.0', inertVendorTar, 'inert vendor metadata')
  const inertVendorArchive = parseTar(inertVendorTar, inertVendorBinding.identity)
  const inertVendorMember = inertVendorArchive.archiveMembers[0]
  const inertVendorOutput = planPackageOutputInventory(0, inertVendorArchive.entries, inertVendorBinding.identity)
  if (inertVendorArchive.archiveRoot !== 'package' || inertVendorArchive.entries.length !== 1 ||
    inertVendorArchive.entries[0]?.path !== 'package/ordinary.txt' ||
    inertVendorArchive.entries[0]?.data.toString('utf8') !== 'header-authoritative-payload' ||
    inertVendorArchive.archiveMembers.length !== 2 || inertVendorMember?.type !== 'pax-extension' ||
    inertVendorMember.payloadBytes !== inertPaxBytes.length || inertVendorMember.payloadSha256 !== hash(inertPaxBytes, 'sha256') ||
    inertVendorMember.boundToHeaderOffset !== inertVendorArchive.archiveMembers[1]?.headerOffset ||
    inertVendorArchive.archiveMembers[1]?.paxHeaderIndex !== 0 || inertVendorOutput.some((record) => record.path.includes('vendor-metadata')) ||
    inertVendorOutput.filter((record) => record.type === 'file').length !== 1) {
    fail('Positive inert legacy PAX metadata changed lock/header authority or lost exact extension binding')
  }
  const secondVendorTar = fixtureTar([
    { path: 'opaque-vendor-header', type: 'x', data: fixturePaxRecords([
      ['NODETAR.depth', '1'], ['NODETAR.follow', 'false'], ['NODETAR.package.name', 'not-the-lock-name'], ['SCHILY.nlink', '1']
    ]) },
    { path: 'argparse/', type: '5' },
    { path: 'argparse/LICENSE', data: 'MIT license\n' }
  ])
  const secondVendorBinding = compactLockFixture('@types/argparse', '1.0.38', secondVendorTar,
    'second inert vendor identity')
  const secondVendorArchive = parseTar(secondVendorTar, secondVendorBinding.identity)
  const secondVendorOutput = planPackageOutputInventory(0, secondVendorArchive.entries, secondVendorBinding.identity)
  if (secondVendorArchive.archiveRoot !== 'argparse' ||
    secondVendorArchive.entries[0]?.type !== 'directory' || secondVendorArchive.entries[0]?.path !== 'package' ||
    secondVendorArchive.entries[1]?.path !== 'package/LICENSE' ||
    secondVendorArchive.archiveMembers[0]?.boundToHeaderOffset !== secondVendorArchive.archiveMembers[1]?.headerOffset ||
    secondVendorOutput.some((record) => record.path.includes('opaque-vendor-header')) ||
    secondVendorOutput.filter((record) => record.type === 'file').length !== 1) {
    fail('Positive second lock identity/vendor-PAX fixture lost directory/header authority or created a metadata output')
  }
  const inertPaxTar = (records, target = { path: 'package/ordinary.txt', data: 'safe' }) => fixtureTar([
    { path: 'vendor-metadata', type: 'x', data: fixturePaxRecords(records) }, target
  ])
  for (let codePoint = 0x80; codePoint <= 0x9f; codePoint++) {
    const control = String.fromCodePoint(codePoint)
    const label = `C1 U+${codePoint.toString(16).toUpperCase().padStart(4, '0')}`
    fixtureMustFailWith(`${label} in NODETAR.package`, 'Invalid or oversized inert PAX value for NODETAR.package',
      () => parseTar(inertPaxTar([['NODETAR.package.description', `before${control}after`]])))
    fixtureMustFailWith(`${label} in NODETAR.ignoreFiles`, 'Invalid or oversized inert PAX value for NODETAR.ignoreFiles',
      () => parseTar(inertPaxTar([['NODETAR.ignoreFiles.0', `before${control}after`]])))
  }
  fixtureMustFailWith('unknown legacy vendor PAX key', 'Unsupported PAX key: NODETAR.path',
    () => parseTar(inertPaxTar([['NODETAR.path', 'package/forged.txt']])))
  for (const key of ['NODETAR.size', 'NODETAR.linkpath', 'SCHILY.acl', 'SCHILY.sparse']) {
    fixtureMustFailWith(`unknown vendor PAX key ${key}`, `Unsupported PAX key: ${key}`,
      () => parseTar(inertPaxTar([[key, 'value']])))
  }
  fixtureMustFailWith('unknown SCHILY vendor PAX key', 'Unsupported PAX key: SCHILY.linkpath',
    () => parseTar(inertPaxTar([['SCHILY.linkpath', 'package/forged.txt']])))
  fixtureMustFailWith('unrelated vendor PAX namespace', 'Unsupported PAX key: VENDOR.safe',
    () => parseTar(inertPaxTar([['VENDOR.safe', 'value']])))
  fixtureMustFailWith('duplicate inert PAX key', 'Duplicate PAX key: NODETAR.follow',
    () => parseTar(inertPaxTar([['NODETAR.follow', 'true'], ['NODETAR.follow', 'false']])))
  fixtureMustFailWith('invalid inert PAX boolean', 'Invalid inert boolean PAX value for NODETAR.follow',
    () => parseTar(inertPaxTar([['NODETAR.follow', 'yes']])))
  fixtureMustFailWith('noncanonical inert PAX integer', 'Invalid inert numeric PAX value for NODETAR.depth',
    () => parseTar(inertPaxTar([['NODETAR.depth', '01']])))
  fixtureMustFailWith('inert PAX integer exceeds uint64', 'Invalid inert numeric PAX value for SCHILY.ino',
    () => parseTar(inertPaxTar([['SCHILY.ino', '18446744073709551616']])))
  fixtureMustFailWith('inert PAX ignoreFiles index bound', 'PAX inert ignoreFiles index exceeds its bound',
    () => parseTar(inertPaxTar([['NODETAR.ignoreFiles.1025', 'ignored']])))
  fixtureMustFailWith('inert PAX property depth bound', 'Invalid inert NODETAR.package property path',
    () => parseTar(inertPaxTar([['NODETAR.package.a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.p.q', 'value']])))
  fixtureMustFailWith('inert PAX prototype property', 'Invalid inert NODETAR.package property path',
    () => parseTar(inertPaxTar([['NODETAR.package.__proto__.polluted', 'true']])))
  for (const property of ['prototype', 'constructor']) {
    fixtureMustFailWith(`inert PAX prototype-special property ${property}`, 'Invalid inert NODETAR.package property path',
      () => parseTar(inertPaxTar([[`NODETAR.package.${property}.polluted`, 'true']])))
  }
  fixtureMustFailWith('inert PAX empty property segment', 'Invalid inert NODETAR.package property path',
    () => parseTar(inertPaxTar([['NODETAR.package.dependencies..child', '1.0.0']])))
  fixtureMustFailWith('inert PAX control value', 'Invalid or oversized inert PAX value for NODETAR.package',
    () => parseTar(inertPaxTar([['NODETAR.package.description', 'bad\u0001value']])))
  fixtureMustFailWith('inert PAX value byte bound', 'Invalid or oversized inert PAX value for NODETAR.ignoreFiles',
    () => parseTar(inertPaxTar([['NODETAR.ignoreFiles.0', 'x'.repeat(paxInertValueByteLimit + 1)]])))
  fixtureMustFailWith('non-ASCII PAX key', 'PAX key is not bounded printable ASCII',
    () => parseTar(inertPaxTar([['NODETAR.package.naïve', 'value']])))
  fixtureMustFailWith('empty PAX key', 'Malformed PAX key/value',
    () => parseTar(fixtureTar([{ path: 'vendor-metadata', type: 'x', data: fixturePaxRawRecord('', Buffer.from('value')) },
      { path: 'package/ordinary.txt', data: 'safe' }])))
  fixtureMustFailWith('inert PAX key byte bound', 'PAX key is not bounded printable ASCII',
    () => parseTar(inertPaxTar([[`NODETAR.package.${'a'.repeat(paxKeyByteLimit)}`, 'value']])))
  fixtureMustFailWith('inert PAX strict UTF-8 value', 'PAX record is not strict UTF-8',
    () => parseTar(fixtureTar([{ path: 'vendor-metadata', type: 'x', data: fixturePaxRawRecord('NODETAR.package.description', Buffer.from([0xc3, 0x28])) },
      { path: 'package/ordinary.txt', data: 'safe' }])))
  const tooManyPaxRecords = fixturePaxRecords(Array.from({ length: paxRecordCountLimit + 1 }, (_, index) =>
    [`NODETAR.ignoreFiles.${index}`, 'x']))
  fixtureMustFailWith('PAX record-count bound', 'PAX record count exceeds its bound',
    () => parseTar(fixtureTar([{ path: 'vendor-metadata', type: 'x', data: tooManyPaxRecords },
      { path: 'package/ordinary.txt', data: 'safe' }])))
  fixtureMustFailWith('PAX payload byte bound', 'PAX payload exceeds its byte bound',
    () => parsePaxRecord(Buffer.alloc(paxPayloadByteLimit + 1)))
  fixtureMustFailWith('inert vendor type cannot authorize tar link', 'Forbidden tar member type "2" at package/ordinary.txt',
    () => parseTar(inertPaxTar([['NODETAR.type', 'SymbolicLink'], ['NODETAR.follow', 'true']],
      { path: 'package/ordinary.txt', type: '2', data: '' })))
  fixtureMustFailWith('inert SCHILY device metadata cannot authorize tar device', 'Forbidden tar member type "3" at package/ordinary.txt',
    () => parseTar(inertPaxTar([['NODETAR.type', 'CharacterDevice'], ['SCHILY.dev', '1'], ['SCHILY.ino', '2'],
      ['SCHILY.nlink', '1']], { path: 'package/ordinary.txt', type: '3', data: '' })))
  fixtureMustFailWith('inert vendor metadata cannot override effective path', 'Tar member path contains parent traversal: package/../escape',
    () => parseTar(inertPaxTar([['NODETAR.package.name', 'fixture-package'], ['NODETAR.follow', 'true'],
      ['path', 'package/../escape']])))
  const dottedPaxPath = 'package/./dist/./remirror-core-constants.cjs'
  const dottedPaxRecord = fixturePaxRecord('path', dottedPaxPath)
  const dottedPaxTar = fixtureTar([
    { path: 'PaxHeader-dotted', type: 'x', data: dottedPaxRecord.toString('utf8') },
    { path: 'package/dist/fallback.cjs', data: 'alias-payload' },
    { path: 'package/dist/remirror-core-constants.cjs', data: 'alias-payload' },
    { path: 'package/dist/./remirror-core-constants.cjs', data: 'alias-payload' }
  ])
  const dottedAliasBinding = compactLockFixture('fixture-package', '1.0.0', dottedPaxTar, 'dotted alias package')
  const dottedPaxArchive = parseTar(dottedPaxTar, dottedAliasBinding.identity)
  const dottedPaxMember = dottedPaxArchive.archiveMembers[1]
  const dottedAliasGroup = collectCanonicalFileAliasGroups(dottedPaxArchive.entries, dottedAliasBinding.identity)[0]
  const dottedAliasOutput = planPackageOutputInventory(12, dottedPaxArchive.entries, dottedAliasBinding.identity)
  const dottedAliasSelected = selectPackageOutputEntries(dottedPaxArchive.entries, dottedAliasOutput, 12, dottedAliasBinding.identity)
  if (dottedPaxArchive.archiveMembers.length !== 4 || dottedPaxArchive.entries.length !== 3 ||
    dottedPaxArchive.entries.some((entry) => entry.path !== 'package/dist/remirror-core-constants.cjs') ||
    dottedPaxMember?.headerName !== 'package/dist/fallback.cjs' ||
    dottedPaxMember.headerPath !== 'package/dist/fallback.cjs' || dottedPaxMember.rawPath !== dottedPaxPath ||
    dottedPaxMember.paxPath !== dottedPaxPath || dottedPaxMember.path !== 'package/dist/remirror-core-constants.cjs' ||
    dottedPaxMember.canonicalPath !== 'package/dist/remirror-core-constants.cjs' ||
    dottedPaxMember.outputPrimaryArchiveMemberIndex !== 1 ||
    JSON.stringify(dottedPaxMember.outputArchiveMemberIndices) !== JSON.stringify([1, 2, 3]) ||
    JSON.stringify(dottedAliasGroup?.archiveMemberIndices) !== JSON.stringify([1, 2, 3]) ||
    dottedAliasGroup.primaryArchiveMemberIndex !== 1 || dottedAliasOutput.length !== 4 ||
    dottedAliasOutput.find((record) => record.type === 'file')?.archiveMemberIndex !== 1 ||
    JSON.stringify(dottedAliasOutput.find((record) => record.type === 'file')?.archiveMemberIndices) !== JSON.stringify([1, 2, 3]) ||
    dottedAliasSelected.length !== 1 || dottedAliasSelected[0]?.archiveMemberIndex !== 1) {
    fail('Positive dotted PAX/clean/dotted alias group lost complete members or did not plan one primary output')
  }
  const uniqueAliasOutputBytes = dottedAliasOutput.filter((record) => record.type === 'file')
    .reduce((total, record) => total + record.bytes, 0)
  const measuredFullTarBytes = gunzipSync(dottedPaxTar).byteLength
  const exactExpansionRecords = []
  const exactExpansionTotal = accountArchiveExpansion(exactExpansionRecords, 0,
    dottedPaxArchive.archiveExpandedBytes, dottedPaxArchive.archiveExpandedBytes)
  const exactTwoArchiveRecords = []
  accountArchiveExpansion(exactTwoArchiveRecords, 0, dottedPaxArchive.archiveExpandedBytes,
    dottedPaxArchive.archiveExpandedBytes * 2)
  const exactTwoArchiveTotal = accountArchiveExpansion(exactTwoArchiveRecords, 1,
    dottedPaxArchive.archiveExpandedBytes, dottedPaxArchive.archiveExpandedBytes * 2)
  if (dottedPaxArchive.archiveExpandedBytes !== measuredFullTarBytes || measuredFullTarBytes <= uniqueAliasOutputBytes ||
    exactExpansionTotal !== measuredFullTarBytes || exactTwoArchiveTotal !== measuredFullTarBytes * 2 ||
    exactExpansionRecords[0]?.archiveExpandedBytes !== measuredFullTarBytes ||
    exactTwoArchiveRecords.length !== 2) {
    fail('Positive full-tar expansion accounting omitted alias, PAX, header, padding, or EOF bytes')
  }
  fixtureMustFailWith('aggregate decompressed tar cap over by one', 'Aggregate gzip-expanded archive-byte cap exceeded', () =>
    accountArchiveExpansion([], 0, dottedPaxArchive.archiveExpandedBytes, dottedPaxArchive.archiveExpandedBytes - 1))
  fixtureMustFailWith('aggregate decompressed tar total over cap', 'Aggregate gzip-expanded archive-byte cap exceeded', () => {
    const records = []
    accountArchiveExpansion(records, 0, dottedPaxArchive.archiveExpandedBytes,
      dottedPaxArchive.archiveExpandedBytes * 2 - 1)
    accountArchiveExpansion(records, 1, dottedPaxArchive.archiveExpandedBytes,
      dottedPaxArchive.archiveExpandedBytes * 2 - 1)
  })
  const aliasInventoryFile = dottedAliasOutput.find((record) => record.type === 'file')
  const reverseAliasArchive = parseTar(fixtureTar([
    { path: 'package/dist/remirror-core-constants.cjs', data: 'alias-payload' },
    { path: 'package/./dist/remirror-core-constants.cjs', data: 'alias-payload' }
  ]))
  const reverseAliasOutput = planPackageOutputInventory(12, reverseAliasArchive.entries)
  const reverseAliasSelection = selectPackageOutputEntries(reverseAliasArchive.entries, reverseAliasOutput, 12)
  const reverseAliasFile = reverseAliasOutput.find((record) => record.type === 'file')
  if (reverseAliasArchive.entries[0]?.rawPath !== 'package/dist/remirror-core-constants.cjs' ||
    reverseAliasArchive.entries[1]?.rawPath !== 'package/./dist/remirror-core-constants.cjs' ||
    reverseAliasFile?.archiveMemberIndex !== 0 || JSON.stringify(reverseAliasFile.archiveMemberIndices) !== JSON.stringify([0, 1]) ||
    reverseAliasSelection.length !== 1 || reverseAliasSelection[0]?.archiveMemberIndex !== 0) {
    fail('Positive canonical-first alias fixture did not select the earliest archive member as the sole output')
  }
  assertPackageAliasProvenance(12, dottedPaxArchive.archiveMembers, dottedAliasOutput, dottedAliasBinding.identity, 'package')
  fixtureMustFailWith('package record omits alias member provenance',
    'Package file alias group does not bind every archive member exactly once: package-0012/package/dist/remirror-core-constants.cjs',
    () => assertPackageAliasProvenance(12, dottedPaxArchive.archiveMembers,
      dottedAliasOutput.map((record) => record.type === 'file' ? { ...record, archiveMemberIndices: [1, 2] } : record),
      dottedAliasBinding.identity, 'package'))
  fixtureMustFailWith('package record duplicates alias output provenance',
    'Package file alias group does not bind every archive member exactly once: package-0012/package/dist/remirror-core-constants.cjs',
    () => assertPackageAliasProvenance(12, dottedPaxArchive.archiveMembers,
      [...dottedAliasOutput, { ...aliasInventoryFile }], dottedAliasBinding.identity, 'package'))
  fixtureMustFailWith('same-length alias content mismatch', 'Canonical file alias payload mismatch: package/a.bin', () =>
    parseTar(fixtureTar([{ path: 'package/a.bin', data: 'same' }, { path: 'package/./a.bin', data: 'diff' }])))
  fixtureMustFailWith('alias size mismatch', 'Canonical file alias size mismatch: package/a.bin', () =>
    parseTar(fixtureTar([{ path: 'package/a.bin', data: 'a' }, { path: 'package/./a.bin', data: 'ab' }])))
  fixtureMustFailWith('case-only file alias', 'Duplicate or case-colliding tar path: package/a.bin', () =>
    parseTar(fixtureTar([{ path: 'package/A.bin', data: 'same' }, { path: 'package/./a.bin', data: 'same' }])))
  fixtureMustFailWith('repeated raw file path', 'Repeated raw tar file path: package/a.bin', () =>
    parseTar(fixtureTar([{ path: 'package/a.bin', data: 'same' }, { path: 'package/./a.bin', data: 'same' },
      { path: 'package/a.bin', data: 'same' }])))
  fixtureMustFailWith('duplicate directory alias', 'Duplicate or case-colliding tar path: package/a', () =>
    parseTar(fixtureTar([{ path: 'package/a/', type: '5' }, { path: 'package/./a/', type: '5' }])))
  const aliasSelectionFailure = 'Extraction file alias provenance differs from its complete archive group: package-0012/package/dist/remirror-core-constants.cjs'
  fixtureMustFailWith('alias output omitted', 'Extraction file alias inventory count or uniqueness differs from the complete archive', () =>
    selectPackageOutputEntries(dottedPaxArchive.entries, dottedAliasOutput.filter((record) => record.type !== 'file'), 12))
  fixtureMustFailWith('alias output extra', 'Extraction file alias inventory count or uniqueness differs from the complete archive', () =>
    selectPackageOutputEntries(dottedPaxArchive.entries, [...dottedAliasOutput,
      { ...aliasInventoryFile, path: 'package-0012/package/extra.bin' }], 12))
  fixtureMustFailWith('alias indices reordered', aliasSelectionFailure, () =>
    selectPackageOutputEntries(dottedPaxArchive.entries, dottedAliasOutput.map((record) => record.type === 'file'
      ? { ...record, archiveMemberIndices: [3, 2, 1] } : record), 12))
  fixtureMustFailWith('alias output wrong type', 'Extraction file alias inventory count or uniqueness differs from the complete archive', () =>
    selectPackageOutputEntries(dottedPaxArchive.entries, dottedAliasOutput.map((record) => record.type === 'file'
      ? { ...record, type: 'directory' } : record), 12))
  fixtureMustFailWith('alias indices duplicated', aliasSelectionFailure, () =>
    selectPackageOutputEntries(dottedPaxArchive.entries, dottedAliasOutput.map((record) => record.type === 'file'
      ? { ...record, archiveMemberIndices: [1, 1, 3] } : record), 12))
  fixtureMustFailWith('alias index foreign', aliasSelectionFailure, () =>
    selectPackageOutputEntries(dottedPaxArchive.entries, dottedAliasOutput.map((record) => record.type === 'file'
      ? { ...record, archiveMemberIndices: [1, 2, 99] } : record), 12))
  fixtureMustFailWith('alias primary changed', aliasSelectionFailure, () =>
    selectPackageOutputEntries(dottedPaxArchive.entries, dottedAliasOutput.map((record) => record.type === 'file'
      ? { ...record, archiveMemberIndex: 2 } : record), 12))
  fixtureMustFailWith('alias member omitted on recheck', 'Reparsed file alias group annotation differs from its complete members: package/dist/remirror-core-constants.cjs', () =>
    selectPackageOutputEntries(dottedPaxArchive.entries.slice(1), dottedAliasOutput, 12))
  fixtureMustFailWith('alias output digest tamper', 'Extraction file alias provenance differs from its complete archive group: package-0012/package/dist/remirror-core-constants.cjs', () =>
    selectPackageOutputEntries(dottedPaxArchive.entries, dottedAliasOutput.map((record) => record.type === 'file'
      ? { ...record, sha256: '0'.repeat(64) } : record), 12))
  const dottedDirectoryArchive = parseTar(fixtureTar([
    { path: './docs/', headerPrefix: 'package', type: '5' },
    { path: 'package/./docs/./guide.txt', data: 'guide' }
  ]))
  const dottedDirectoryMember = dottedDirectoryArchive.archiveMembers[0]
  if (dottedDirectoryArchive.entries[0]?.path !== 'package/docs' || dottedDirectoryMember?.rawPath !== 'package/./docs/' ||
    dottedDirectoryMember.headerName !== './docs/' || dottedDirectoryMember.headerPrefix !== 'package' ||
    dottedDirectoryMember.headerPath !== 'package/./docs/' || dottedDirectoryMember.path !== 'package/docs' ||
    dottedDirectoryMember.canonicalPath !== 'package/docs' || dottedDirectoryArchive.entries[1]?.path !== 'package/docs/guide.txt') {
    fail('Dotted directory path with USTAR prefix/trailing slash lost raw provenance or child mapping')
  }
  if (parseTar(validTar).entries[0]?.path !== 'package/example.txt') fail('Ordinary valid path mapping changed')
  fixtureMustFailWith('leading dot root', 'Unexpected npm tar root: ./package/file.txt', () =>
    parseTar(fixtureTar([{ path: './package/file.txt', data: 'x' }])))
  fixtureMustFailWith('parent traversal', 'Tar member path contains parent traversal: package/../escape', () =>
    parseTar(fixtureTar([{ path: 'package/../escape', data: 'x' }])))
  fixtureMustFailWith('parent traversal behind dot', 'Tar member path contains parent traversal: package/./../escape', () =>
    parseTar(fixtureTar([{ path: 'package/./../escape', data: 'x' }])))
  fixtureMustFailWith('empty path component', 'Tar member path has an empty component: package//empty', () =>
    parseTar(fixtureTar([{ path: 'package//empty', data: 'x' }])))
  fixtureMustFailWith('dot-canonical differing payload', 'Canonical file alias payload mismatch: package/a.txt', () =>
    parseTar(fixtureTar([{ path: 'package/a.txt', data: 'a' }, { path: 'package/./a.txt', data: 'b' }])))
  fixtureMustFailWith('dot-canonical case collision', 'Duplicate or case-colliding tar path: package/a.txt', () =>
    parseTar(fixtureTar([{ path: 'package/A.txt', data: 'a' }, { path: 'package/./a.txt', data: 'b' }])))
  fixtureMustFailWith('dot file descends from file', 'Tar file descends from file: package/tree/child', () =>
    parseTar(fixtureTar([{ path: 'package/tree', data: 'a' }, { path: 'package/./tree/child', data: 'b' }])))
  fixtureMustFailWith('dot file replaces directory', 'Tar file replaces a directory: package/tree', () =>
    parseTar(fixtureTar([{ path: 'package/tree/child', data: 'a' }, { path: 'package/./tree', data: 'b' }])))
  fixtureMustFailWith('dot directory collides with file', 'Duplicate or case-colliding tar path: package/a', () =>
    parseTar(fixtureTar([{ path: 'package/./a/', type: '5' }, { path: 'package/a', data: 'b' }])))
  fixtureMustFailWith('dot implicit ancestor case alias',
    'Case- or normalization-colliding planned output path: package-0011/package/A / package-0011/package/a', () =>
      planPackageOutputInventory(11, parseTar(fixtureTar([
        { path: 'package/A/one.txt', data: 'one' },
        { path: 'package/./a/two.txt', data: 'two' }
      ])).entries))
  fixtureMustFailWith('dot path Windows device hazard', 'Ambiguous tar member path: package/./CON.txt', () =>
    parseTar(fixtureTar([{ path: 'package/./CON.txt', data: 'x' }])))
  fixtureMustFailWith('dot path Windows ADS hazard', 'Ambiguous tar member path: package/./stream:meta', () =>
    parseTar(fixtureTar([{ path: 'package/./stream:meta', data: 'x' }])))
  const overRawBoundPath = `package/${'a'.repeat(tarRawPathByteLimit)}`
  const overComponentPath = `package/${'a'.repeat(tarPathComponentByteLimit + 1)}`
  const overCanonicalPath = `package/${'a'.repeat(200)}`
  fixtureMustFailWith('raw original path bound', `Tar member raw path exceeds its ${tarRawPathByteLimit}-byte bound`, () =>
    parseTar(fixtureTar([{ path: 'PaxHeader-long', type: 'x', data: fixturePaxRecord('path', overRawBoundPath).toString('utf8') },
      { path: 'package/fallback.txt', data: 'x' }])))
  fixtureMustFailWith('original component bound', `Tar member path component exceeds its ${tarPathComponentByteLimit}-byte bound: ${overComponentPath}`, () =>
    parseTar(fixtureTar([{ path: 'PaxHeader-component', type: 'x', data: fixturePaxRecord('path', overComponentPath).toString('utf8') },
      { path: 'package/fallback.txt', data: 'x' }])))
  fixtureMustFailWith('canonical output path bound', `Tar member canonical output path exceeds its ${computedExtractionPathByteLimit}-character bound: ${overCanonicalPath}`, () =>
    parseTar(fixtureTar([{ path: 'PaxHeader-canonical', type: 'x', data: fixturePaxRecord('path', overCanonicalPath).toString('utf8') },
      { path: 'package/fallback.txt', data: 'x' }])))
  const implicitOutput = planPackageOutputInventory(7, parsedPaxTar.entries)
  const implicitPaths = implicitOutput.map(({ path: relativePath, type, provenance }) => ({ path: relativePath, type, provenance }))
  if (JSON.stringify(implicitPaths) !== JSON.stringify([
    { path: 'package-0007', type: 'directory', provenance: 'artifact-ordinal-root' },
    { path: 'package-0007/package', type: 'directory', provenance: 'synthesized-ancestor' },
    { path: 'package-0007/package/a', type: 'directory', provenance: 'synthesized-ancestor' },
    { path: 'package-0007/package/a/b.js', type: 'file', provenance: 'archive-explicit' }
  ])) fail('PAX archive with implicit parents did not plan every output directory and file')
  const explicitThenChild = parseTar(fixtureTar([
    { path: 'package/a', type: '5' },
    { path: 'package/a/child.txt', data: 'ok' }
  ]))
  const explicitThenChildPlan = planPackageOutputInventory(8, explicitThenChild.entries)
  if (!explicitThenChildPlan.some((record) => record.path === 'package-0008/package/a' &&
    record.type === 'directory' && record.provenance === 'archive-explicit') ||
    !explicitThenChildPlan.some((record) => record.path === 'package-0008/package/a/child.txt' && record.type === 'file')) {
    fail('Explicit archive directory followed by a child was not deduplicated in the output inventory')
  }
  fixtureMustFail('case-colliding implicit output directories', () => planPackageOutputInventory(9, parseTar(fixtureTar([
    { path: 'package/A/one.txt', data: 'one' },
    { path: 'package/a/two.txt', data: 'two' }
  ])).entries))
  fixtureMustFail('case-colliding explicit and synthesized output directories', () => planPackageOutputInventory(10, parseTar(fixtureTar([
    { path: 'package/A', type: '5' },
    { path: 'package/a/child.txt', data: 'child' }
  ])).entries))
  const identityFixture = implicitOutput.map((record, index) => ({
    ...record, identity: fileIdentityRecord(identityStat(1n, BigInt(index + 1), 0n), 'inventory identity fixture')
  }))
  const observedFixture = identityFixture.map(({ path: relativePath, type, bytes, sha256, identity }) => ({
    path: relativePath, type, bytes, sha256, identity: { ...identity }
  }))
  assertInventoryMatches(identityFixture, observedFixture, 'Positive in-memory output inventory fixture')
  fixtureMustFail('missing output path in exact inventory', () => assertInventoryMatches(identityFixture, identityFixture.slice(1), 'fixture'))
  fixtureMustFail('extra output path in exact inventory', () => assertInventoryMatches(identityFixture, [...identityFixture, { ...identityFixture[0], path: 'package-0007/unplanned' }], 'fixture'))
  fixtureMustFail('tampered output digest in exact inventory', () => assertInventoryMatches(identityFixture, identityFixture.map((item, index) => index === 3 ? { ...item, sha256: '0'.repeat(64) } : item), 'fixture'))
  const paxRaw = fixtureTarRaw(paxEntries)
  const badPaxPadding = Buffer.from(paxRaw)
  badPaxPadding[512 + paxRecord.length] = 1
  fixtureMustFail('nonzero PAX member padding', () => parseTar(gzipSync(badPaxPadding)))
  fixtureMustFail('unconsumed PAX', () => parseTar(fixtureTar([{ path: 'PaxHeader', type: 'x', data: paxRecord.toString('utf8') }])) )
  const malformedPax = fixturePaxRecord('path', 'package/no-newline.txt', false)
  fixtureMustFail('PAX newline', () => parseTar(fixtureTar([{ path: 'PaxHeader', type: 'x', data: malformedPax.toString('utf8') }, { path: 'package/a.txt', data: 'x' }])) )
  const duplicatePax = Buffer.concat([fixturePaxRecord('path', 'package/a.txt'), fixturePaxRecord('path', 'package/b.txt')])
  fixtureMustFail('duplicate PAX key', () => parseTar(fixtureTar([{ path: 'PaxHeader', type: 'x', data: duplicatePax.toString('utf8') }, { path: 'package/c.txt', data: 'x' }])) )
  fixtureMustFail('multiple PAX records for one member', () => parseTar(fixtureTar([
    { path: 'PaxHeader1', type: 'x', data: paxRecord.toString('utf8') },
    { path: 'PaxHeader2', type: 'x', data: paxRecord.toString('utf8') },
    { path: 'package/c.txt', data: 'x' }
  ])))
  fixtureMustFail('Windows case collision', () => parseTar(fixtureTar([{ path: 'package/FILE.txt', data: 'a' }, { path: 'package/file.txt', data: 'b' }])) )
  fixtureMustFail('Windows device filename', () => parseTar(fixtureTar([{ path: 'package/CON.txt', data: 'x' }])))
  fixtureMustFail('directory member payload', () => parseTar(fixtureTar([{ path: 'package/folder', type: '5', data: 'x' }])))
  if (parseSpdxExpression('MIT AND Apache-2.0').expression !== 'MIT AND Apache-2.0' ||
    parseSpdxExpression('GPL-3.0-only WITH Classpath-exception-2.0').expression !== 'GPL-3.0-only WITH Classpath-exception-2.0') {
    fail('Positive frozen SPDX license/exception subset fixtures were rejected')
  }
  fixtureMustFail('unknown SPDX license identifier', () => parseSpdxExpression('MadeUpLicense'))
  fixtureMustFail('unknown SPDX exception identifier', () => parseSpdxExpression('GPL-3.0-only WITH MadeUpException'))
  fixtureMustFail('unreviewed LicenseRef', () => parseSpdxExpression('LicenseRef-Local'))
  fixtureMustFail('unreviewed SEE LICENSE IN', () => parseSpdxExpression('SEE LICENSE IN LICENSE.custom'))
  const licenseFixturePackage = { name: 'fixture-package', version: '1.0.0', license: 'MIT' }
  const licenseFixtureMetadata = { license: 'Apache-2.0' }
  const licenseFixtureEntries = [{ path: 'package/LICENSE', type: 'file', bytes: 12, data: Buffer.from('MIT license\n'), archiveMemberIndex: 0 }]
  const supportedLicenseAssessment = assessLicense(licenseFixturePackage, licenseFixtureMetadata, licenseFixtureEntries, { inspectionOnly: true })
  const strictSupportedLicenseAssessment = assessLicense(licenseFixturePackage, licenseFixtureMetadata, licenseFixtureEntries)
  if (supportedLicenseAssessment.declaration.source !== 'packageJson.license' ||
    supportedLicenseAssessment.declaration.text !== 'MIT' || supportedLicenseAssessment.issues.length !== 0 ||
    supportedLicenseAssessment.declaration.status !== 'SUPPORTED_SUBSET' ||
    supportedLicenseAssessment.texts.length !== 1 || supportedLicenseAssessment.texts[0].path !== 'package/LICENSE' ||
    supportedLicenseAssessment.texts[0].archiveMemberIndex !== 0 ||
    supportedLicenseAssessment.texts[0].bytes !== 12 || supportedLicenseAssessment.texts[0].sha256 !== hash(licenseFixtureEntries[0].data, 'sha256') ||
    supportedLicenseAssessment.texts[0].utf8 !== 'MIT license\n') {
    fail('Positive license inspection fixture lost declaration or exact UTF-8 text provenance')
  }
  if (strictSupportedLicenseAssessment.issues.length !== 0 || strictSupportedLicenseAssessment.texts[0]?.path !== 'package/LICENSE') {
    fail('Positive strict extraction fixture changed its supported declaration/text behavior')
  }
  const licenseAliasArchive = parseTar(fixtureTar([
    { path: 'package/LICENSE', data: 'MIT license\n' },
    { path: 'package/./LICENSE', data: 'MIT license\n' }
  ]))
  const licenseAliasAssessment = assessLicense(licenseFixturePackage, licenseFixtureMetadata,
    licenseAliasArchive.entries, { inspectionOnly: true })
  const licenseAliasOutput = planPackageOutputInventory(13, licenseAliasArchive.entries)
  const licenseAliasFile = licenseAliasOutput.find((record) => record.type === 'file')
  if (licenseAliasArchive.archiveMembers.length !== 2 || licenseAliasAssessment.texts.length !== 2 ||
    licenseAliasAssessment.texts.some((evidence) => evidence.path !== 'package/LICENSE') ||
    JSON.stringify(licenseAliasAssessment.texts.map((evidence) => evidence.archiveMemberIndex)) !== JSON.stringify([0, 1]) ||
    !licenseAliasFile || licenseAliasFile.archiveMemberIndex !== 0 ||
    JSON.stringify(licenseAliasFile.archiveMemberIndices) !== JSON.stringify([0, 1])) {
    fail('Positive identical license alias evidence did not retain every archive member index')
  }
  const arrayLicenseRaw = [{ type: 'MIT' }, { type: 'Apache-2.0' }]
  const arrayLicenseAssessment = assessLicense({ ...licenseFixturePackage, license: undefined, licenses: arrayLicenseRaw }, licenseFixtureMetadata, licenseFixtureEntries, { inspectionOnly: true })
  if (arrayLicenseAssessment.declaration.source !== 'packageJson.licenses' ||
    JSON.stringify(arrayLicenseAssessment.declaration.raw) !== JSON.stringify(arrayLicenseRaw) ||
    arrayLicenseAssessment.declaration.text !== 'MIT OR Apache-2.0') {
    fail('License array inspection did not preserve the raw declaration and selected source')
  }
  const unresolvedLicenseAssessment = assessLicense({ ...licenseFixturePackage, license: 'LicenseRef-Private' }, licenseFixtureMetadata, licenseFixtureEntries, { inspectionOnly: true })
  if (unresolvedLicenseAssessment.issues.length !== 1 || unresolvedLicenseAssessment.issues[0].code !== 'unsupported-license-identifier' ||
    unresolvedLicenseAssessment.declaration.status !== 'UNRESOLVED' ||
    unresolvedLicenseAssessment.texts[0].sha256 !== supportedLicenseAssessment.texts[0].sha256) {
    fail('Unsupported license declaration was not represented as unresolved with retained text evidence')
  }
  fixtureMustFailWith('strict extraction rejects unresolved declaration',
    'Unsupported SPDX license identifier in the frozen subset: LicenseRef-Private',
    () => assessLicense({ ...licenseFixturePackage, license: 'LicenseRef-Private' }, licenseFixtureMetadata, licenseFixtureEntries))
  const missingLicenseText = assessLicense(licenseFixturePackage, licenseFixtureMetadata, [], { inspectionOnly: true })
  if (!missingLicenseText.issues.some((issue) => issue.code === 'missing-license-notice-text')) {
    fail('Missing license/notice evidence was not represented as an unresolved inspection issue')
  }
  fixtureMustFailWith('strict extraction rejects missing license text',
    'Package archive contains no non-empty license/notice text',
    () => assessLicense(licenseFixturePackage, licenseFixtureMetadata, []))
  const invalidUtf8Bytes = Buffer.from([0xc3, 0x28])
  const invalidUtf8License = assessLicense(licenseFixturePackage, licenseFixtureMetadata, [
    { path: 'package/NOTICE', type: 'file', bytes: invalidUtf8Bytes.byteLength, data: invalidUtf8Bytes, archiveMemberIndex: 0 }
  ], { inspectionOnly: true })
  if (invalidUtf8License.texts[0].utf8 !== null || invalidUtf8License.texts[0].sha256 !== hash(invalidUtf8Bytes, 'sha256') ||
    !invalidUtf8License.issues.some((issue) => issue.code === 'invalid-utf8-license-notice')) {
    fail('Invalid UTF-8 notice was not retained as measured unresolved evidence')
  }
  fixtureMustFailWith('strict extraction rejects invalid UTF-8 notice',
    'License/notice is not strict UTF-8 text: package/NOTICE',
    () => assessLicense(licenseFixturePackage, licenseFixtureMetadata, [
      { path: 'package/NOTICE', type: 'file', bytes: invalidUtf8Bytes.byteLength, data: invalidUtf8Bytes, archiveMemberIndex: 0 }
    ]))
  const emptyLicense = assessLicense(licenseFixturePackage, licenseFixtureMetadata, [
    { path: 'package/COPYING', type: 'file', bytes: 0, data: Buffer.alloc(0), archiveMemberIndex: 0 }
  ], { inspectionOnly: true })
  if (emptyLicense.texts[0].bytes !== 0 || emptyLicense.texts[0].utf8 !== '' ||
    !emptyLicense.issues.some((issue) => issue.code === 'empty-license-notice-text')) {
    fail('Empty license text did not retain measured unresolved evidence')
  }
  fixtureMustFailWith('strict extraction rejects empty-only license text',
    'Package archive contains no non-empty license/notice text',
    () => assessLicense(licenseFixturePackage, licenseFixtureMetadata, [
      { path: 'package/COPYING', type: 'file', bytes: 0, data: Buffer.alloc(0), archiveMemberIndex: 0 }
    ]))
  const emptyAndValidLicense = assessLicense(licenseFixturePackage, licenseFixtureMetadata, [
    { path: 'package/LICENSE.empty', type: 'file', bytes: 0, data: Buffer.alloc(0), archiveMemberIndex: 1 }, ...licenseFixtureEntries
  ], { inspectionOnly: true })
  if (!emptyAndValidLicense.issues.some((issue) => issue.code === 'empty-license-notice-text') ||
    emptyAndValidLicense.texts.length !== 2 || emptyAndValidLicense.texts[0].bytes !== 0 ||
    emptyAndValidLicense.texts[1].path !== 'package/LICENSE') {
    fail('Inspection did not retain the empty matching notice alongside valid text')
  }
  const strictEmptyAndValidLicense = assessLicense(licenseFixturePackage, licenseFixtureMetadata, [
    { path: 'package/LICENSE.empty', type: 'file', bytes: 0, data: Buffer.alloc(0), archiveMemberIndex: 1 }, ...licenseFixtureEntries
  ])
  if (strictEmptyAndValidLicense.issues.length || strictEmptyAndValidLicense.texts.length !== 1 ||
    strictEmptyAndValidLicense.texts[0].path !== 'package/LICENSE') {
    fail('Strict extraction no longer accepts a valid non-empty notice alongside an empty matching file')
  }
  let structuralLicenseFailureEscaped = false
  try { assessLicense(null, licenseFixtureMetadata, licenseFixtureEntries, { inspectionOnly: true }) } catch (error) {
    structuralLicenseFailureEscaped = error instanceof TypeError && error.message === "Cannot read properties of null (reading 'license')"
  }
  if (!structuralLicenseFailureEscaped) fail('Inspection branch did not propagate the exact non-policy TypeError')
  const completePackageJsonBytes = Buffer.from(JSON.stringify({ name: 'fixture-package', version: '1.0.0', license: 'MIT' }), 'utf8')
  const completeLicenseBytes = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('MIT license\n')])
  const completeVendorPaxBytes = fixturePaxRecords([
    ['path', 'package/./LICENSE'], ['NODETAR.follow', 'true'], ['NODETAR.type', 'SymbolicLink'],
    ['NODETAR.package.name', 'attacker-package'], ['NODETAR.package.version', '99.0.0'],
    ['NODETAR.package.description', ''],
    ['NODETAR.package.license', 'LicenseRef-forged'], ['NODETAR.package.scripts.preinstall', 'run-untrusted-command'],
    ['SCHILY.dev', '16777220'], ['SCHILY.ino', '40154246'], ['SCHILY.nlink', '1']
  ])
  const completeLicensePax = completeVendorPaxBytes
  const completeRemirrorPax = fixturePaxRecord('path', 'package/./dist/./remirror-core-constants.cjs')
  const completeRemirrorBytes = Buffer.from('export default remirror\n')
  const completeTar = fixtureTar([
    { path: 'package/./package.json', data: completePackageJsonBytes },
    { path: 'License-Pax', type: 'x', data: completeLicensePax.toString('utf8') },
    { path: 'package/LICENSE-fallback', data: completeLicenseBytes },
    { path: 'package/LICENSE', data: completeLicenseBytes },
    { path: 'package/././LICENSE', data: completeLicenseBytes },
    { path: 'package/./src/./index.js', data: 'export default 1\n' },
    { path: './docs/', headerPrefix: 'package', type: '5' },
    { path: 'Remirror-Pax', type: 'x', data: completeRemirrorPax.toString('utf8') },
    { path: 'package/dist/remirror-fallback.cjs', data: completeRemirrorBytes },
    { path: 'package/dist/remirror-core-constants.cjs', data: completeRemirrorBytes },
    { path: 'package/dist/./remirror-core-constants.cjs', data: completeRemirrorBytes },
    { path: 'package/README.md', data: 'fixture readme\n' },
    { path: 'package/src/util.js', data: 'export const util = true\n' },
    { path: 'package/dist/extra.js', data: 'export const extra = true\n' }
  ])
  const completeSRI = `sha512-${hash(completeTar, 'sha512')}`
  const completeFixtureLock = [
    "lockfileVersion: '9.0'", 'importers:', '  .:', '    dependencies:', '      fixture-package:', '        specifier: 1.0.0',
    '        version: 1.0.0', 'packages:', '  fixture-package@1.0.0:', `    resolution: {integrity: ${completeSRI}}`,
    'snapshots:', '  fixture-package@1.0.0: {}', ''
  ].join('\n')
  const completeExpectedArtifacts = collectClosure(completeFixtureLock).artifacts
  const completeArtifact = {
    ordinal: 0, locator: 'fixture-package@1.0.0', lockIntegrity: completeSRI,
    registryIntegrity: completeSRI, registryTarball: 'https://registry.npmjs.org/fixture-package/-/fixture-package-1.0.0.tgz',
    archiveByteLimit: artifactByteLimit, archive: 'fixture.tgz', bytes: completeTar.byteLength, sha256: hash(completeTar, 'sha256'),
    metadata: 'fixture.json', metadataBytes: 3, metadataSha256: 'b'.repeat(64)
  }
  if (JSON.stringify(Object.keys(completeArtifact).sort()) !== JSON.stringify([...fetchedRecordKeys].sort())) {
    fail('Complete inspection fixture does not use the exact compact fetched-record shape')
  }
  const completeExpectedIdentity = authenticatedExpectedArtifact(completeExpectedArtifacts, 0, completeArtifact, 'complete fixture')
  const completeParsedArchive = parseTar(completeTar, completeExpectedIdentity)
  const completePackageJson = manifestJson(
    completeParsedArchive.entries.find((entry) => entry.path === 'package/package.json').data,
    'Complete inspection fixture package.json'
  )
  const completeLicenseAssessment = assessLicense(completePackageJson, licenseFixtureMetadata, completeParsedArchive.entries, { inspectionOnly: true })
  const completeOutputInventory = planPackageOutputInventory(0, completeParsedArchive.entries, completeExpectedIdentity)
  const completeInspectionPackage = assembleInspectionPackage({
    ordinal: 0, artifact: completeArtifact, expectedIdentity: completeExpectedIdentity, archiveByteLimit: artifactByteLimit,
    packageJson: completePackageJson, licenseAssessment: completeLicenseAssessment,
    parsedArchive: completeParsedArchive, outputInventory: completeOutputInventory
  })
  const completePlannedInventory = packageInventoryRecord(completeInspectionPackage, () => identityReservation, completeExpectedIdentity)
  const completeFinalInventory = packageInventoryRecord(completeInspectionPackage, () => actualPackageIdentity, completeExpectedIdentity)
  const completeCreatedIdentities = new Map(completeFinalInventory.files.map((record) =>
    [`unpacked/${record.path}`, actualPackageIdentity]))
  assertPackageInventoryMatches([completePlannedInventory], [completeFinalInventory], completeCreatedIdentities)
  const completeForgedPaxMembers = completeInspectionPackage.archiveMembers.map((member, index) => index === 1
    ? { ...member, payloadSha256: '0'.repeat(64) } : member)
  fixtureMustFailWith('complete preflight rejects forged PAX payload digest',
    'Inspection preflight archive-member inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(completeParsedArchive, completeForgedPaxMembers,
      completeOutputInventory, 0, completeExpectedIdentity))
  const completeForgedPaxSize = completeInspectionPackage.archiveMembers.map((member, index) => index === 1
    ? { ...member, payloadBytes: member.payloadBytes + 1 } : member)
  fixtureMustFailWith('complete preflight rejects forged PAX payload size',
    'Inspection preflight archive-member inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(completeParsedArchive, completeForgedPaxSize,
      completeOutputInventory, 0, completeExpectedIdentity))
  const completeForgedPaxBinding = completeInspectionPackage.archiveMembers.map((member, index) => index === 1
    ? { ...member, boundToHeaderOffset: member.boundToHeaderOffset + 512 } : member)
  fixtureMustFailWith('complete preflight rejects forged PAX following-header binding',
    'Inspection preflight archive-member inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(completeParsedArchive, completeForgedPaxBinding,
      completeOutputInventory, 0, completeExpectedIdentity))
  fixtureMustFailWith('package reservation rejects forged PAX payload digest',
    'Package archive-member provenance changed at ordinal 0',
    () => packageInventoryRecord({ ...completeInspectionPackage, archiveMembers: completeForgedPaxMembers },
      () => identityReservation, completeExpectedIdentity))
  const expectedOutputPaths = [
    'package-0000', 'package-0000/package', 'package-0000/package/LICENSE', 'package-0000/package/README.md',
    'package-0000/package/dist', 'package-0000/package/dist/extra.js',
    'package-0000/package/dist/remirror-core-constants.cjs', 'package-0000/package/docs',
    'package-0000/package/package.json', 'package-0000/package/src', 'package-0000/package/src/index.js',
    'package-0000/package/src/util.js'
  ]
  const expectedCompleteMemberProvenance = [
    ['file', 'package/./package.json', 'package/./package.json', '', 'package/./package.json', null, 'package/package.json', 'package'],
    ['pax-extension', 'License-Pax', 'License-Pax', '', 'License-Pax', null, null, null],
    ['file', 'package/./LICENSE', 'package/LICENSE-fallback', '', 'package/LICENSE-fallback', 'package/./LICENSE', 'package/LICENSE', 'package'],
    ['file', 'package/LICENSE', 'package/LICENSE', '', 'package/LICENSE', null, 'package/LICENSE', 'package'],
    ['file', 'package/././LICENSE', 'package/././LICENSE', '', 'package/././LICENSE', null, 'package/LICENSE', 'package'],
    ['file', 'package/./src/./index.js', 'package/./src/./index.js', '', 'package/./src/./index.js', null, 'package/src/index.js', 'package'],
    ['directory', 'package/./docs/', './docs/', 'package', 'package/./docs/', null, 'package/docs', 'package'],
    ['pax-extension', 'Remirror-Pax', 'Remirror-Pax', '', 'Remirror-Pax', null, null, null],
    ['file', 'package/./dist/./remirror-core-constants.cjs', 'package/dist/remirror-fallback.cjs', '',
      'package/dist/remirror-fallback.cjs', 'package/./dist/./remirror-core-constants.cjs', 'package/dist/remirror-core-constants.cjs', 'package'],
    ['file', 'package/dist/remirror-core-constants.cjs', 'package/dist/remirror-core-constants.cjs', '', 'package/dist/remirror-core-constants.cjs', null, 'package/dist/remirror-core-constants.cjs', 'package'],
    ['file', 'package/dist/./remirror-core-constants.cjs', 'package/dist/./remirror-core-constants.cjs', '', 'package/dist/./remirror-core-constants.cjs', null, 'package/dist/remirror-core-constants.cjs', 'package'],
    ['file', 'package/README.md', 'package/README.md', '', 'package/README.md', null, 'package/README.md', 'package'],
    ['file', 'package/src/util.js', 'package/src/util.js', '', 'package/src/util.js', null, 'package/src/util.js', 'package'],
    ['file', 'package/dist/extra.js', 'package/dist/extra.js', '', 'package/dist/extra.js', null, 'package/dist/extra.js', 'package']
  ]
  const completeLicenseMembers = completeInspectionPackage.archiveMembers.filter((member) =>
    member.type === 'file' && member.canonicalPath === 'package/LICENSE')
  const completeDirectoryMember = completeInspectionPackage.archiveMembers.find((member) => member.type === 'directory')
  const completeRemirrorMember = completeInspectionPackage.archiveMembers.find((member) => member.paxPath === 'package/./dist/./remirror-core-constants.cjs')
  const completeRemirrorOutput = completeInspectionPackage.files.find((record) => record.path.endsWith('/dist/remirror-core-constants.cjs'))
  if (completeInspectionPackage.archiveMembers.length !== 14 ||
    JSON.stringify(completeInspectionPackage.archiveMembers.map((member) => [member.type, member.rawPath,
      member.headerName, member.headerPrefix, member.headerPath, member.paxPath, member.canonicalPath, member.archiveRoot])) !==
      JSON.stringify(expectedCompleteMemberProvenance) ||
    JSON.stringify(completeInspectionPackage.files.map((record) => record.path)) !== JSON.stringify(expectedOutputPaths) ||
    completeInspectionPackage.files.filter((record) => record.type === 'directory').length !== 5 ||
    completeDirectoryMember?.rawPath !== 'package/./docs/' || completeDirectoryMember.headerName !== './docs/' ||
    completeDirectoryMember.headerPrefix !== 'package' || completeDirectoryMember.headerPath !== 'package/./docs/' ||
    completeDirectoryMember.canonicalPath !== 'package/docs' || completeLicenseMembers.length !== 3 ||
    JSON.stringify(completeLicenseMembers.map((member) => member.index)) !== JSON.stringify([2, 3, 4]) ||
    JSON.stringify(completeLicenseMembers.map((member) => member.outputArchiveMemberIndices)) !== JSON.stringify([[2, 3, 4], [2, 3, 4], [2, 3, 4]]) ||
    completeLicenseMembers[0]?.rawPath !== 'package/./LICENSE' || completeLicenseMembers[0].headerPath !== 'package/LICENSE-fallback' ||
    completeLicenseMembers[0].canonicalPath !== 'package/LICENSE' ||
    completeLicenseMembers[0].paxHeaderIndex !== 1 ||
    completeLicenseMembers[0].headerOffset !== completeInspectionPackage.archiveMembers[1]?.boundToHeaderOffset ||
    completeInspectionPackage.archiveMembers[1]?.payloadBytes !== completeVendorPaxBytes.length ||
    completeInspectionPackage.archiveMembers[1]?.payloadSha256 !== hash(completeVendorPaxBytes, 'sha256') ||
    completePlannedInventory.archiveMembers[1]?.payloadSha256 !== hash(completeVendorPaxBytes, 'sha256') ||
    completeFinalInventory.archiveMembers[1]?.payloadSha256 !== hash(completeVendorPaxBytes, 'sha256') ||
    completeInspectionPackage.archiveMembers[1]?.type !== 'pax-extension' ||
    completeRemirrorMember?.rawPath !== 'package/./dist/./remirror-core-constants.cjs' ||
    completeRemirrorMember.headerPath !== 'package/dist/remirror-fallback.cjs' ||
    completeRemirrorMember.canonicalPath !== 'package/dist/remirror-core-constants.cjs' ||
    completeRemirrorMember.paxHeaderIndex !== 7 ||
    completeRemirrorMember.headerOffset !== completeInspectionPackage.archiveMembers[7]?.boundToHeaderOffset ||
    completeRemirrorMember.outputPrimaryArchiveMemberIndex !== 8 ||
    JSON.stringify(completeRemirrorMember.outputArchiveMemberIndices) !== JSON.stringify([8, 9, 10]) ||
    completeRemirrorOutput?.archiveMemberIndex !== 8 ||
    JSON.stringify(completeRemirrorOutput.archiveMemberIndices) !== JSON.stringify([8, 9, 10]) ||
    completeInspectionPackage.licenseAssessment.texts.length !== 3 ||
    JSON.stringify(completeInspectionPackage.licenseAssessment.texts.map((evidence) => evidence.archiveMemberIndex)) !== JSON.stringify([2, 3, 4]) ||
    completeInspectionPackage.licenseAssessment.texts[0].sha256 !== hash(completeLicenseBytes, 'sha256') ||
    completeInspectionPackage.packageJson.name !== 'fixture-package' || completeInspectionPackage.packageJson.version !== '1.0.0' ||
    completeInspectionPackage.licenseAssessment.declaration.text !== 'MIT' ||
    completeInspectionPackage.licenseAssessment.texts[0].utf8 !== '\ufeffMIT license\n' ||
    Buffer.byteLength(completeInspectionPackage.licenseAssessment.texts[0].utf8, 'utf8') !== completeInspectionPackage.licenseAssessment.texts[0].bytes) {
    fail('Complete multi-member inspection fixture omitted a member, file, synthesized directory, or license digest')
  }
  fixtureMustFailWith('inspection member omission',
    'Inspection preflight archive-member inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(completeParsedArchive, completeParsedArchive.archiveMembers.slice(1),
      completeInspectionPackage.files, 0, completeExpectedIdentity))
  fixtureMustFailWith('inspection output omission',
    'Inspection preflight prospective-output inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(completeParsedArchive, completeParsedArchive.archiveMembers,
      completeInspectionPackage.files.slice(1), 0, completeExpectedIdentity))
  fixtureMustFailWith('inspection output digest tamper',
    'Inspection preflight prospective-output inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(completeParsedArchive, completeParsedArchive.archiveMembers,
      completeInspectionPackage.files.map((record) => record.path.endsWith('/LICENSE') ? { ...record, sha256: '0'.repeat(64) } : record),
      0, completeExpectedIdentity))
  const forgedLayoutMembers = completeParsedArchive.archiveMembers.map((member, index) => index === 2
    ? { ...member, headerLayout: { ...member.headerLayout, headerSha256: '0'.repeat(64) } } : member)
  fixtureMustFailWith('complete archive inventory rejects forged header digest annotation',
    'Inspection preflight archive-member inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(completeParsedArchive, forgedLayoutMembers,
      completeInspectionPackage.files, 0, completeExpectedIdentity))
  const fixtureAcquisition = {
    packageManager: `pnpm@${pnpmVersion}`,
    packageManagerPin: { integrity: pnpmIntegrity, tarball: pnpmTarball, source: pnpmPinSource, sourceSha256: pnpmPinSourceSha256 },
    reconciliation: { reachableSnapshots: 1, snapshotResolutions: [{ snapshot: 'fixture@1.0.0', registryLocator: 'fixture@1.0.0' }] }
  }
  const gnuDirectoryName = 'long-directory-name-' + 'd'.repeat(45)
  const gnuLongFilePath = `package/${gnuDirectoryName}/long-file-${'f'.repeat(55)}.txt`
  const gnuLicenseBytes = Buffer.from('GNU fixture license\n', 'utf8')
  const gnuPackageJsonBytes = Buffer.from(JSON.stringify({ name: 'fixture-gnu', version: '1.0.0', license: 'MIT' }), 'utf8')
  const gnuTar = fixtureTar([
    { path: 'package/package.json', data: gnuPackageJsonBytes },
    { path: 'GNU-L-license', type: 'L', data: Buffer.from('package/./LICENSE\0', 'utf8') },
    { path: 'package/L-short', data: gnuLicenseBytes },
    { path: 'package/LICENSE', data: gnuLicenseBytes },
    { path: 'GNU-L-directory', type: 'L', data: Buffer.from(`package/${gnuDirectoryName}/\0`, 'utf8') },
    { path: 'package/D-short/', type: '5', data: '' },
    { path: 'GNU-L-file', type: 'L', data: Buffer.from(`${gnuLongFilePath}\0`, 'utf8') },
    { path: 'package/F-short', data: 'long GNU path payload\n' }
  ])
  const gnuBinding = compactLockFixture('fixture-gnu', '1.0.0', gnuTar, 'GNU long-name fixture')
  const gnuParsed = parseTar(gnuTar, gnuBinding.identity)
  const gnuOutput = planPackageOutputInventory(0, gnuParsed.entries, gnuBinding.identity)
  assertCompleteInspectionPackageInventory(gnuParsed, gnuParsed.archiveMembers, gnuOutput, 0, gnuBinding.identity)
  const gnuSelected = selectPackageOutputEntries(gnuParsed.entries, gnuOutput, 0, gnuBinding.identity)
  const gnuPackageJson = manifestJson(gnuParsed.entries.find((entry) => entry.path === 'package/package.json').data,
    'GNU long-name fixture package.json')
  const gnuAssessment = assessLicense(gnuPackageJson, licenseFixtureMetadata, gnuParsed.entries, { inspectionOnly: true })
  const gnuInspectionPackage = assembleInspectionPackage({ ordinal: 0, artifact: gnuBinding.artifact,
    expectedIdentity: gnuBinding.identity, archiveByteLimit: artifactByteLimit, packageJson: gnuPackageJson,
    licenseAssessment: gnuAssessment, parsedArchive: gnuParsed, outputInventory: gnuOutput })
  const gnuPlannedPackage = packageInventoryRecord(gnuInspectionPackage, () => identityReservation, gnuBinding.identity)
  const gnuFinalPackage = packageInventoryRecord(gnuInspectionPackage, () => actualPackageIdentity, gnuBinding.identity)
  const gnuOutputIdentities = new Map(gnuFinalPackage.files.map((record) => [`unpacked/${record.path}`, actualPackageIdentity]))
  assertPackageInventoryMatches([gnuPlannedPackage], [gnuFinalPackage], gnuOutputIdentities)
  const gnuExpandedBytes = gnuOutput.filter((record) => record.type === 'file').reduce((sum, record) => sum + record.bytes, 0)
  const gnuDirectoryCount = 1 + gnuOutput.filter((record) => record.type === 'directory').length
  const gnuMetadataIndexes = new Set(gnuParsed.archiveMembers
    .filter((member) => member.type === 'gnu-long-name')
    .map((member) => member.index))
  const gnuOutputReferencesMetadata = (records) => records.some((record) =>
    gnuMetadataIndexes.has(record.archiveMemberIndex) ||
    (Array.isArray(record.archiveMemberIndices) && record.archiveMemberIndices.some((index) => gnuMetadataIndexes.has(index))))
  const gnuReportAssembly = assembleCompleteLicenseInspectionReport([gnuInspectionPackage], fixtureAcquisition, '9'.repeat(64),
    gnuParsed.archiveMembers.length, gnuParsed.archiveExpandedBytes, gnuExpandedBytes, gnuDirectoryCount,
    { perLicenseTextBytes: gnuLicenseBytes.length, aggregateLicenseTextBytes: gnuLicenseBytes.length * 2,
      reportBytes: licenseInspectionReportByteLimit }, [gnuBinding.identity])
  const gnuReport = gnuReportAssembly.report
  const gnuReservationInput = { preflight: [gnuInspectionPackage], sourceManifestSha256: '9'.repeat(64),
    archiveMemberCount: gnuParsed.archiveMembers.length, aggregateArchiveExpandedBytes: gnuParsed.archiveExpandedBytes,
    createdDirectoryCount: gnuDirectoryCount, aggregateExpandedBytes: gnuExpandedBytes,
    trustedExpectedIdentities: [gnuBinding.identity], identityReservation }
  const gnuReservation = reserveExtractionInventory(gnuReservationInput)
  const gnuObservedPlan = gnuReservation.plannedInventory.map((record) => ({ ...record, identity: actualPackageIdentity }))
  const gnuCreatedIdentities = new Map(gnuObservedPlan.map((record) => [record.path, actualPackageIdentity]))
  const gnuFinalExtraction = assembleFinalExtractionInventory(gnuReservation.plannedExtraction, '9'.repeat(64),
    gnuObservedPlan, [gnuFinalPackage], gnuCreatedIdentities)
  const gnuReservationBytes = boundedCompactJsonBytes(gnuReservation.plannedExtraction,
    extractedManifestByteLimit, 'Extracted inventory manifest reservation')
  const gnuFinalInventoryBytes = boundedCompactJsonBytes(gnuFinalExtraction,
    extractedManifestByteLimit, 'Extracted inventory manifest')
  const gnuExactInventoryCap = gnuReservationBytes.byteLength
  const gnuExactReservation = reserveExtractionInventory({ ...gnuReservationInput, manifestByteLimit: gnuExactInventoryCap })
  const gnuRoundTripReport = JSON.parse(gnuReportAssembly.bytes.toString('utf8'))
  const gnuRoundTripInventory = JSON.parse(gnuReservationBytes.toString('utf8'))
  const gnuRoundTripFinalInventory = JSON.parse(gnuFinalInventoryBytes.toString('utf8'))
  const expectedGnuReportBytes = Buffer.from(`${JSON.stringify(gnuReport)}\n`, 'utf8')
  const expectedGnuReservationBytes = Buffer.from(`${JSON.stringify(gnuReservation.plannedExtraction)}\n`, 'utf8')
  const expectedGnuFinalInventoryBytes = Buffer.from(`${JSON.stringify(gnuFinalExtraction)}\n`, 'utf8')
  if (!gnuReservationBytes.equals(gnuReservation.reservedManifestBytes) ||
    gnuReservationBytes.byteLength > extractedManifestByteLimit ||
    gnuFinalInventoryBytes.byteLength > gnuReservationBytes.byteLength ||
    !gnuExactReservation.reservedManifestBytes.equals(gnuReservationBytes) ||
    !gnuReservationBytes.equals(expectedGnuReservationBytes) ||
    !gnuFinalInventoryBytes.equals(expectedGnuFinalInventoryBytes) ||
    !gnuReportAssembly.bytes.equals(expectedGnuReportBytes) ||
    JSON.stringify(gnuRoundTripReport) !== JSON.stringify(gnuReport) ||
    JSON.stringify(gnuRoundTripInventory) !== JSON.stringify(gnuReservation.plannedExtraction) ||
    JSON.stringify(gnuRoundTripFinalInventory) !== JSON.stringify(gnuFinalExtraction) ||
    Buffer.byteLength(gnuReportAssembly.bytes.toString('utf8'), 'utf8') !== gnuReportAssembly.bytes.byteLength ||
    gnuReportAssembly.bytes[gnuReportAssembly.bytes.byteLength - 1] !== 0x0a ||
    gnuReportAssembly.bytes.byteLength >= jsonBytes(gnuReport).byteLength ||
    Buffer.byteLength(gnuReservationBytes.toString('utf8'), 'utf8') !== gnuReservationBytes.byteLength ||
    gnuReservationBytes[gnuReservationBytes.byteLength - 1] !== 0x0a ||
    !JSON.stringify(gnuReservation.plannedExtraction).includes(identityReservation.dev) ||
    JSON.stringify(gnuReservation.plannedExtraction) !== JSON.stringify(JSON.parse(jsonBytes(gnuReservation.plannedExtraction).toString('utf8'))) ||
    JSON.stringify(gnuReport) !== JSON.stringify(JSON.parse(jsonBytes(gnuReport).toString('utf8'))) ||
    gnuReservationBytes.byteLength >= jsonBytes(gnuReservation.plannedExtraction).byteLength ||
    gnuRoundTripReport.packages[0].archiveMembers[2].headerBytesHex !== gnuParsed.archiveMembers[2].headerBytesHex ||
    JSON.stringify(gnuRoundTripReport.packages[0].prospectiveOutputInventory) !== JSON.stringify(gnuOutput) ||
    JSON.stringify(gnuRoundTripInventory.packages[0].archiveMembers) !== JSON.stringify(gnuParsed.archiveMembers) ||
    JSON.stringify(gnuRoundTripInventory.outputInventory[0].identity) !== JSON.stringify(identityReservation)) {
    fail('Compact report/inventory serialization changed semantics, byte accounting, or maximum-width identity reservation')
  }
  fixtureMustFailWith('compact extracted inventory reservation one byte below exact fit',
    `Extracted inventory manifest reservation exceeds its ${gnuExactInventoryCap - 1}-byte output limit`,
    () => reserveExtractionInventory({ ...gnuReservationInput, manifestByteLimit: gnuExactInventoryCap - 1 }))
  fixtureMustFailWith('internal extracted inventory cap cannot exceed the fixed production limit',
    'Extraction inventory reservation inputs are incomplete or malformed',
    () => reserveExtractionInventory({ ...gnuReservationInput, manifestByteLimit: extractedManifestByteLimit + 1 }))
  if (gnuParsed.archiveMembers.length !== 8 || gnuParsed.entries.length !== 5 || gnuSelected.length !== 3 ||
    gnuParsed.archiveMembers.filter((member) => member.type === 'gnu-long-name').length !== 3 ||
    gnuOutput.some((record) => record.path.includes('GNU-L') || record.path.includes('long-name-record')) ||
    gnuParsed.archiveMembers.some((member) => member.type === 'gnu-long-name' && member.archiveRoot !== null) ||
    gnuParsed.archiveMembers.some((member) => member.type === 'gnu-long-name' && member.gnuLongNameMetadataIndex !== null) ||
    gnuParsed.archiveMembers[2]?.gnuLongNameMetadataIndex !== 1 ||
    gnuParsed.archiveMembers[2]?.gnuLongNamePath !== 'package/./LICENSE' ||
    gnuParsed.archiveMembers[1]?.targetHeaderOffset !== gnuParsed.archiveMembers[2]?.headerOffset ||
    gnuParsed.archiveMembers[4]?.targetHeaderOffset !== gnuParsed.archiveMembers[5]?.headerOffset ||
    gnuParsed.archiveMembers[6]?.targetHeaderOffset !== gnuParsed.archiveMembers[7]?.headerOffset ||
    gnuParsed.archiveMembers[1]?.payloadBytes !== Buffer.byteLength('package/./LICENSE\0') ||
    gnuParsed.archiveMembers[1]?.payloadSha256 !== hash(Buffer.from('package/./LICENSE\0'), 'sha256') ||
    gnuMetadataIndexes.size !== 3 ||
    [...gnuMetadataIndexes].some((index) => gnuParsed.archiveMembers[index]?.archiveRoot !== null ||
      gnuParsed.archiveMembers[index]?.gnuLongNameMetadataIndex !== null) ||
    gnuParsed.entries.some((entry) => gnuMetadataIndexes.has(entry.archiveMemberIndex)) ||
    gnuOutputReferencesMetadata(gnuOutput) ||
    gnuSelected.some((entry) => gnuMetadataIndexes.has(entry.archiveMemberIndex)) ||
    JSON.stringify(gnuSelected.map((entry) => entry.path).sort()) !== JSON.stringify([
      gnuLongFilePath, 'package/LICENSE', 'package/package.json'
    ].sort()) ||
    !gnuOutput.some((record) => record.path === 'package-0000/package/package.json' && record.type === 'file' &&
      JSON.stringify(record.archiveMemberIndices) === JSON.stringify([0])) ||
    !gnuOutput.some((record) => record.path === `package-0000/package/LICENSE` && record.type === 'file' &&
      JSON.stringify(record.archiveMemberIndices) === JSON.stringify([2, 3])) ||
    !gnuOutput.some((record) => record.path === `package-0000/package/${gnuDirectoryName}` && record.type === 'directory' &&
      record.provenance === 'archive-explicit' && record.archiveMemberIndex === 5) ||
    !gnuOutput.some((record) => record.path === `package-0000/${gnuLongFilePath}` && record.type === 'file' &&
      JSON.stringify(record.archiveMemberIndices) === JSON.stringify([7])) ||
    gnuOutputReferencesMetadata(gnuInspectionPackage.files) ||
    gnuAssessment.texts.some((record) => gnuMetadataIndexes.has(record.archiveMemberIndex)) ||
    gnuInspectionPackage.archiveMembersSha256 !== archiveMemberInventorySha256(gnuParsed.archiveMembers) ||
    gnuReport.schema !== 'comfy-canvas-license-inspection/v7' ||
    gnuReport.archiveMemberCount !== gnuParsed.archiveMembers.length ||
    gnuReport.packages[0].archiveMembers.length !== gnuParsed.archiveMembers.length ||
    gnuOutputReferencesMetadata(gnuReport.packages[0].prospectiveOutputInventory) ||
    !gnuReport.packages[0].prospectiveOutputInventory.some((record) => record.path.includes(gnuDirectoryName)) ||
    gnuReport.packages[0].prospectiveOutputInventory.some((record) => record.path.includes('GNU-L')) ||
    gnuReservation.plannedExtraction.schema !== 'comfy-canvas-extracted-build-closure/v9' ||
    gnuFinalExtraction.schema !== 'comfy-canvas-extracted-build-closure/v9' ||
    gnuReservation.plannedExtraction.archiveMemberCount !== gnuParsed.archiveMembers.length ||
    gnuReservation.plannedExtraction.createdDirectoryCount !== gnuDirectoryCount ||
    gnuReservation.plannedExtraction.outputPathCount !== gnuReservation.plannedInventory.length ||
    gnuReservation.plannedExtraction.aggregateArchiveExpandedBytes !== gnuParsed.archiveExpandedBytes ||
    gnuReservation.plannedExtraction.aggregateExpandedBytes !== gnuExpandedBytes ||
    gnuReservation.plannedExtraction.packages[0].archiveMembers.length !== gnuParsed.archiveMembers.length ||
    gnuOutputReferencesMetadata(gnuReservation.plannedExtraction.packages[0].files) ||
    gnuOutputReferencesMetadata(gnuReservation.plannedInventory) ||
    gnuFinalExtraction.packages[0].archiveMembers.length !== gnuParsed.archiveMembers.length ||
    gnuOutputReferencesMetadata(gnuFinalExtraction.packages[0].files) ||
    gnuOutputReferencesMetadata(gnuFinalExtraction.outputInventory)) {
    fail('GNU long-name positive fixture lost member, payload, alias, output exclusion, or report/reservation/final provenance')
  }
  const gnuRecheck = [{ ordinal: 0, locator: gnuBinding.artifact.locator, archiveBytes: gnuBinding.artifact.bytes,
    archiveSha256: gnuBinding.artifact.sha256, archiveByteLimit: artifactByteLimit,
    lockIntegrity: gnuBinding.artifact.lockIntegrity, registryIntegrity: gnuBinding.artifact.registryIntegrity,
    archiveSha512: gnuBinding.artifact.lockIntegrity, archiveExpandedBytes: gnuParsed.archiveExpandedBytes,
    archiveRoot: gnuParsed.archiveRoot, headerLayoutSha256: headerLayoutInventorySha256(gnuParsed.archiveMembers),
    archiveMembersSha256: archiveMemberInventorySha256(gnuParsed.archiveMembers), packageName: 'fixture-gnu',
    packageVersion: '1.0.0', metadataBytes: gnuBinding.artifact.metadataBytes,
    metadataSha256: gnuBinding.artifact.metadataSha256 }]
  if (gnuRecheck[0].archiveMembersSha256 !== archiveMemberInventorySha256(gnuParsed.archiveMembers) ||
    gnuRecheck[0].headerLayoutSha256 !== headerLayoutInventorySha256(gnuParsed.archiveMembers) ||
    gnuOutputReferencesMetadata(gnuAssessment.texts)) {
    fail('GNU long-name positive fixture lost complete recheck or notice-output metadata exclusion')
  }
  assertInspectionRecheckFacts(Buffer.from('gnu-manifest'), Buffer.from('gnu-manifest'),
    [gnuInspectionPackage], gnuRecheck, [gnuBinding.identity])
  const gnuFinalArguments = (plannedExtraction) => [plannedExtraction, '9'.repeat(64), gnuObservedPlan,
    [gnuFinalPackage], gnuCreatedIdentities]
  const gnuReservationCounterCases = [
    ['archive-member', { archiveMemberCount: gnuParsed.archiveMembers.length - 1 }],
    ['archive-expanded-byte', { aggregateArchiveExpandedBytes: gnuParsed.archiveExpandedBytes - 1 }],
    ['created-directory', { createdDirectoryCount: gnuDirectoryCount - 1 }],
    ['expanded-output-byte', { aggregateExpandedBytes: gnuExpandedBytes + 1 }]
  ]
  for (const [label, changed] of gnuReservationCounterCases) {
    fixtureMustFailWith(`GNU reservation independently rejects forged ${label} count`,
      'Extraction inventory reservation counters differ from complete package/output inventory',
      () => reserveExtractionInventory({ preflight: [gnuInspectionPackage], sourceManifestSha256: '9'.repeat(64),
        archiveMemberCount: changed.archiveMemberCount ?? gnuParsed.archiveMembers.length,
        aggregateArchiveExpandedBytes: changed.aggregateArchiveExpandedBytes ?? gnuParsed.archiveExpandedBytes,
        createdDirectoryCount: changed.createdDirectoryCount ?? gnuDirectoryCount,
        aggregateExpandedBytes: changed.aggregateExpandedBytes ?? gnuExpandedBytes,
        trustedExpectedIdentities: [gnuBinding.identity], identityReservation }))
  }
  const gnuFinalCounterCases = [
    ...gnuReservationCounterCases,
    ['output-path', { outputPathCount: gnuReservation.plannedInventory.length - 1 }]
  ]
  for (const [label, changed] of gnuFinalCounterCases) {
    fixtureMustFailWith(`GNU final inventory rejects reserved ${label} count mutation`,
      'Final extraction reservation counters differ from complete final package/output inventory',
      () => assembleFinalExtractionInventory(...gnuFinalArguments({ ...gnuReservation.plannedExtraction, ...changed })))
  }
  const gnuForgeMembers = (change) => {
    const members = gnuParsed.archiveMembers.map((member) => ({ ...member }))
    change(members)
    return members
  }
  const gnuReaggregate = (archiveMembers) => ({
    ...gnuInspectionPackage,
    archiveMembers,
    archiveMembersSha256: archiveMemberInventorySha256(archiveMembers),
    headerLayoutSha256: headerLayoutInventorySha256(archiveMembers)
  })
  const forgedGnuPayload = gnuForgeMembers((members) => {
    members[1].gnuLongNamePayloadHex = Buffer.from('package/./LICENSF\0').toString('hex')
  })
  const forgedGnuPath = gnuForgeMembers((members) => { members[1].gnuLongNamePath = 'package/./LICENSF' })
  const forgedGnuHeader = gnuForgeMembers((members) => {
    members[1].headerLayout = { ...members[1].headerLayout, headerSha256: '0'.repeat(64) }
  })
  const forgedGnuHeaderBytes = gnuForgeMembers((members) => { members[1].headerBytesHex = '00'.repeat(512) })
  const forgedGnuIndex = gnuForgeMembers((members) => { members[2].gnuLongNameMetadataIndex = 0 })
  const forgedGnuBinding = gnuForgeMembers((members) => { members[1].targetHeaderOffset += 512 })
  const forgedGnuDigest = gnuForgeMembers((members) => { members[1].payloadSha256 = '0'.repeat(64) })
  const forgedGnuCount = gnuParsed.archiveMembers.filter((_, index) => index !== 1)
  fixtureMustFailWith('GNU long-name production inspection rejects forged payload bytes',
    'Inspection preflight archive-member inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(gnuParsed, forgedGnuPayload, gnuOutput, 0, gnuBinding.identity))
  fixtureMustFailWith('GNU long-name production member-to-entry check rejects forged reciprocal index',
    'Inspection preflight archive entry is missing from full member inventory: package/LICENSE',
    () => assertCompleteInspectionPackageInventory({
      ...gnuParsed,
      entries: gnuParsed.entries.map((entry) => entry.archiveMemberIndex === 2
        ? { ...entry, gnuLongNameMetadataIndex: 0 } : entry)
    }, gnuParsed.archiveMembers, gnuOutput, 0, gnuBinding.identity))
  fixtureMustFailWith('GNU long-name production reservation rejects forged decoded path',
    'GNU long-name payload or immediate-target offset provenance is forged',
    () => packageInventoryRecord(gnuReaggregate(forgedGnuPath), () => identityReservation, gnuBinding.identity))
  fixtureMustFailWith('GNU long-name production report rejects forged header digest',
    'Tar member full header bytes do not match the header digest',
    () => packageInventoryRecord(gnuReaggregate(forgedGnuHeader), () => identityReservation, gnuBinding.identity))
  fixtureMustFailWith('GNU long-name production report rejects forged complete header bytes',
    'Tar member full header bytes do not match the header digest',
    () => packageInventoryRecord(gnuReaggregate(forgedGnuHeaderBytes), () => identityReservation, gnuBinding.identity))
  fixtureMustFailWith('GNU long-name production package seam rejects forged target index',
    'GNU long-name metadata is not reciprocally bound to its immediate target',
    () => packageInventoryRecord(gnuReaggregate(forgedGnuIndex), () => identityReservation, gnuBinding.identity))
  fixtureMustFailWith('GNU long-name production package seam rejects forged target offset',
    'GNU long-name payload or immediate-target offset provenance is forged',
    () => packageInventoryRecord(gnuReaggregate(forgedGnuBinding), () => identityReservation, gnuBinding.identity))
  fixtureMustFailWith('GNU long-name production package seam rejects forged payload digest after reaggregation',
    'GNU long-name payload or immediate-target offset provenance is forged',
    () => packageInventoryRecord(gnuReaggregate(forgedGnuDigest), () => identityReservation, gnuBinding.identity))
  fixtureMustFailWith('GNU long-name production package seam rejects omitted metadata after reaggregation',
    'Tar archive-member header offsets are missing or noncontiguous',
    () => packageInventoryRecord(gnuReaggregate(forgedGnuCount), () => identityReservation, gnuBinding.identity))
  fixtureMustFailWith('GNU long-name report rejects incorrect member count',
    'Complete inspection preflight counters differ from full member/output inventory',
    () => assembleCompleteLicenseInspectionReport([gnuInspectionPackage], fixtureAcquisition, '9'.repeat(64),
      gnuParsed.archiveMembers.length - 1, gnuParsed.archiveExpandedBytes, gnuExpandedBytes, gnuDirectoryCount,
      { perLicenseTextBytes: gnuLicenseBytes.length, aggregateLicenseTextBytes: gnuLicenseBytes.length * 2,
        reportBytes: licenseInspectionReportByteLimit }, [gnuBinding.identity]))
  fixtureMustFailWith('GNU long-name report rejects forged path after digest recomputation',
    'GNU long-name payload or immediate-target offset provenance is forged',
    () => assembleCompleteLicenseInspectionReport([gnuReaggregate(forgedGnuPath)], fixtureAcquisition, '9'.repeat(64),
      gnuParsed.archiveMembers.length, gnuParsed.archiveExpandedBytes, gnuExpandedBytes, gnuDirectoryCount,
      { perLicenseTextBytes: gnuLicenseBytes.length, aggregateLicenseTextBytes: gnuLicenseBytes.length * 2,
        reportBytes: licenseInspectionReportByteLimit }, [gnuBinding.identity]))
  fixtureMustFailWith('GNU long-name metadata cannot be injected into output inventory',
    'Inspection preflight prospective-output inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(gnuParsed, gnuParsed.archiveMembers,
      [...gnuOutput, { path: 'package-0000/GNU-L-license', type: 'file', bytes: 0, sha256: '0'.repeat(64),
        provenance: 'archive-file', archiveMemberIndex: 1, archiveMemberIndices: [1] }], 0, gnuBinding.identity))
  fixtureMustFailWith('GNU long-name recheck validates reciprocal annotations after digest recomputation',
    'GNU long-name payload or immediate-target offset provenance is forged',
    () => assertInspectionRecheckFacts(Buffer.from('gnu-manifest'), Buffer.from('gnu-manifest'),
      [gnuReaggregate(forgedGnuPath)], [{ ...gnuRecheck[0], archiveMembersSha256: archiveMemberInventorySha256(forgedGnuPath),
        headerLayoutSha256: headerLayoutInventorySha256(forgedGnuPath) }], [gnuBinding.identity]))
  fixtureMustFailWith('GNU long-name final inventory compares reserved member provenance',
    'Final package inventory schema or cap differs from preflight at ordinal 0',
    () => assembleFinalExtractionInventory(gnuReservation.plannedExtraction, '9'.repeat(64), gnuObservedPlan,
      [{ ...gnuFinalPackage, archiveMembers: forgedGnuPath }], gnuCreatedIdentities))
  const gnuDirectAttributionPath = 'package-0000/package/package.json'
  const gnuDirectAttributionMatches = gnuOutput.filter((record) => record.path === gnuDirectAttributionPath && record.type === 'file')
  const gnuDirectMetadataIndex = gnuParsed.archiveMembers.find((member) => member.type === 'gnu-long-name')?.index
  if (gnuDirectAttributionMatches.length !== 1 || !Number.isSafeInteger(gnuDirectMetadataIndex) ||
    gnuParsed.archiveMembers[gnuDirectMetadataIndex]?.type !== 'gnu-long-name' ||
    gnuDirectAttributionMatches[0].archiveMemberIndex === gnuDirectMetadataIndex) {
    fail('GNU direct-attribution negative does not uniquely identify a valid file and metadata member')
  }
  const forgedGnuDirectAttribution = gnuOutput.map((record) => ({
    ...record,
    ...(Array.isArray(record.archiveMemberIndices) ? { archiveMemberIndices: [...record.archiveMemberIndices] } : {})
  }))
  const forgedGnuDirectTarget = forgedGnuDirectAttribution.find((record) => record.path === gnuDirectAttributionPath)
  const originalGnuDirectIndex = forgedGnuDirectTarget.archiveMemberIndex
  forgedGnuDirectTarget.archiveMemberIndex = gnuDirectMetadataIndex
  if (forgedGnuDirectAttribution.length !== gnuOutput.length ||
    forgedGnuDirectAttribution.some((record, index) => index !== gnuOutput.indexOf(gnuDirectAttributionMatches[0]) &&
      JSON.stringify(record) !== JSON.stringify(gnuOutput[index])) ||
    JSON.stringify({ ...forgedGnuDirectTarget, archiveMemberIndex: originalGnuDirectIndex }) !==
      JSON.stringify(gnuDirectAttributionMatches[0]) || originalGnuDirectIndex === forgedGnuDirectTarget.archiveMemberIndex) {
    fail('GNU direct-attribution negative changes facts beyond its unique file index')
  }
  fixtureMustFailWith('GNU long-name output rejects direct attribution to a metadata member',
    'Inspection preflight prospective-output inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(gnuParsed, gnuParsed.archiveMembers,
      forgedGnuDirectAttribution, 0, gnuBinding.identity))

  const gnuAliasAttributionPath = 'package-0000/package/LICENSE'
  const gnuAliasAttributionMatches = gnuOutput.filter((record) => record.path === gnuAliasAttributionPath && record.type === 'file')
  const gnuAliasMetadataIndex = gnuParsed.archiveMembers.find((member) => member.type === 'gnu-long-name')?.index
  if (gnuAliasAttributionMatches.length !== 1 || !Number.isSafeInteger(gnuAliasMetadataIndex) ||
    gnuParsed.archiveMembers[gnuAliasMetadataIndex]?.type !== 'gnu-long-name' ||
    !Array.isArray(gnuAliasAttributionMatches[0].archiveMemberIndices) ||
    gnuAliasAttributionMatches[0].archiveMemberIndices.length !== 2 ||
    gnuAliasAttributionMatches[0].archiveMemberIndices.includes(gnuAliasMetadataIndex)) {
    fail('GNU alias-attribution negative does not uniquely identify a valid alias file and metadata member')
  }
  const forgedGnuAliasAttribution = gnuOutput.map((record) => ({
    ...record,
    ...(Array.isArray(record.archiveMemberIndices) ? { archiveMemberIndices: [...record.archiveMemberIndices] } : {})
  }))
  const forgedGnuAliasTarget = forgedGnuAliasAttribution.find((record) => record.path === gnuAliasAttributionPath)
  const originalGnuAliasIndices = [...forgedGnuAliasTarget.archiveMemberIndices]
  forgedGnuAliasTarget.archiveMemberIndices[0] = gnuAliasMetadataIndex
  if (forgedGnuAliasAttribution.length !== gnuOutput.length ||
    forgedGnuAliasAttribution.some((record, index) => index !== gnuOutput.indexOf(gnuAliasAttributionMatches[0]) &&
      JSON.stringify(record) !== JSON.stringify(gnuOutput[index])) ||
    JSON.stringify({ ...forgedGnuAliasTarget, archiveMemberIndices: originalGnuAliasIndices }) !==
      JSON.stringify(gnuAliasAttributionMatches[0]) || forgedGnuAliasTarget.archiveMemberIndices[0] === originalGnuAliasIndices[0] ||
    forgedGnuAliasTarget.archiveMemberIndices[1] !== originalGnuAliasIndices[1]) {
    fail('GNU alias-attribution negative changes facts beyond one alias member index')
  }
  fixtureMustFailWith('GNU long-name output rejects alias attribution to a metadata member',
    'Inspection preflight prospective-output inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(gnuParsed, gnuParsed.archiveMembers,
      forgedGnuAliasAttribution, 0, gnuBinding.identity))

  const gnuMakeTar = (longPath, targetPath = 'package/short-name', targetType = '0', payload = 'x') => fixtureTar([
    { path: 'GNU-L', type: 'L', data: Buffer.isBuffer(longPath) ? longPath : Buffer.from(longPath, 'utf8') },
    { path: targetPath, type: targetType, data: payload }
  ])
  fixtureMustFailWith('GNU long-name missing NUL terminator', 'GNU long-name payload requires a nonempty NUL-terminated path and zero-only remainder',
    () => parseTar(gnuMakeTar(Buffer.from('package/a.txt', 'utf8')), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name nonzero post-NUL bytes', 'GNU long-name payload requires a nonempty NUL-terminated path and zero-only remainder',
    () => parseTar(gnuMakeTar(Buffer.from([0x70, 0, 0x78])), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name invalid UTF-8', 'GNU long-name path is not strict UTF-8',
    () => parseTar(gnuMakeTar(Buffer.from([0xc3, 0x28, 0])), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name payload lower bound', 'GNU long-name payload must contain 2..4096 bytes',
    () => parseTar(gnuMakeTar(Buffer.alloc(1, 0)), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name payload upper bound', 'GNU long-name payload must contain 2..4096 bytes',
    () => parseTar(gnuMakeTar(Buffer.concat([Buffer.from('p\0'), Buffer.alloc(4_095)])), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name empty decoded path', 'GNU long-name payload requires a nonempty NUL-terminated path and zero-only remainder',
    () => parseTar(gnuMakeTar(Buffer.from([0, 0])), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name unsafe traversal', 'Tar member path contains parent traversal: package/../escape',
    () => parseTar(gnuMakeTar(Buffer.from('package/../escape\0'), 'package/short'), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name unauthorized root', 'Unexpected npm tar root: other/escape',
    () => parseTar(gnuMakeTar(Buffer.from('other/escape\0'), 'package/short'), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name target root mismatch reaches the shared header/effective-root guard',
    'Tar header/effective path roots differ: fixture-gnu-v1.0.0 / package',
    () => parseTar(gnuMakeTar(Buffer.from('package/escape\0'), 'fixture-gnu-v1.0.0/short'), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name forged target root binding is rejected independently',
    'GNU long-name target root or canonical path provenance differs from its short header',
    () => assertGnuLongNameBindings(gnuForgeMembers((members) => {
      members[2].archiveRoot = 'fixture-gnu-v1.0.0'
    }), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name stacked metadata', 'GNU long-name record cannot stack or combine with PAX metadata',
    () => parseTar(fixtureTar([{ path: 'GNU-L-1', type: 'L', data: 'package/a\0' },
      { path: 'GNU-L-2', type: 'L', data: 'package/b\0' }, { path: 'package/b', data: 'x' }]), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name then PAX conflict', 'GNU long-name record cannot stack or combine with PAX metadata',
    () => parseTar(fixtureTar([{ path: 'GNU-L', type: 'L', data: 'package/a\0' },
      { path: 'PaxHeader', type: 'x', data: fixturePaxRecord('path', 'package/a').toString('utf8') },
      { path: 'package/a', data: 'x' }]), gnuBinding.identity))
  fixtureMustFailWith('PAX then GNU long-name conflict', 'GNU long-name metadata cannot combine with pending PAX metadata',
    () => parseTar(fixtureTar([{ path: 'PaxHeader', type: 'x', data: fixturePaxRecord('path', 'package/a').toString('utf8') },
      { path: 'GNU-L', type: 'L', data: 'package/a\0' }, { path: 'package/a', data: 'x' }]), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name missing target', 'Tar archive ended with an unconsumed GNU long-name record',
    () => parseTar(fixtureTar([{ path: 'GNU-L', type: 'L', data: 'package/a\0' }]), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name unsupported target', 'GNU long-name record targets unsupported tar member type "2"',
    () => parseTar(gnuMakeTar(Buffer.from('package/a\0'), 'package/link', '2'), gnuBinding.identity))
  const badGnuPadding = fixtureTarRaw([{ path: 'GNU-L', type: 'L', data: 'package/a\0' },
    { path: 'package/a', data: 'x' }])
  badGnuPadding[512 + Buffer.byteLength('package/a\0')] = 1
  fixtureMustFailWith('GNU long-name nonzero payload padding', 'Tar member data padding contains nonzero bytes',
    () => parseTar(gzipSync(badGnuPadding), gnuBinding.identity))
  const badGnuHeader = fixtureTarRaw([{ path: 'GNU-L', type: 'L', data: 'package/a\0' },
    { path: 'package/a', data: 'x' }])
  badGnuHeader[0] ^= 1
  fixtureMustFailWith('GNU long-name bad header checksum', 'Tar header checksum mismatch',
    () => parseTar(gzipSync(badGnuHeader), gnuBinding.identity))
  fixtureMustFailWith('GNU long-name archive requires two complete end blocks',
    'Tar archive requires two complete zero end blocks',
    () => parseTar(fixtureTar([{ path: 'package/a', data: 'x' }], 1), gnuBinding.identity))
  const truncatedGnuHeader = fixtureTarHeader('GNU-L', 12, 'L')
  const truncatedGnuPayloadBytes = Buffer.from('package/a\0', 'utf8')
  const truncatedGnuPayload = Buffer.concat([truncatedGnuHeader, truncatedGnuPayloadBytes])
  const truncatedGnuDeclaredBytes = tarOctal(truncatedGnuHeader, 124, 12)
  const truncatedGnuAvailableBytes = truncatedGnuPayload.length - truncatedGnuHeader.length
  if (truncatedGnuDeclaredBytes !== 12 || truncatedGnuAvailableBytes !== 10 ||
    truncatedGnuAvailableBytes >= truncatedGnuDeclaredBytes ||
    truncatedGnuPayload.length >= truncatedGnuHeader.length + truncatedGnuDeclaredBytes) {
    fail('GNU long-name truncated-payload fixture does not end inside its declared payload extent')
  }
  fixtureMustFailWith('GNU long-name truncated declared payload extent', 'Tar member size is invalid',
    () => parseTar(gzipSync(truncatedGnuPayload), gnuBinding.identity))
  const typesPackageJson = manifestJson(typesRootArchive.entries.find((entry) => entry.path === 'package/package.json').data,
    'Authenticated @types root fixture package.json')
  const typesLicenseAssessment = assessLicense(typesPackageJson, licenseFixtureMetadata, typesRootArchive.entries, { inspectionOnly: true })
  const typesExpectedIdentity = typesArchiveIdentity
  const typesInspectionPackage = assembleInspectionPackage({
    ordinal: 0, artifact: typesArtifact, expectedIdentity: typesExpectedIdentity, archiveByteLimit: artifactByteLimit,
    packageJson: typesPackageJson, licenseAssessment: typesLicenseAssessment,
    parsedArchive: typesRootArchive, outputInventory: typesRootOutput
  })
  fixtureMustFailWith('inspection root identity must match lock artifact name/version',
    'Inspection package at ordinal 0 package manifest identity mismatch',
    () => assembleInspectionPackage({ ordinal: 0, artifact: typesArtifact,
      expectedIdentity: typesExpectedIdentity,
      archiveByteLimit: artifactByteLimit, packageJson: { ...typesPackageJson, name: '@types/other' }, licenseAssessment: typesLicenseAssessment,
      parsedArchive: typesRootArchive, outputInventory: typesRootOutput }))
  const typesArchiveExpandedBytes = typesRootArchive.archiveExpandedBytes
  const typesExpandedBytes = typesRootOutput.filter((record) => record.type === 'file')
    .reduce((total, record) => total + record.bytes, 0)
  const typesDirectoryCount = 1 + typesRootOutput.filter((record) => record.type === 'directory').length
  const typesReport = assembleCompleteLicenseInspectionReport([typesInspectionPackage], fixtureAcquisition, 'f'.repeat(64),
    typesRootArchive.archiveMembers.length, typesArchiveExpandedBytes, typesExpandedBytes, typesDirectoryCount,
    { perLicenseTextBytes: typesLicenseBytes.length, aggregateLicenseTextBytes: typesLicenseBytes.length,
      reportBytes: licenseInspectionReportByteLimit }, [typesExpectedIdentity]).report
  fixtureMustFailWith('report builder rejects substituted lock identity',
    'Complete inspection lock identity differs from authenticated closure at ordinal 0',
    () => assembleCompleteLicenseInspectionReport([typesInspectionPackage], fixtureAcquisition, 'f'.repeat(64),
      typesRootArchive.archiveMembers.length, typesArchiveExpandedBytes, typesExpandedBytes, typesDirectoryCount, {},
      [{ ...typesExpectedIdentity, locator: `${typesExpectedIdentity.locator}(fixture-peer@1.0.0)` }]))
  if (typesInspectionPackage.archiveRoot !== 'argparse' || typesInspectionPackage.packageJson.name !== typesPackageName ||
    typesReport.schema !== 'comfy-canvas-license-inspection/v7' || typesReport.packages[0]?.archiveRoot !== 'argparse' ||
    typesReport.packages[0]?.name !== typesPackageName ||
    typesReport.packages[0]?.archiveMembers.some((member) => (member.type === 'file' || member.type === 'directory') && member.archiveRoot !== 'argparse') ||
    typesReport.packages[0]?.prospectiveOutputInventory.some((record) => record.path !== 'package-0000' &&
      record.path !== 'package-0000/package' && !record.path.startsWith('package-0000/package/')) ||
    typesReport.packages[0]?.licenseTexts[0]?.archiveMemberIndex !== 3) {
    fail('@types root report lost authenticated identity, raw root provenance, canonical package outputs, or license member binding')
  }
  fixtureMustFailWith('tampered @types member-root report binding',
    'Inspection preflight archive-member inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(typesRootArchive,
      typesRootArchive.archiveMembers.map((member, index) => index === 3 ? { ...member, archiveRoot: 'package' } : member),
      typesRootOutput, 0, typesExpectedIdentity))
  const typesRecheckFixture = [{ ordinal: 0, locator: typesArtifact.locator, archiveBytes: typesArtifact.bytes,
    archiveSha256: typesArtifact.sha256, archiveByteLimit: artifactByteLimit,
    lockIntegrity: typesArtifact.lockIntegrity, registryIntegrity: typesArtifact.registryIntegrity,
    archiveSha512: typesArtifact.lockIntegrity, archiveExpandedBytes: typesArchiveExpandedBytes, archiveRoot: 'argparse',
    headerLayoutSha256: headerLayoutInventorySha256(typesInspectionPackage.archiveMembers),
    archiveMembersSha256: archiveMemberInventorySha256(typesInspectionPackage.archiveMembers),
    packageName: typesExpectedIdentity.name, packageVersion: typesExpectedIdentity.version,
    metadataBytes: typesArtifact.metadataBytes, metadataSha256: typesArtifact.metadataSha256 }]
  const typesManifestFixture = Buffer.from('types-acquisition-manifest')
  assertInspectionRecheckFacts(typesManifestFixture, Buffer.from(typesManifestFixture), [typesInspectionPackage], typesRecheckFixture,
    [typesExpectedIdentity])
  fixtureMustFailWith('recheck builder rejects substituted lock identity',
    'Inspection archive/metadata recheck differs from complete preflight at ordinal 0',
    () => assertInspectionRecheckFacts(typesManifestFixture, Buffer.from(typesManifestFixture), [typesInspectionPackage],
      typesRecheckFixture, [{ ...typesExpectedIdentity, locator: `${typesExpectedIdentity.locator}(fixture-peer@1.0.0)` }]))
  fixtureMustFailWith('tampered @types archive root on recheck',
    'Inspection archive/metadata recheck differs from complete preflight at ordinal 0',
    () => assertInspectionRecheckFacts(typesManifestFixture, Buffer.from(typesManifestFixture), [typesInspectionPackage],
      [{ ...typesRecheckFixture[0], archiveRoot: 'package' }], [typesExpectedIdentity]))
  fixtureMustFailWith('tampered @types package name on recheck',
    'Inspection archive/metadata recheck differs from complete preflight at ordinal 0',
    () => assertInspectionRecheckFacts(typesManifestFixture, Buffer.from(typesManifestFixture), [typesInspectionPackage],
      [{ ...typesRecheckFixture[0], packageName: '@types/other' }], [typesExpectedIdentity]))
  const typesPlannedPackageInventory = packageInventoryRecord(typesInspectionPackage, () => identityReservation, typesExpectedIdentity)
  const typesFinalPackageInventory = packageInventoryRecord(typesInspectionPackage, () => actualPackageIdentity, typesExpectedIdentity)
  fixtureMustFailWith('package-root reservation must bind the lock artifact identity',
    'Archive member root provenance differs from its authenticated package identity: argparse/',
    () => packageInventoryRecord({ ...typesInspectionPackage, archiveRoot: 'package' }, () => identityReservation, typesExpectedIdentity))
  const typesPackageIdentities = new Map(typesInspectionPackage.files.map((record) =>
    [`unpacked/${record.path}`, actualPackageIdentity]))
  assertPackageInventoryMatches([typesPlannedPackageInventory], [typesFinalPackageInventory], typesPackageIdentities)
  fixtureMustFailWith('tampered @types package root in final inventory',
    'Final package inventory schema or cap differs from preflight at ordinal 0',
    () => assertPackageInventoryMatches([typesPlannedPackageInventory],
      [{ ...typesFinalPackageInventory, archiveRoot: 'package' }], typesPackageIdentities))
  fixtureMustFailWith('tampered @types root in report package',
    'Archive member root provenance differs from its authenticated package identity: argparse/',
    () => assembleCompleteLicenseInspectionReport([{ ...typesInspectionPackage, archiveRoot: 'package' },
    ], fixtureAcquisition, 'f'.repeat(64), typesRootArchive.archiveMembers.length, typesArchiveExpandedBytes,
    typesExpandedBytes, typesDirectoryCount, { perLicenseTextBytes: typesLicenseBytes.length,
      aggregateLicenseTextBytes: typesLicenseBytes.length, reportBytes: licenseInspectionReportByteLimit }, [typesExpectedIdentity]))
  const markdownPackageJson = manifestJson(markdownRootArchive.entries.find((entry) => entry.path === 'package/package.json').data,
    'Versioned @types fixture package.json')
  const markdownLicenseAssessment = assessLicense(markdownPackageJson, licenseFixtureMetadata, markdownRootArchive.entries,
    { inspectionOnly: true })
  const markdownOutput = planPackageOutputInventory(0, markdownRootArchive.entries, markdownRootBinding.identity)
  const markdownSelected = selectPackageOutputEntries(markdownRootArchive.entries, markdownOutput, 0, markdownRootBinding.identity)
  const markdownInspectionPackage = assembleInspectionPackage({ ordinal: 0, artifact: markdownRootBinding.artifact,
    expectedIdentity: markdownRootBinding.identity, archiveByteLimit: artifactByteLimit, packageJson: markdownPackageJson,
    licenseAssessment: markdownLicenseAssessment, parsedArchive: markdownRootArchive, outputInventory: markdownOutput })
  const markdownExpandedBytes = markdownOutput.filter((record) => record.type === 'file').reduce((total, record) => total + record.bytes, 0)
  const markdownDirectoryCount = 1 + markdownOutput.filter((record) => record.type === 'directory').length
  const markdownReport = assembleCompleteLicenseInspectionReport([markdownInspectionPackage], fixtureAcquisition, 'd'.repeat(64),
    markdownRootArchive.archiveMembers.length, markdownRootArchive.archiveExpandedBytes, markdownExpandedBytes, markdownDirectoryCount,
    { perLicenseTextBytes: typesLicenseBytes.length, aggregateLicenseTextBytes: typesLicenseBytes.length,
      reportBytes: licenseInspectionReportByteLimit }, [markdownRootBinding.identity]).report
  const markdownPlannedInventory = packageInventoryRecord(markdownInspectionPackage, () => identityReservation, markdownRootBinding.identity)
  const markdownFinalInventory = packageInventoryRecord(markdownInspectionPackage, () => actualPackageIdentity, markdownRootBinding.identity)
  const markdownOutputIdentities = new Map(markdownInspectionPackage.files.map((record) =>
    [`unpacked/${record.path}`, actualPackageIdentity]))
  assertPackageInventoryMatches([markdownPlannedInventory], [markdownFinalInventory], markdownOutputIdentities)
  const markdownRecheck = [{ ordinal: 0, locator: markdownRootBinding.artifact.locator,
    archiveBytes: markdownRootBinding.artifact.bytes, archiveSha256: markdownRootBinding.artifact.sha256,
    archiveByteLimit: artifactByteLimit, lockIntegrity: markdownRootBinding.artifact.lockIntegrity,
    registryIntegrity: markdownRootBinding.artifact.registryIntegrity, archiveSha512: markdownRootBinding.artifact.lockIntegrity,
    archiveExpandedBytes: markdownRootArchive.archiveExpandedBytes, archiveRoot: 'markdown-it v13.0',
    headerLayoutSha256: headerLayoutInventorySha256(markdownInspectionPackage.archiveMembers),
    archiveMembersSha256: archiveMemberInventorySha256(markdownInspectionPackage.archiveMembers),
    packageName: markdownRootBinding.identity.name, packageVersion: markdownRootBinding.identity.version,
    metadataBytes: markdownRootBinding.artifact.metadataBytes, metadataSha256: markdownRootBinding.artifact.metadataSha256 }]
  assertInspectionRecheckFacts(Buffer.from('markdown-manifest'), Buffer.from('markdown-manifest'),
    [markdownInspectionPackage], markdownRecheck, [markdownRootBinding.identity])
  if (markdownInspectionPackage.archiveRoot !== 'markdown-it v13.0' ||
    markdownReport.packages[0]?.archiveRoot !== 'markdown-it v13.0' ||
    markdownReport.packages[0]?.prospectiveOutputInventory.some((record) => record.path !== 'package-0000' &&
      record.path !== 'package-0000/package' && !record.path.startsWith('package-0000/package/')) ||
    markdownSelected.some((entry) => entry.archiveRoot !== 'markdown-it v13.0') ||
    markdownFinalInventory.archiveRoot !== 'markdown-it v13.0') {
    fail('Versioned @types lock identity did not survive production selection, report, reservation/final inventory, and recheck')
  }
  fixtureMustFailWith('versioned @types forged output identity is not accepted',
    'Unexpected npm tar root: markdown-it v13.0/',
    () => planPackageOutputInventory(0, markdownRootArchive.entries, { ...markdownRootBinding.identity, version: '13.1.9' }))
  fixtureMustFailWith('versioned @types recheck rejects changed trusted version',
    'Inspection archive/metadata recheck differs from complete preflight at ordinal 0',
    () => assertInspectionRecheckFacts(Buffer.from('markdown-manifest'), Buffer.from('markdown-manifest'),
      [markdownInspectionPackage], markdownRecheck, [{ ...markdownRootBinding.identity, version: '13.1.9' }]))
  fixtureMustFailWith('versioned @types package root annotation is rebound to lock identity',
    'Archive member root provenance differs from its authenticated package identity: markdown-it v13.0/',
    () => packageInventoryRecord({ ...markdownInspectionPackage, archiveRoot: 'package' },
      () => identityReservation, markdownRootBinding.identity))
  fixtureMustFailWith('versioned @types report root annotation is rebound to lock identity',
    'Archive member root provenance differs from its authenticated package identity: markdown-it v13.0/',
    () => assembleCompleteLicenseInspectionReport([{ ...markdownInspectionPackage, archiveRoot: 'package' }],
      fixtureAcquisition, 'd'.repeat(64), markdownRootArchive.archiveMembers.length,
      markdownRootArchive.archiveExpandedBytes, markdownExpandedBytes, markdownDirectoryCount,
      { perLicenseTextBytes: typesLicenseBytes.length, aggregateLicenseTextBytes: typesLicenseBytes.length,
        reportBytes: licenseInspectionReportByteLimit }, [markdownRootBinding.identity]))
  const ordinaryVersionedRootCases = [
    { name: 'ejs', version: '3.1.10', root: 'ejs-v3.1.10' },
    { name: 'jake', version: '10.9.4', root: 'jake-v10.9.4' },
    { name: 'filelist', version: '1.0.6', root: 'FileList-v1.0.6' },
    { name: 'fixture-casefold', version: '2.7.11', root: 'Fixture-CaseFold-v2.7.11' }
  ]
  const ordinaryVersionedRootFixtures = []
  for (const [index, testCase] of ordinaryVersionedRootCases.entries()) {
    const packageJsonBytes = Buffer.from(JSON.stringify({ name: testCase.name, version: testCase.version, license: 'MIT' }), 'utf8')
    const ordinaryRootTar = fixtureTar([
      { path: `${testCase.root}/`, type: '5' },
      { path: `PaxHeader-${index}`, type: 'x', data: fixturePaxRecord('path', `${testCase.root}/./LICENSE`).toString('utf8') },
      { path: `${testCase.root}/LICENSE-fallback`, data: typesLicenseBytes },
      { path: `${testCase.root}/package.json`, data: packageJsonBytes }
    ])
    const binding = compactLockFixture(testCase.name, testCase.version, ordinaryRootTar, `ordinary root ${testCase.name}`)
    const parsedArchive = parseTar(ordinaryRootTar, binding.identity)
    const outputInventory = planPackageOutputInventory(0, parsedArchive.entries, binding.identity)
    const selectedEntries = selectPackageOutputEntries(parsedArchive.entries, outputInventory, 0, binding.identity)
    const packageJson = manifestJson(parsedArchive.entries.find((entry) => entry.path === 'package/package.json').data,
      `Ordinary versioned root ${testCase.name} package.json`)
    const licenseAssessment = assessLicense(packageJson, licenseFixtureMetadata, parsedArchive.entries, { inspectionOnly: true })
    const inspectionPackage = assembleInspectionPackage({ ordinal: 0, artifact: binding.artifact,
      expectedIdentity: binding.identity, archiveByteLimit: artifactByteLimit, packageJson, licenseAssessment,
      parsedArchive, outputInventory })
    const plannedInventory = packageInventoryRecord(inspectionPackage, () => identityReservation, binding.identity)
    const finalInventory = packageInventoryRecord(inspectionPackage, () => actualPackageIdentity, binding.identity)
    const outputIdentities = new Map(inspectionPackage.files.map((record) => [`unpacked/${record.path}`, actualPackageIdentity]))
    assertPackageInventoryMatches([plannedInventory], [finalInventory], outputIdentities)
    const expandedBytes = outputInventory.filter((record) => record.type === 'file')
      .reduce((total, record) => total + record.bytes, 0)
    const directoryCount = 1 + outputInventory.filter((record) => record.type === 'directory').length
    const report = assembleCompleteLicenseInspectionReport([inspectionPackage], fixtureAcquisition, 'a'.repeat(64),
      parsedArchive.archiveMembers.length, parsedArchive.archiveExpandedBytes, expandedBytes, directoryCount,
      { perLicenseTextBytes: typesLicenseBytes.length, aggregateLicenseTextBytes: typesLicenseBytes.length,
        reportBytes: licenseInspectionReportByteLimit }, [binding.identity]).report
    const recheck = [{ ordinal: 0, locator: binding.artifact.locator, archiveBytes: binding.artifact.bytes,
      archiveSha256: binding.artifact.sha256, archiveByteLimit: artifactByteLimit,
      lockIntegrity: binding.artifact.lockIntegrity, registryIntegrity: binding.artifact.registryIntegrity,
      archiveSha512: binding.artifact.lockIntegrity, archiveExpandedBytes: parsedArchive.archiveExpandedBytes,
      archiveRoot: testCase.root, headerLayoutSha256: headerLayoutInventorySha256(inspectionPackage.archiveMembers),
      archiveMembersSha256: inspectionPackage.archiveMembersSha256, packageName: binding.identity.name,
      packageVersion: binding.identity.version, metadataBytes: binding.artifact.metadataBytes,
      metadataSha256: binding.artifact.metadataSha256 }]
    assertInspectionRecheckFacts(Buffer.from(`ordinary-${testCase.name}-manifest`),
      Buffer.from(`ordinary-${testCase.name}-manifest`), [inspectionPackage], recheck, [binding.identity])
    if (parsedArchive.archiveRoot !== testCase.root || selectedEntries.some((entry) => entry.archiveRoot !== testCase.root) ||
      inspectionPackage.archiveRoot !== testCase.root || plannedInventory.archiveRoot !== testCase.root ||
      finalInventory.archiveRoot !== testCase.root || report.packages[0]?.archiveRoot !== testCase.root ||
      report.packages[0]?.name !== testCase.name || parsedArchive.expectedIdentity?.name !== testCase.name) {
      fail(`Ordinary versioned root lost authenticated package or raw-root provenance: ${testCase.name}`)
    }
    ordinaryVersionedRootFixtures.push({ ...testCase, binding, tar: ordinaryRootTar, parsedArchive, inspectionPackage, recheck })
  }
  const ejsRootFixture = ordinaryVersionedRootFixtures[0]
  const exactOracleSelfControl = (label, action) => {
    const expectedFailure = `Source fixture did not fail for the expected reason: ${label}`
    let rejectedByOracle = false
    try { fixtureMustFailWith(label, 'the intended validation diagnostic', action) } catch (error) {
      rejectedByOracle = error?.message === expectedFailure
    }
    if (!rejectedByOracle) fail(`Exact-message fixture oracle accepted a broken action: ${label}`)
  }
  exactOracleSelfControl('oracle rejects a non-callable action', null)
  exactOracleSelfControl('oracle rejects an unexpected TypeError', () => { throw new TypeError('incidental failure') })
  if (!safeTypesArchiveRootComponent(ejsRootFixture.root)) {
    fail('Positive safe root-component control was rejected')
  }
  for (const unsafeComponent of ['CON', 'CON.txt', 'bad:root', 'trailing.', 'trailing ', 'nonascii\u00e9',
    'control\u0001', 'x'.repeat(tarPathComponentByteLimit + 1)]) {
    if (safeTypesArchiveRootComponent(unsafeComponent)) {
      fail(`Unsafe root-component control was accepted: ${unsafeComponent.slice(0, 36)}`)
    }
  }
  for (const invalidRoot of ['ejs-V3.1.10', 'ejs_v3.1.10', 'ejs-v3.1.11', 'EJS-v3.1.10x', 'other-v3.1.10']) {
    fixtureMustFailWith(`ordinary versioned root rejects altered spelling ${invalidRoot}`,
      `Unexpected npm tar root: ${invalidRoot}/LICENSE`,
      () => parseTar(fixtureTar([{ path: `${invalidRoot}/LICENSE`, data: typesLicenseBytes }]), ejsRootFixture.binding.identity))
  }
  fixtureMustFailWith('ordinary versioned root rejects package name mismatch',
    'Unexpected npm tar root: other-v3.1.10/LICENSE',
    () => parseTar(fixtureTar([{ path: 'other-v3.1.10/LICENSE', data: typesLicenseBytes }]), ejsRootFixture.binding.identity))
  fixtureMustFailWith('ordinary versioned root rejects package version mismatch',
    'Unexpected npm tar root: ejs-v3.1.11/LICENSE',
    () => parseTar(fixtureTar([{ path: 'ejs-v3.1.11/LICENSE', data: typesLicenseBytes }]), ejsRootFixture.binding.identity))
  fixtureMustFailWith('ordinary versioned root requires authenticated identity',
    'Unexpected npm tar root: ejs-v3.1.10/LICENSE',
    () => parseTar(fixtureTar([{ path: 'ejs-v3.1.10/LICENSE', data: typesLicenseBytes }])))
  fixtureMustFailWith('ordinary versioned root rejects malformed identity',
    'Unexpected npm tar root: ejs-v3.1.10/LICENSE',
    () => parseTar(fixtureTar([{ path: 'ejs-v3.1.10/LICENSE', data: typesLicenseBytes }]),
      { ...ejsRootFixture.binding.identity, locator: 'other@3.1.10' }))
  const scopedOrdinaryTar = fixtureTar([{ path: 'package/LICENSE', data: typesLicenseBytes }])
  const scopedOrdinaryBinding = compactLockFixture('@scope/ejs', '3.1.10', scopedOrdinaryTar,
    'scoped ordinary root')
  const scopedOrdinaryCandidateRoot = `${scopedOrdinaryBinding.identity.name}-v${scopedOrdinaryBinding.identity.version}`
  if (scopedOrdinaryBinding.identity.name !== '@scope/ejs' ||
    scopedOrdinaryBinding.identity.version !== '3.1.10' ||
    expectedOrdinaryVersionedArchiveRoot(scopedOrdinaryBinding.identity) !== null) {
    fail('Scoped ordinary root control did not retain a consistent lock identity or reject at the ordinary-root predicate')
  }
  fixtureMustFailWith('ordinary versioned root rejects its internally consistent scoped identity root',
    `Archive root ${JSON.stringify(scopedOrdinaryCandidateRoot)} is not authorized by authenticated package identity "@scope/ejs"`,
    () => assertSelectedArchiveRoot(scopedOrdinaryBinding.identity, scopedOrdinaryCandidateRoot))
  fixtureMustFailWith('ordinary versioned root rejects scoped identity archive path',
    'Unexpected npm tar root: @scope/ejs-v3.1.10/LICENSE',
    () => parseTar(fixtureTar([{ path: '@scope/ejs-v3.1.10/LICENSE', data: typesLicenseBytes }]),
      scopedOrdinaryBinding.identity))
  for (const malformedVersion of ['03.1.10', '3.01.10', '3.1.010', '9007199254740992.1.10', '3.1.10-beta', '3.1.10+build']) {
    const malformedRoot = `ejs-v${malformedVersion}`
    const malformedTar = fixtureTar([{ path: 'package/LICENSE', data: typesLicenseBytes }])
    const malformedBinding = compactLockFixture('ejs', malformedVersion, malformedTar,
      `malformed ordinary version ${malformedVersion}`)
    if (malformedBinding.identity.name !== 'ejs' || malformedBinding.identity.version !== malformedVersion ||
      malformedRoot !== `${malformedBinding.identity.name}-v${malformedBinding.identity.version}`) {
      fail(`Malformed-version root control lost its internally consistent lock identity: ${malformedVersion}`)
    }
    fixtureMustFailWith(`ordinary versioned root rejects internally consistent noncanonical version ${malformedVersion}`,
      `Archive root ${JSON.stringify(malformedRoot)} is not authorized by authenticated package identity "ejs"`,
      () => assertSelectedArchiveRoot(malformedBinding.identity, malformedRoot))
  }
  fixtureMustFailWith('ordinary versioned root rejects traversal after authenticated basename',
    'Tar member path contains parent traversal: ejs-v3.1.10/../escape',
    () => parseTar(fixtureTar([{ path: 'ejs-v3.1.10/../escape', data: 'x' }]), ejsRootFixture.binding.identity))
  fixtureMustFailWith('ordinary versioned root rejects ADS in member path',
    'Ambiguous tar member path: ejs-v3.1.10/stream:meta',
    () => parseTar(fixtureTar([{ path: 'ejs-v3.1.10/stream:meta', data: 'x' }]), ejsRootFixture.binding.identity))
  fixtureMustFailWith('ordinary versioned root rejects Windows device member path',
    'Ambiguous tar member path: ejs-v3.1.10/CON.txt',
    () => parseTar(fixtureTar([{ path: 'ejs-v3.1.10/CON.txt', data: 'x' }]), ejsRootFixture.binding.identity))
  fixtureMustFailWith('ordinary versioned root rejects control member path at the pure path seam',
    'Ambiguous tar member path: package/\u0001',
    () => validateTarPath('package/\u0001', { expectedIdentity: ejsRootFixture.binding.identity }))
  const overlongMemberComponent = 'x'.repeat(tarPathComponentByteLimit + 1)
  fixtureMustFailWith('ordinary versioned root rejects overlong member component at the pure path seam',
    `Tar member path component exceeds its ${tarPathComponentByteLimit}-byte bound: package/${overlongMemberComponent}`,
    () => validateTarPath(`package/${overlongMemberComponent}`, { expectedIdentity: ejsRootFixture.binding.identity }))
  fixtureMustFailWith('ordinary versioned root rejects Unicode member path',
    'Ambiguous tar member path: ejs-v3.1.10/\u00e9',
    () => parseTar(fixtureTar([
      { path: 'PaxHeader-unicode', type: 'x', data: fixturePaxRecord('path', 'ejs-v3.1.10/\u00e9').toString('utf8') },
      { path: 'ejs-v3.1.10/fallback', data: 'x' }
    ]), ejsRootFixture.binding.identity))
  fixtureMustFailWith('ordinary versioned root rejects PAX header/effective root drift',
    'Tar header/effective path roots differ: package / ejs-v3.1.10',
    () => parseTar(fixtureTar([
      { path: 'PaxHeader-root-drift', type: 'x', data: fixturePaxRecord('path', 'ejs-v3.1.10/LICENSE').toString('utf8') },
      { path: 'package/fallback', data: 'x' }
    ]), ejsRootFixture.binding.identity))
  fixtureMustFailWith('ordinary versioned root rejects mixed case aliases as distinct raw roots',
    'Tar archive mixes effective roots: ejs-v3.1.10 / EJS-v3.1.10',
    () => parseTar(fixtureTar([{ path: 'ejs-v3.1.10/LICENSE', data: 'x' },
      { path: 'EJS-v3.1.10/README.md', data: 'x' }]), ejsRootFixture.binding.identity))
  fixtureMustFailWith('ordinary versioned root rejects forged archive-member root provenance',
    'Inspection preflight archive-member inventory is incomplete or changed',
    () => assertCompleteInspectionPackageInventory(ejsRootFixture.parsedArchive,
      ejsRootFixture.parsedArchive.archiveMembers.map((member, index) => index === 1
        ? { ...member, archiveRoot: 'ejs-v3.1.10' } : member), ejsRootFixture.inspectionPackage.files, 0,
      ejsRootFixture.binding.identity))
  fixtureMustFailWith('ordinary versioned root rejects forged reservation root annotation',
    'Archive member root provenance differs from its authenticated package identity: ejs-v3.1.10/',
    () => packageInventoryRecord({ ...ejsRootFixture.inspectionPackage, archiveRoot: 'package' },
      () => identityReservation, ejsRootFixture.binding.identity))
  fixtureMustFailWith('ordinary versioned root rejects later recheck root tamper',
    'Inspection archive/metadata recheck differs from complete preflight at ordinal 0',
    () => assertInspectionRecheckFacts(Buffer.from('ordinary-ejs-manifest'), Buffer.from('ordinary-ejs-manifest'),
      [ejsRootFixture.inspectionPackage], [{ ...ejsRootFixture.recheck[0], archiveRoot: 'package' }],
      [ejsRootFixture.binding.identity]))
  const completeMemberCount = completeInspectionPackage.archiveMembers.length
  const completeArchiveExpandedBytes = completeInspectionPackage.archiveExpandedBytes
  if (assertPackageArchiveExpansion([completeInspectionPackage], completeArchiveExpandedBytes) !== completeArchiveExpandedBytes) {
    fail('Package archive-expansion aggregate positive fixture differs')
  }
  fixtureMustFailWith('package archive-expansion aggregate mismatch',
    'Package archive-expansion aggregate differs from measured archive total',
    () => assertPackageArchiveExpansion([completeInspectionPackage], completeArchiveExpandedBytes - 1))
  const secondArchiveExpansionPackage = { ...completeInspectionPackage, ordinal: 1 }
  fixtureMustFailWith('package archive-expansion package omission',
    'Package archive-expansion aggregate differs from measured archive total',
    () => assertPackageArchiveExpansion([completeInspectionPackage], completeArchiveExpandedBytes * 2))
  if (assertPackageArchiveExpansion([completeInspectionPackage, secondArchiveExpansionPackage],
    completeArchiveExpandedBytes * 2) !== completeArchiveExpandedBytes * 2) {
    fail('Package archive-expansion multi-package positive fixture differs')
  }
  const completeExpandedBytes = completeInspectionPackage.files.filter((record) => record.type === 'file').reduce((total, record) => total + record.bytes, 0)
  const completeDirectoryCount = 1 + completeInspectionPackage.files.filter((record) => record.type === 'directory').length
  const reportCaps = { perLicenseTextBytes: 15, aggregateLicenseTextBytes: 45, reportBytes: licenseInspectionReportByteLimit }
  const reportAssembly = assembleCompleteLicenseInspectionReport([completeInspectionPackage], fixtureAcquisition,
    'c'.repeat(64), completeMemberCount, completeArchiveExpandedBytes, completeExpandedBytes, completeDirectoryCount,
    reportCaps, [completeExpectedIdentity])
  const reportFixture = reportAssembly.report
  if (reportFixture.schema !== 'comfy-canvas-license-inspection/v7' || reportFixture.reportPath !== licenseInspectionReportRelative ||
    reportFixture.packages[0].licenseTexts[0].utf8 !== '\ufeffMIT license\n' || reportFixture.lockSha256 !== lockSha256 ||
    JSON.stringify(reportFixture.packages[0].licenseTexts.map((evidence) => evidence.archiveMemberIndex)) !== JSON.stringify([2, 3, 4]) ||
    reportFixture.packageManager !== `pnpm@${pnpmVersion}` ||
    JSON.stringify(reportFixture.packages[0].archiveMembers) !== JSON.stringify(completeParsedArchive.archiveMembers) ||
    reportFixture.packages[0].archiveMembers[1]?.payloadSha256 !== hash(completeVendorPaxBytes, 'sha256') ||
    reportFixture.packages[0].name !== 'fixture-package' || reportFixture.packages[0].version !== '1.0.0' ||
    reportFixture.packages[0].declaredLicense?.text !== 'MIT' ||
    reportFixture.packages[0].headerLayoutSha256 !== headerLayoutInventorySha256(completeParsedArchive.archiveMembers) ||
    JSON.stringify(reportFixture.packages[0].prospectiveOutputInventory) !== JSON.stringify(completeOutputInventory) ||
    reportFixture.aggregateArchiveExpandedBytes !== completeArchiveExpandedBytes ||
    reportFixture.packages[0].archiveExpandedBytes !== completeArchiveExpandedBytes ||
    reportFixture.inspectionLimits.perLicenseTextBytes !== 15 || reportAssembly.bytes.byteLength > reportCaps.reportBytes) {
    fail('Complete inspection report omitted provenance, exact inventories, or injected finite caps')
  }
  fixtureMustFailWith('report rejects forged member header-layout annotation',
    'Tar member full header bytes do not match the header digest',
    () => assembleCompleteLicenseInspectionReport([{
      ...completeInspectionPackage,
      archiveMembers: completeInspectionPackage.archiveMembers.map((member, index) => index === 0
        ? { ...member, headerLayout: { ...member.headerLayout, headerSha256: '0'.repeat(64) } } : member)
    }], fixtureAcquisition, 'c'.repeat(64), completeMemberCount, completeArchiveExpandedBytes,
    completeExpandedBytes, completeDirectoryCount, reportCaps, [completeExpectedIdentity]))
  let exactReportCap = reportAssembly.bytes.byteLength
  let exactReportAssembly
  for (let attempt = 0; attempt < 8; attempt++) {
    exactReportAssembly = assembleCompleteLicenseInspectionReport([completeInspectionPackage], fixtureAcquisition, 'c'.repeat(64),
      completeMemberCount, completeArchiveExpandedBytes, completeExpandedBytes, completeDirectoryCount,
      { ...reportCaps, reportBytes: exactReportCap }, [completeExpectedIdentity])
    if (exactReportAssembly.bytes.byteLength === exactReportCap) break
    exactReportCap = exactReportAssembly.bytes.byteLength
  }
  if (exactReportAssembly.bytes.byteLength !== exactReportCap) fail('Inspection report exact-cap fixture did not converge')
  fixtureMustFailWith('inspection report cap through complete assembler',
    `License inspection report exceeds its ${exactReportCap - 1}-byte output limit`,
    () => assembleCompleteLicenseInspectionReport([completeInspectionPackage], fixtureAcquisition, 'c'.repeat(64),
      completeMemberCount, completeArchiveExpandedBytes, completeExpandedBytes, completeDirectoryCount,
      { ...reportCaps, reportBytes: exactReportCap - 1 }, [completeExpectedIdentity]))
  fixtureMustFailWith('inspection per-text cap', 'Inspection license evidence exceeds or violates its finite schema: package/LICENSE',
    () => assembleCompleteLicenseInspectionReport([completeInspectionPackage], fixtureAcquisition, 'c'.repeat(64),
      completeMemberCount, completeArchiveExpandedBytes, completeExpandedBytes, completeDirectoryCount,
      { ...reportCaps, perLicenseTextBytes: 11 }, [completeExpectedIdentity]))
  fixtureMustFailWith('inspection alias evidence member tamper',
    'Inspection license evidence exceeds or violates its finite schema: package/LICENSE',
    () => assembleCompleteLicenseInspectionReport([{
      ...completeInspectionPackage,
      licenseAssessment: { ...completeInspectionPackage.licenseAssessment,
        texts: completeInspectionPackage.licenseAssessment.texts.map((evidence, index) => index === 1
          ? { ...evidence, archiveMemberIndex: 2 } : evidence) }
    }], fixtureAcquisition, 'c'.repeat(64), completeMemberCount, completeArchiveExpandedBytes,
      completeExpandedBytes, completeDirectoryCount, reportCaps, [completeExpectedIdentity]))
  fixtureMustFailWith('report rejects forged PAX payload annotation',
    'Complete inspection header-layout inventory changed at ordinal 0',
    () => assembleCompleteLicenseInspectionReport([{
      ...completeInspectionPackage, archiveMembers: completeForgedPaxMembers
    }], fixtureAcquisition, 'c'.repeat(64), completeMemberCount, completeArchiveExpandedBytes,
    completeExpandedBytes, completeDirectoryCount, reportCaps, [completeExpectedIdentity]))
  fixtureMustFailWith('inspection alias evidence omission', 'Inspection license evidence omits or adds an archive member at ordinal 0',
    () => assembleCompleteLicenseInspectionReport([{
      ...completeInspectionPackage,
      licenseAssessment: { ...completeInspectionPackage.licenseAssessment,
        texts: completeInspectionPackage.licenseAssessment.texts.slice(1) }
    }], fixtureAcquisition, 'c'.repeat(64), completeMemberCount, completeArchiveExpandedBytes,
      completeExpandedBytes, completeDirectoryCount, reportCaps, [completeExpectedIdentity]))
  fixtureMustFailWith('inspection aggregate-text cap', 'Aggregate license/notice text inspection bound exceeded',
    () => assembleCompleteLicenseInspectionReport([completeInspectionPackage], fixtureAcquisition, 'c'.repeat(64),
      completeMemberCount, completeArchiveExpandedBytes, completeExpandedBytes, completeDirectoryCount,
      { ...reportCaps, aggregateLicenseTextBytes: 11 }, [completeExpectedIdentity]))
  const manifestFixture = Buffer.from('complete-acquisition-manifest')
  const recheckFixture = [{ ordinal: 0, locator: completeArtifact.locator, archiveBytes: completeArtifact.bytes,
    archiveSha256: completeArtifact.sha256, archiveByteLimit: artifactByteLimit,
    lockIntegrity: completeArtifact.lockIntegrity, registryIntegrity: completeArtifact.registryIntegrity,
    archiveSha512: `sha512-${hash(completeTar, 'sha512')}`,
    archiveExpandedBytes: completeArchiveExpandedBytes,
    archiveRoot: completeInspectionPackage.archiveRoot,
    headerLayoutSha256: headerLayoutInventorySha256(completeInspectionPackage.archiveMembers),
    archiveMembersSha256: archiveMemberInventorySha256(completeInspectionPackage.archiveMembers),
    packageName: completeExpectedIdentity.name, packageVersion: completeExpectedIdentity.version,
    metadataBytes: completeArtifact.metadataBytes, metadataSha256: completeArtifact.metadataSha256 }]
  assertInspectionRecheckFacts(manifestFixture, Buffer.from(manifestFixture), [completeInspectionPackage], recheckFixture,
    [completeExpectedIdentity])
  fixtureMustFailWith('recheck rejects forged PAX payload annotation',
    'Inspection archive/metadata recheck differs from complete preflight at ordinal 0',
    () => assertInspectionRecheckFacts(manifestFixture, Buffer.from(manifestFixture),
      [{ ...completeInspectionPackage, archiveMembers: completeForgedPaxMembers }], recheckFixture,
      [completeExpectedIdentity]))
  fixtureMustFailWith('inspection recheck omission', 'Inspection archive/metadata recheck count differs from complete preflight',
    () => assertInspectionRecheckFacts(manifestFixture, Buffer.from(manifestFixture), [completeInspectionPackage], [],
      [completeExpectedIdentity]))
  fixtureMustFailWith('inspection recheck tamper', 'Inspection archive/metadata recheck differs from complete preflight at ordinal 0',
    () => assertInspectionRecheckFacts(manifestFixture, Buffer.from(manifestFixture), [completeInspectionPackage],
      [{ ...recheckFixture[0], archiveSha256: '0'.repeat(64) }], [completeExpectedIdentity]))
  fixtureMustFailWith('inspection archive expansion recheck tamper',
    'Inspection archive/metadata recheck differs from complete preflight at ordinal 0',
    () => assertInspectionRecheckFacts(manifestFixture, Buffer.from(manifestFixture), [completeInspectionPackage],
      [{ ...recheckFixture[0], archiveExpandedBytes: completeArchiveExpandedBytes - 512 }], [completeExpectedIdentity]))
  fixtureMustFailWith('inspection archive root recheck tamper',
    'Inspection archive/metadata recheck differs from complete preflight at ordinal 0',
    () => assertInspectionRecheckFacts(manifestFixture, Buffer.from(manifestFixture), [completeInspectionPackage],
      [{ ...recheckFixture[0], archiveRoot: 'unexpected' }], [completeExpectedIdentity]))
  fixtureMustFailWith('inspection header-layout recheck tamper',
    'Inspection archive/metadata recheck differs from complete preflight at ordinal 0',
    () => assertInspectionRecheckFacts(manifestFixture, Buffer.from(manifestFixture), [completeInspectionPackage],
      [{ ...recheckFixture[0], headerLayoutSha256: '0'.repeat(64) }], [completeExpectedIdentity]))
  fixtureMustFailWith('inspection manifest recheck tamper', 'Acquisition manifest changed between inspection preflight and report creation',
    () => assertInspectionRecheckFacts(manifestFixture, Buffer.from('changed-acquisition-manifest'), [completeInspectionPackage], recheckFixture,
      [completeExpectedIdentity]))
  const effectFixture = assertInspectionEffectPlan(inspectionEffectPlan())
  if (effectFixture.networkRequests !== 0 || effectFixture.packageCodeExecution !== false || effectFixture.createNewDirectories.length !== 0 ||
    JSON.stringify(effectFixture.createNewFiles) !== JSON.stringify(['web/comfy/build-artifacts-v2/license-inspection-report.json']) ||
    effectFixture.extractionRoot === effectFixture.createNewFiles[0] || effectFixture.extractedInventory === effectFixture.createNewFiles[0]) {
    fail('Inspection report fixture crosses the extraction-root or package-write effect boundary')
  }
  fixtureMustFailWith('different report destination in inspection effect plan',
    'Inspection effect plan has a different or extra report destination',
    () => assertInspectionEffectPlan({ ...effectFixture, createNewFiles: ['web/comfy/build-artifacts-v2/other.json'] }))
  fixtureMustFailWith('extra report destination in inspection effect plan',
    'Inspection effect plan has a different or extra report destination',
    () => assertInspectionEffectPlan({ ...effectFixture, createNewFiles: [...effectFixture.createNewFiles, 'web/comfy/extra.json'] }))
  fixtureMustFailWith('directory creation in inspection effect plan',
    'Inspection effect plan attempts directory creation',
    () => assertInspectionEffectPlan({ ...effectFixture, createNewDirectories: [effectFixture.extractionRoot] }))
  fixtureMustFailWith('network access in inspection effect plan',
    'Inspection effect plan requests network access',
    () => assertInspectionEffectPlan({ ...effectFixture, networkRequests: 1 }))
  fixtureMustFailWith('package execution in inspection effect plan',
    'Inspection effect plan permits package code execution',
    () => assertInspectionEffectPlan({ ...effectFixture, packageCodeExecution: true }))
  fixtureMustFailWith('unknown field in inspection effect plan',
    'Inspection effect plan contains unknown or missing fields',
    () => assertInspectionEffectPlan({ ...effectFixture, packageWrites: true }))
  process.stdout.write('Acquisition source fixtures passed; pure in-memory only\n')
}

async function inspectLicenses() {
  return extractArtifacts({ inspectionOnly: true })
}

async function extractArtifacts({ inspectionOnly = false } = {}) {
  const base = safePath(prefix)
  const manifestPath = path.join(base, 'manifest.json')
  const manifestBytes = await readBoundedLocal(manifestPath, acquisitionManifestByteLimit, 'Acquisition manifest')
  const acquisition = manifestJson(manifestBytes, 'Acquisition manifest')
  if (!manifestBytes.equals(jsonBytes(acquisition))) fail('Acquisition manifest is not in its canonical create-new form')
  if (acquisition.schema !== 'comfy-canvas-build-acquisition/v3' || acquisition.lockSha256 !== lockSha256 ||
    acquisition.packageManager !== `pnpm@${pnpmVersion}` || acquisition.packageManagerPin?.integrity !== pnpmIntegrity ||
    acquisition.packageManagerPin?.tarball !== pnpmTarball || acquisition.packageManagerPin?.source !== pnpmPinSource ||
    acquisition.packageManagerPin?.sourceSha256 !== pnpmPinSourceSha256 ||
    acquisition.packageManagerPin?.authority !== 'root-observed-official-registry-metadata-not-archive-proof' || acquisition.target !== 'win32-x64' ||
    !Array.isArray(acquisition.artifacts) || acquisition.artifacts.length < 1 || acquisition.artifacts.length > artifactLimit ||
    !Number.isSafeInteger(acquisition.archiveBytes) || acquisition.archiveBytes < 0 || acquisition.archiveBytes > aggregateArchiveByteLimit) {
    fail('Acquisition manifest is absent or malformed')
  }
  const lock = await readBoundedLocal(safePath(lockRelative), lockByteLimit, 'Authenticated pnpm lockfile')
  if (hash(lock, 'sha256') !== lockSha256) fail('Authenticated lockfile changed before extraction')
  const lockText = new TextDecoder('utf-8', { fatal: true }).decode(lock)
  const { artifacts: lockedArtifacts, reconciliation } = collectClosure(lockText)
  const expectedArtifacts = [...lockedArtifacts, { locator: `pnpm@${pnpmVersion}`, name: 'pnpm', version: pnpmVersion, integrity: pnpmIntegrity }]
  const trustedExpectedIdentities = expectedArtifacts.map((expected, index) =>
    lockExpectedIdentity(expected, index, `Authenticated lock artifact ${index}`))
  if (JSON.stringify(acquisition.reconciliation) !== JSON.stringify(reconciliation) || acquisition.artifacts.length !== expectedArtifacts.length) {
    fail('Acquisition manifest closure reconciliation differs from the authenticated lock')
  }
  const expectedRequestCount = expectedArtifacts.length
  if (JSON.stringify(acquisition.networkRequests) !== JSON.stringify({ metadata: expectedRequestCount, tarballs: expectedRequestCount, aggregate: expectedRequestCount * 2 }) ||
    JSON.stringify(acquisition.limits) !== JSON.stringify(acquisitionLimits())) {
    fail('Acquisition manifest request counts or hard limits differ from the reviewed source declaration')
  }
  assertInjectiveMappings(expectedArtifacts)
  for (let index = 0; index < expectedArtifacts.length; index++) {
    const expected = expectedArtifacts[index]
    const actual = acquisition.artifacts[index]
    validateAcquisitionArchiveRecord(expectedArtifacts, index, actual, `Acquisition record ${index}`)
    if (actual.registryIntegrity !== expected.integrity ||
      actual.archive !== `${prefix}/npm/${archiveFilename(index)}` || actual.metadata !== `${prefix}/metadata/${archiveFilename(index, '.json')}`) {
      fail('Acquisition manifest locator/SRI closure differs from the authenticated lock')
    }
  }
  const measuredArchiveTotal = acquisition.artifacts.reduce((total, item, index) => {
    const archiveByteLimit = validateAcquisitionArchiveRecord(
      expectedArtifacts, index, item, `Acquisition record ${index}`
    )
    if (!Number.isSafeInteger(item.bytes) || item.bytes < 1 || item.bytes > archiveByteLimit || !Number.isSafeInteger(total + item.bytes)) {
      fail(`Archive byte count is invalid: ${item.locator}`)
    }
    return total + item.bytes
  }, 0)
  if (!Number.isSafeInteger(measuredArchiveTotal) || measuredArchiveTotal !== acquisition.archiveBytes ||
    measuredArchiveTotal > aggregateArchiveByteLimit) fail('Acquisition aggregate archive bound does not match its records')
  if (!/^sha512-[A-Za-z0-9+/]{86}==$/.test(pnpmIntegrity)) fail('Fixed pnpm archive pin is malformed')
  const preflight = []
  const archiveExpansionRecords = []
  let aggregateArchiveExpandedBytes = 0
  let expandedTotal = 0
  let archiveMemberCount = 0
  let createdDirectoryCount = 1
  let aggregateLicenseTextBytes = 0

  for (let index = 0; index < acquisition.artifacts.length; index++) {
    const artifact = acquisition.artifacts[index]
    const expected = expectedArtifacts[index]
    const expectedIdentity = authenticatedExpectedArtifact(expectedArtifacts, index, artifact, `Archive ${index}`)
    if (JSON.stringify(expectedIdentity) !== JSON.stringify(trustedExpectedIdentities[index])) {
      fail(`Acquisition record differs from authenticated lock identity at ordinal ${index}`)
    }
    const archiveByteLimit = validateAcquisitionArchiveRecord(expectedArtifacts, index, artifact, `Archive ${index}`)
    if (artifact.bytes > archiveByteLimit || !Number.isSafeInteger(artifact.bytes) || artifact.bytes < 1 ||
      artifact.metadataBytes > metadataByteLimit || !Number.isSafeInteger(artifact.metadataBytes) || artifact.metadataBytes < 1 ||
      artifact.locator !== expected.locator || artifact.lockIntegrity !== expected.integrity || artifact.registryIntegrity !== expected.integrity) {
      fail(`Archive/manifest integrity or byte bound invalid: ${artifact.locator}`)
    }
    const archivePath = safePath(artifact.archive)
    const bytes = await readBoundedLocal(archivePath, archiveByteLimit, `Archive ${artifact.locator}`)
    if (bytes.byteLength !== artifact.bytes || hash(bytes, 'sha256') !== artifact.sha256) {
      fail(`Archive changed after acquisition: ${artifact.locator}`)
    }
    assertArtifactIntegrity(expected.integrity, artifact.registryIntegrity, bytes, artifact.locator)
    const metadataBytes = await readBoundedLocal(safePath(artifact.metadata), metadataByteLimit, `Registry metadata ${artifact.locator}`)
    if (metadataBytes.byteLength !== artifact.metadataBytes || metadataBytes.byteLength > metadataByteLimit ||
      hash(metadataBytes, 'sha256') !== artifact.metadataSha256) {
      fail(`Registry metadata changed after acquisition: ${artifact.locator}`)
    }
    const metadata = manifestJson(metadataBytes, `Registry metadata ${artifact.locator}`)
    if (metadata.name !== expected.name || metadata.version !== expected.version ||
      metadata.dist?.integrity !== expected.integrity || artifact.registryIntegrity !== expected.integrity) {
      fail(`Registry metadata/archive SRI mismatch: ${artifact.locator}`)
    }
    const tarball = new URL(metadata.dist.tarball)
    if (tarball.origin !== registryOrigin || tarball.protocol !== 'https:' || tarball.username || tarball.password ||
      (artifact.locator === `pnpm@${pnpmVersion}` && tarball.href !== pnpmTarball) || tarball.href !== artifact.registryTarball) {
      fail(`Acquired metadata references an unallowlisted host: ${artifact.locator}`)
    }
    const parsedArchive = parseTar(bytes, expectedIdentity)
    aggregateArchiveExpandedBytes = accountArchiveExpansion(
      archiveExpansionRecords, index, parsedArchive.archiveExpandedBytes
    )
    const packageEntry = parsedArchive.entries.find((entry) => entry.path === 'package/package.json' && entry.type === 'file')
    if (!packageEntry) fail(`Package manifest missing from archive: ${artifact.locator}`)
    if (packageEntry.bytes > packageJsonByteLimit) fail(`Package manifest exceeds local bound: ${artifact.locator}`)
    const packageJson = manifestJson(packageEntry.data, `Package manifest ${artifact.locator}`)
    if (packageJson.name !== expectedIdentity.name || packageJson.version !== expectedIdentity.version) {
      fail(`Archive package identity mismatch: ${artifact.locator}`)
    }
    const licenseAssessment = assessLicense(packageJson, metadata, parsedArchive.entries, { inspectionOnly })
    for (const evidence of licenseAssessment.texts) {
      if (inspectionOnly) {
        aggregateLicenseTextBytes += evidence.bytes
        if (!Number.isSafeInteger(aggregateLicenseTextBytes) || aggregateLicenseTextBytes > aggregateLicenseTextByteLimit) {
          fail('Aggregate license/notice text inspection bound exceeded')
        }
      }
    }
    const licensePaths = licenseAssessment.texts.map((evidence) => evidence.path)
    const outputInventory = planPackageOutputInventory(index, parsedArchive.entries, expectedIdentity)
    const checked = inspectionOnly
      ? assembleInspectionPackage({ ordinal: index, artifact, expectedIdentity: trustedExpectedIdentities[index], archiveByteLimit, packageJson, licenseAssessment, parsedArchive, outputInventory })
      : {
          ordinal: index,
          artifact,
          expectedIdentity: trustedExpectedIdentities[index],
          archiveByteLimit,
          archiveExpandedBytes: parsedArchive.archiveExpandedBytes,
          archiveRoot: parsedArchive.archiveRoot,
          headerLayoutSha256: parsedArchive.headerLayoutSha256,
          archiveMembersSha256: parsedArchive.archiveMembersSha256,
          packageJson: { name: packageJson.name, version: packageJson.version, license: licenseAssessment.declaration.text },
          licenseAssessment,
          archiveMembers: parsedArchive.archiveMembers,
          files: outputInventory
        }
    const ordinalPrefix = `${packageDirectoryName(index)}/`
    for (const record of checked.files) {
      if (record.type === 'directory') createdDirectoryCount++
      if (record.type === 'file') {
        expandedTotal += record.bytes
        if (!Number.isSafeInteger(expandedTotal) || expandedTotal > aggregateExpandedByteLimit) {
          fail('Aggregate extraction byte cap exceeded')
        }
        if (licensePaths.includes(record.path.slice(ordinalPrefix.length))) record.licenseOrNotice = true
      }
    }
    archiveMemberCount += checked.archiveMembers.length
    if (!Number.isSafeInteger(archiveMemberCount) || archiveMemberCount + createdDirectoryCount > expandedEntryCountLimit) {
      fail('Aggregate archive-member and created-directory bound exceeded')
    }
    preflight.push(checked)
  }

  // Validate the entire archive set, all member records, all output paths, and final-manifest size before effects.
  assertPackageArchiveExpansion(preflight, aggregateArchiveExpandedBytes)
  const destinationRoot = path.join(base, 'unpacked')
  const identityReservation = maximumFileIdentityRecord()
  const { plannedExtraction, plannedInventory, reservedManifestBytes } = reserveExtractionInventory({
    preflight,
    sourceManifestSha256: hash(manifestBytes, 'sha256'),
    archiveMemberCount,
    aggregateArchiveExpandedBytes,
    createdDirectoryCount,
    aggregateExpandedBytes: expandedTotal,
    trustedExpectedIdentities,
    identityReservation
  })

  if (inspectionOnly) {
    const finalManifestBytes = await readBoundedLocal(manifestPath, acquisitionManifestByteLimit, 'Acquisition manifest inspection recheck')
    const recheckFacts = []
    for (const checked of preflight) {
      const expectedIdentity = authenticatedExpectedArtifact(expectedArtifacts, checked.ordinal, checked.artifact,
        `Inspection recheck ${checked.ordinal}`)
      if (JSON.stringify(expectedIdentity) !== JSON.stringify(trustedExpectedIdentities[checked.ordinal]) ||
        JSON.stringify(trustedExpectedIdentities[checked.ordinal]) !== JSON.stringify(checked.expectedIdentity)) {
        fail(`Authenticated lock identity changed between inspection preflight and report creation at ordinal ${checked.ordinal}`)
      }
      const archive = await readBoundedLocal(safePath(checked.artifact.archive), checked.archiveByteLimit, `Archive inspection recheck ${checked.artifact.locator}`)
      if (archive.byteLength !== checked.artifact.bytes || hash(archive, 'sha256') !== checked.artifact.sha256) {
        fail(`Archive changed between inspection preflight and report creation: ${checked.artifact.locator}`)
      }
      assertArtifactIntegrity(checked.artifact.lockIntegrity, checked.artifact.registryIntegrity, archive, checked.artifact.locator)
      const reparsedArchive = parseTar(archive, expectedIdentity)
      if (reparsedArchive.archiveExpandedBytes !== checked.archiveExpandedBytes ||
        reparsedArchive.archiveRoot !== checked.archiveRoot ||
        JSON.stringify(reparsedArchive.archiveMembers) !== JSON.stringify(checked.archiveMembers)) {
        fail(`Archive expansion/member inventory changed between inspection preflight and report creation: ${checked.artifact.locator}`)
      }
      const packageEntry = reparsedArchive.entries.find((entry) => entry.path === 'package/package.json' && entry.type === 'file')
      if (!packageEntry || packageEntry.bytes > packageJsonByteLimit) {
        fail(`Package manifest changed between inspection preflight and report creation: ${checked.artifact.locator}`)
      }
      const reparsedPackageJson = manifestJson(packageEntry.data, `Package manifest inspection recheck ${checked.artifact.locator}`)
      assertCheckedPackageIdentity(checked.ordinal, checked.artifact, expectedIdentity, reparsedPackageJson,
        `Inspection recheck ${checked.ordinal}`)
      const metadataBytes = await readBoundedLocal(safePath(checked.artifact.metadata), metadataByteLimit, `Metadata inspection recheck ${checked.artifact.locator}`)
      if (metadataBytes.byteLength !== checked.artifact.metadataBytes || hash(metadataBytes, 'sha256') !== checked.artifact.metadataSha256) {
        fail(`Registry metadata changed between inspection preflight and report creation: ${checked.artifact.locator}`)
      }
      recheckFacts.push({
        ordinal: checked.ordinal,
        locator: checked.artifact.locator,
        archiveBytes: archive.byteLength,
        archiveSha256: hash(archive, 'sha256'),
        archiveByteLimit: checked.archiveByteLimit,
        lockIntegrity: checked.artifact.lockIntegrity,
        registryIntegrity: checked.artifact.registryIntegrity,
        archiveSha512: `sha512-${hash(archive, 'sha512')}`,
        archiveExpandedBytes: reparsedArchive.archiveExpandedBytes,
        archiveRoot: reparsedArchive.archiveRoot,
        headerLayoutSha256: headerLayoutInventorySha256(reparsedArchive.archiveMembers),
        archiveMembersSha256: archiveMemberInventorySha256(reparsedArchive.archiveMembers),
        packageName: reparsedPackageJson.name,
        packageVersion: reparsedPackageJson.version,
        metadataBytes: metadataBytes.byteLength,
        metadataSha256: hash(metadataBytes, 'sha256')
      })
    }
    assertInspectionRecheckFacts(manifestBytes, finalManifestBytes, preflight, recheckFacts, trustedExpectedIdentities)
    const assembled = assembleCompleteLicenseInspectionReport(
      preflight, acquisition, hash(manifestBytes, 'sha256'), archiveMemberCount,
      aggregateArchiveExpandedBytes, expandedTotal, createdDirectoryCount, {}, trustedExpectedIdentities
    )
    const effects = assertInspectionEffectPlan(inspectionEffectPlan())
    const reportPath = safePath(effects.createNewFiles[0])
    await assertAbsentAndSafe(reportPath)
    await writeNewFile(reportPath, assembled.bytes)
    const unresolved = preflight.reduce((count, checked) => count + checked.licenseAssessment.issues.length, 0)
    process.stdout.write(`Inspected ${preflight.length} package archives; report=${licenseInspectionReportRelative}; unresolvedLicenseIssues=${unresolved}; no extraction tree or package code was created/executed\n`)
    return
  }

  // No output exists before this point. Every archive member and every planned created directory is now capped and inventoried.
  const createdIdentities = new Map()
  createdIdentities.set('unpacked', await makeDirectoryNew(destinationRoot))
  for (const checked of preflight) {
    const expectedIdentity = authenticatedExpectedArtifact(expectedArtifacts, checked.ordinal, checked.artifact,
      `Archive recheck ${checked.ordinal}`)
    if (JSON.stringify(expectedIdentity) !== JSON.stringify(trustedExpectedIdentities[checked.ordinal]) ||
      JSON.stringify(trustedExpectedIdentities[checked.ordinal]) !== JSON.stringify(checked.expectedIdentity)) {
      fail(`Authenticated lock identity changed after complete preflight at ordinal ${checked.ordinal}`)
    }
    const archiveByteLimit = validateAcquisitionArchiveRecord(
      expectedArtifacts, checked.ordinal, checked.artifact, `Archive recheck ${checked.ordinal}`
    )
    if (archiveByteLimit !== checked.archiveByteLimit) {
      fail(`Archive recheck cap differs from its preflight record at ordinal ${checked.ordinal}`)
    }
    const archive = await readBoundedLocal(safePath(checked.artifact.archive), archiveByteLimit, `Archive recheck ${checked.artifact.locator}`)
    if (archive.byteLength !== checked.artifact.bytes || hash(archive, 'sha256') !== checked.artifact.sha256) {
      fail(`Archive changed between preflight and extraction: ${checked.artifact.locator}`)
    }
    const parsedArchive = parseTar(archive, expectedIdentity)
    if (JSON.stringify(parsedArchive.archiveMembers) !== JSON.stringify(checked.archiveMembers) ||
      parsedArchive.archiveExpandedBytes !== checked.archiveExpandedBytes ||
      parsedArchive.archiveRoot !== checked.archiveRoot ||
      parsedArchive.entries.length !== checked.archiveMembers.filter((member) => member.type === 'file' || member.type === 'directory').length) {
      fail(`Archive member inventory changed after complete preflight: ${checked.artifact.locator}`)
    }
    const packageEntry = parsedArchive.entries.find((entry) => entry.path === 'package/package.json' && entry.type === 'file')
    if (!packageEntry || packageEntry.bytes > packageJsonByteLimit) {
      fail(`Package manifest changed after complete preflight: ${checked.artifact.locator}`)
    }
    const reparsedPackageJson = manifestJson(packageEntry.data, `Package manifest extraction recheck ${checked.artifact.locator}`)
    assertCheckedPackageIdentity(checked.ordinal, checked.artifact, expectedIdentity, reparsedPackageJson,
      `Archive recheck ${checked.ordinal}`)
    const outputFileEntries = selectPackageOutputEntries(parsedArchive.entries, checked.files, checked.ordinal,
      expectedIdentity)
    const artifactDirectory = path.join(destinationRoot, packageDirectoryName(checked.ordinal))
    const ordinalRoot = packageDirectoryName(checked.ordinal)
    createdIdentities.set(`unpacked/${ordinalRoot}`, await makeDirectoryNew(artifactDirectory))
    const directories = checked.files.filter((record) => record.type === 'directory' && record.path !== ordinalRoot)
      .sort((left, right) => left.path.split('/').length - right.path.split('/').length || (left.path < right.path ? -1 : left.path > right.path ? 1 : 0))
    for (const directory of directories) {
      const parts = directory.path.split('/').slice(1)
      const created = await ensureOutputDirectories(artifactDirectory, parts)
      createdIdentities.set(`unpacked/${directory.path}`, created.identity)
    }
    const expectedFiles = new Map(checked.files.filter((record) => record.type === 'file').map((record) => [record.path, record]))
    for (const entry of outputFileEntries) {
      const expected = expectedFiles.get(`${ordinalRoot}/${entry.path}`)
      if (!expected || expected.bytes !== entry.bytes || expected.sha256 !== hash(entry.data, 'sha256')) {
        fail(`Archive file does not match the planned output inventory: ${checked.artifact.locator}`)
      }
      const absolute = path.join(destinationRoot, ...expected.path.split('/'))
      createdIdentities.set(`unpacked/${expected.path}`, await writeNewFile(absolute, entry.data))
    }
  }

  const finalManifestBytes = await readBoundedLocal(manifestPath, acquisitionManifestByteLimit, 'Acquisition manifest final recheck')
  const sourceManifestSha256 = hash(manifestBytes, 'sha256')
  if (!finalManifestBytes.equals(manifestBytes) || hash(finalManifestBytes, 'sha256') !== sourceManifestSha256) {
    fail('Acquisition manifest changed between preflight and extraction completion')
  }
  if (createdIdentities.size !== plannedInventory.length) fail('Created output identity count differs from the complete plan')
  const observedPlan = plannedInventory.map((record) => {
    const identity = createdIdentities.get(record.path)
    if (!identity) fail(`Missing create-new identity for planned output: ${record.path}`)
    return { ...record, identity }
  })
  const actualTree = await inventoryOutputTree(destinationRoot)
  assertInventoryMatches(observedPlan, actualTree, 'Final extracted tree')

  const finalPackages = preflight.map((checked) => packageInventoryRecord(
    checked, (record) => createdIdentities.get(`unpacked/${record.path}`), trustedExpectedIdentities[checked.ordinal]
  ))
  const extracted = assembleFinalExtractionInventory(plannedExtraction, sourceManifestSha256,
    observedPlan, finalPackages, createdIdentities)
  const finalExtractedManifestBytes = boundedCompactJsonBytes(extracted, extractedManifestByteLimit, 'Extracted inventory manifest')
  if (finalExtractedManifestBytes.byteLength > reservedManifestBytes.byteLength) {
    fail('Final extracted inventory exceeded its preflight reservation')
  }
  await writeNewFile(path.join(base, 'unpacked-manifest.json'), finalExtractedManifestBytes)
  process.stdout.write(`Safely extracted ${preflight.length} package archives; archiveMembers=${archiveMemberCount}; createdDirectories=${createdDirectoryCount}; expandedBytes=${expandedTotal}; package code was not executed\n`)
}

async function main() {
  const mode = process.argv[2]
  if (mode === '--source-fixtures') {
    runSourceFixtures()
    return
  }
  if (mode !== '--plan-only' && mode !== '--materialize-plan' && mode !== '--fetch' && mode !== '--extract' && mode !== '--inspect-licenses') {
    fail('Usage: node acquire-build-closure.mjs --source-fixtures|--plan-only|--materialize-plan|--fetch|--extract|--inspect-licenses')
  }
  await validatePnpmPinSource()
  if (mode === '--extract') {
    await extractArtifacts()
    return
  }
  if (mode === '--inspect-licenses') {
    await inspectLicenses()
    return
  }
  const lockPath = safePath(lockRelative)
  const lockBytes = await readBoundedLocal(lockPath, lockByteLimit, 'Authenticated pnpm lockfile')
  if (lockBytes.byteLength !== 623_093) fail('Authenticated lockfile size changed')
  if (hash(lockBytes, 'sha256') !== lockSha256) fail('Authenticated pnpm lockfile SHA256 changed')
  const lockText = new TextDecoder('utf-8', { fatal: true }).decode(lockBytes)
  const { artifacts, reconciliation } = collectClosure(lockText)
  const plan = buildPlan(artifacts, reconciliation)
  if (mode === '--plan-only') {
    process.stdout.write(boundedJsonBytes(plan, planByteLimit, 'Build plan').toString('utf8'))
    return
  }
  if (mode === '--materialize-plan') {
    const planPath = safePath(planRelative)
    await writeNewFile(planPath, boundedJsonBytes(plan, planByteLimit, 'Build plan'))
    process.stdout.write(`Materialized lock-derived closure plan with ${artifacts.length + 1} entries; reachableSnapshots=${reconciliation.reachableSnapshots}; no network or package code used\n`)
    return
  }
  await downloadArtifacts(artifacts, reconciliation)
}

main().catch((error) => {
  process.stderr.write(`Comfy build acquisition stopped: ${error.message}\n`)
  process.exitCode = 1
})
