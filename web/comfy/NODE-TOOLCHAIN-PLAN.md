# Node 25 toolchain source plan

This is a source-only prerequisite package for the exact Node `25.9.0 win32-x64` runtime declared by the pinned frontend. It adds one fixed-pin helper and declares two separate future effects. It does not stage or extract the Node archive, install any package manager, run source fixtures, or claim build or canvas-gate credit.

## Frozen inputs

The only archive accepted by the helper is `https://nodejs.org/dist/v25.9.0/node-v25.9.0-win-x64.zip`, exactly 37,531,403 bytes with SHA256 `929552b8305effac843ba7b4270c437aefb702fc3fbd73fcd1bffd35d4ac284e`. Those values match `.unlazy/fleet-residency-v2/comfy-node25-official-pin1.json`. That official TLS checksum/HEAD observation is not a detached signature or complete source/license proof. There is no caller-supplied URL, checksum refresh, alternate mirror, or runtime selector.

## Implementation and review sequence

1. Freeze the helper, this plan, and `NODE-TOOLCHAIN-EFFECTS.md`; keep the independent positive ZIP fixture first, followed by focused malformed framing, path, type, collision, integrity, and bound cases with first-diagnostic assertions.
2. Run only the permitted syntax check during implementation. Fresh genuine Sol/root reviewers must inspect the full source, exact three-file delta and hashes, fixture reachability, and declared effects before any helper mode is approved.
3. If separately authorized later, `--acquire` makes one default-TLS GET to the fixed URL and create-new writes only `web/comfy/vendor/node-v25.9.0-win-x64.zip`. It rejects Node launch options, disabled TLS verification, custom certificate roots, and environment-selected proxy use. Exact response length and SHA256 are required; failed partial output is preserved as unusable evidence.
4. After a separate extraction approval, `--extract` verifies that same ZIP again, fully parses and inflates every member under the fixed caps, preflights all paths/types/collisions and the complete manifest size before creating the absent `web/comfy/toolchains/` parent, the absent `web/comfy/toolchains/node-v25.9.0-win-x64/` tree, and external inventory manifest at `web/comfy/toolchains/node-v25.9.0-win-x64-manifest.json`. No overwrite, merge, cleanup, or retry in place is permitted.
5. Independently review the actual archive and extracted inventory before considering any runtime use. Identify actual bundled license/notice texts and third-party source/redistribution obligations. The ZIP/checksum pair alone cannot resolve them.

## Structural policy

The parser accepts only classic single-disk ZIP framing with the end record and central directory ending exactly at EOF, no prepended bytes, no local/central mismatch, no overlap or unframed local data, no encryption, no descriptors, no ZIP64, and only stored or deflate members. It checks every member CRC32 and inflated byte count. It rejects Windows traversal and ambiguous paths, Unicode/case collisions, links and special files, and requires every entry beneath the single pinned archive root. Limits are 8,192 entries, 268,435,456 inflated bytes per file, and 536,870,912 total inflated bytes. Unsupported real-archive structure must stop with preserved inert evidence; it does not justify broadening parser support speculatively.

The final inventory covers each archive file and directory plus synthesized parent directories and preserves member names, indices, CRCs, sizes, and SHA256 values. It excludes no payload by type or filename. The generated manifest itself is outside the payload tree to avoid self-reference.

## No authority granted here

No Node invocation, package manager, install/resolution/lifecycle, git/profile/PATH/certificate change, frontend import, compiler, typecheck, Vite, graph parser, browser, service, database, GPU, power, deployment, or cleanup is in scope. No mode or fixture was executed. The source package itself grants no acquisition, extraction, runtime, or build approval. Node availability alone does not satisfy pnpm `11.13.1`, the authenticated dependency closure, unresolved license findings, production build, parser proof, editable asset verification, or browser workflow. The original G1-G3 gates and full C1-C26/R1-R8 obligations remain unmet.
