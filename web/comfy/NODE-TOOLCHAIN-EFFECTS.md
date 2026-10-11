# Node 25 toolchain helper effects

This declaration covers only the new helper `acquire-node-toolchain.mjs`. The three files in this Node toolchain source package are new. No existing Comfy source, report, upstream file, pin, or evidence file is changed by this package.

## Fixed inputs and trust limit

- Node release: `25.9.0`, `win32-x64`.
- One fixed URL: `https://nodejs.org/dist/v25.9.0/node-v25.9.0-win-x64.zip`.
- Fixed compressed length: `37,531,403` bytes.
- Fixed SHA256: `929552b8305effac843ba7b4270c437aefb702fc3fbd73fcd1bffd35d4ac284e`.
- The source is `comfy-node25-official-pin1.json`, a root observation of official HTTPS checksum and HEAD metadata. It is not a detached publisher signature, downloaded archive, independent source-build proof, malware finding, or license approval. The helper embeds the same pin and never refreshes or substitutes it.

## Modes and exact effects

- `--source-fixtures`: pure in-memory ZIP construction/parsing, assertions, and one success line on stdout. No file, network, process, or environment effect. Fixture sources are positive-first and are not executed as part of this source package.
- `--acquire`: performs one HTTPS GET to the exact fixed URL using Node's default TLS validation, no credentials, no redirect following, no retry, and a 120-second request timeout. It stops if Node launch arguments/options, TLS verification disabling, custom certificate roots, or environment-selected proxy use are present. It caps streamed bytes at 41,943,040, requires status 200, checks Content-Length when present, then requires the exact pinned length and SHA256. The only file output is the presently absent `web/comfy/vendor/node-v25.9.0-win-x64.zip`, created exclusively. It prints response metadata, measured length/hash, and created-file identity to stdout. No receipt file is created. A failed/interrupted output is not usable and is not overwritten, removed, or retried in place.
- `--extract`: reopens only that fixed archive as a regular single-link file, checks exact size and SHA256, then fully preflights the ZIP before creating outputs. It permits only the exact `node-v25.9.0-win-x64/` root, 8,192 members, 268,435,456 inflated bytes per file, and 536,870,912 inflated bytes total. Since `web/comfy/toolchains/` is currently absent, it is created exclusively as the required parent; the tree is created only at the presently absent `web/comfy/toolchains/node-v25.9.0-win-x64/`, and the external control manifest only at the presently absent `web/comfy/toolchains/node-v25.9.0-win-x64-manifest.json`. Files and directories are create-new. No pre-existing or partial output is adopted or cleaned up.

## ZIP validation and inventory

The parser requires one-disk classic ZIP, exact EOCD and central-directory framing through exact EOF, local/central agreement, a complete sequential local-entry region with no overlap or unframed gaps, and no data descriptors, encryption, ZIP64, unsupported flags, or unsupported compression. It accepts only stored or raw-deflate members. Extra fields are length-checked and ZIP64 extra data is rejected. Every member is bounded while inflated, then checked against declared length and CRC32 before any extraction directory is made. The complete manifest records every archive file, explicit directory, and synthesized parent directory with relative path, byte size, SHA256 where applicable, CRC32 and archive-member provenance; the manifest is outside the payload tree to avoid self-reference.

Names use strict UTF-8 and reject absolute, drive, UNC/backslash, traversal, empty/dot, ADS/colon, control, reserved Windows device, forbidden-character, trailing-dot/space, overlong, out-of-root, case-fold, Unicode-normalization, and file/directory-collision paths. Unix symlinks, links, and special-file types are rejected. No member is excluded, including executables, bundled npm/corepack, documentation, notices, licenses, or third-party material. Extraction is inert: no extracted program is launched.

## Global exclusions

No Node25 binary, npm, pnpm, corepack, package manager, lifecycle hook, git/profile/PATH/certificate setting, frontend source, compiler, typechecker, Vite, native parser, browser, service, database, GPU, power, deployment, or build is invoked or changed. No download, extraction, package operation, fixture execution, or helper mode is authorized by this source declaration. Each future mode needs fresh genuine Sol/root review of the complete settled source, effects, and composition. Acquiring/extracting Node does not satisfy the frontend's separate pnpm, dependency, license/source, build, parser, editable-canvas, browser, or release requirements. Original G1-G3 and C1-C26/R1-R8 remain unmet.
