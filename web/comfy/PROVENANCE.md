# Comfy canvas source provenance

This prefix is an authenticated source snapshot and an in-progress source-only embed. It is not a reviewed production rebuild or a ready-to-ship package. The official distribution ZIP is retained only as a byte-authenticated upstream reference; it does not prove the pinned-source build or parser gates.

## Frontend pin

- Project: `Comfy-Org/ComfyUI_frontend`, release/tag `v1.51.9`, commit `71d2f2f2b5c6da9dee281836b5b72f3af368966f` (official verified tag).
- Package: `@comfyorg/comfyui-frontend@1.51.9`, `pnpm@11.13.1`; package manager input is the official `pnpm-lock.yaml` (git blob `ada397883923ca93998e275de060249cdfa584df`, local SHA256 `37c632265a683d9ee593f21d0f2d7fa5de44f840f59c2e4ce65356216d8824d3`).
- Full source archive: `vendor/ComfyUI_frontend-v1.51.9-source.tar.gz`, 55,919,360 bytes, SHA256 `fd8c4ef68b65d84a4125a624fa5980cad0b1c12b7ae5c58bec4b261e8863dc87`.
- Official release distribution reference: `vendor/ComfyUI_frontend-v1.51.9-dist.zip`, 22,760,363 bytes, SHA256 `313dfff441f6ba9d4fb6f18baadd990df34c8da149d3995091e41c5928552c99`. Extracted reference files are under `dist/`; they have not been rebuilt from the pinned source or patched for this embed.
- The upstream package's `prepare` script runs Husky and `git config`; it was not run. No package install, package-manager resolution, build, or parser execution has occurred.
- Complete extracted frontend source is under `upstream/frontend-1.51.9/`. The upstream `LICENSE` is GPL-3.0-only; `THIRD_PARTY_NOTICES.md` is retained, including the AMD notice. Distribution must preserve both and offer corresponding source.

## Workflow template pin and selected files

Official PyPI release `comfyui-workflow-templates==0.11.50` is a meta-package. Its sdist is 18,739 bytes, SHA256 `402a7310867eef9481a78d93f0164beed781f1f79eb8f58be1d85dfa77247d20`; its wheel is 10,852 bytes, SHA256 `5fccba6a05f6f3bc62b8a9eb8cb1b1e3502ff9b0a756b2d36400ee714df6a518`. Its complete MIT license is retained in `upstream/templates-0.11.50/comfyui_workflow_templates-0.11.50/LICENSE`.

The meta-package pins seven dependencies. Only packages participating in the two selected workflows/previews are vendored and exposed; other catalog content is intentionally unavailable, not advertised:

| Selected dependency | Artifact | Bytes | SHA256 | License evidence |
| --- | --- | ---: | --- | --- |
| `comfyui-workflow-templates-json==0.1.61` | sdist | 2,626,805 | `c39d2477ccf845e666f3ef1e149b2b05068298790fa02b9fd20e9a2964340b2f` | `PKG-INFO`: MIT; upstream package metadata retained |
| `comfyui-workflow-templates-media-image==0.3.160` | sdist | 89,352,862 | `88dcf749302c6a12f5b803dfb46724b4c8acc31d1117cecff51672d9bd85eb18` | `PKG-INFO`: MIT; selected preview copied verbatim |
| `comfyui-workflow-templates-media-video==0.3.101` | sdist | 104,340,610 | `7652ed99fb9bb00b39d8905919dc81509201e335dde23a9736ba138919908476` | `PKG-INFO`: MIT; selected preview copied verbatim |

These archives and the meta-package sdist are retained under `vendor/`. The JSON package is extracted as upstream data under `upstream/templates-0.11.50/json-0.1.61/`. The meta-package's other exact dependencies (`core==0.3.326`, `media-api==0.3.84`, `media-other==0.3.229`, `media-assets-01==0.1.36`) are not fetched or included because their assets are not selected. Their unavailable templates are not exposed.

Selected authentic ComfyUI graph-format templates are retained as data, with original nodes, links, widgets, layout, and metadata:

| Registered template | Upstream file | Output config and served graph SHA256 | Preview provenance / SHA256 |
| --- | --- | --- | --- |
| `image_sdxl_simple` | JSON package `templates/image_sdxl_simple.json` | `a9856bb0dcf02f0a677497eeebbf664d810ad4a6d74ddd1b4ed0d84a22a5d28a` | image package `sdxl_simple_example-1.webp`, `edbd2ddcd6f4926a63721c390c88e56f9c4694e0830e40c50a31990718e63633` |
| `video_wan2_2_5B_ti2v` | JSON package `templates/video_wan2_2_5B_ti2v.json` | `50390798a133757075d750ab78b26274e3bf3e4a09f46aaa2f08d9559e62750b` | video package `video_wan2_2_5B_ti2v-1.webp`, `972226640f44a2d9e8051da7d224058e14ea1404643f761ced8ee5454d35c593` |

Each graph is copied byte-for-byte to its `configs/comfy-bootstrap/*-canvas.json` output and `templates/*.json`. The registered SDXL model is `sd_xl_base_1.0.safetensors`. The registered Wan graph selects `wan2.2_ti2v_5B_fp16.safetensors`, `umt5_xxl_fp8_e4m3fn_scaled.safetensors`, and `wan2.2_vae.safetensors`. The catalog contains only those two workflows.

## Local integration delta

The local files in this prefix are the integration delta; the official extracted `dist/` has no source patch applied. The authored launcher is `index.html` + `launcher.js`; `templates/index.json` registers exactly the two selected graph files and previews. Template graphs/previews and the legal notices are upstream bytes, not hand-built substitutes. No generated local package build or native-parser proof is claimed. The remaining bundle/closure manifest and actual `graphToPrompt` parser proof require the bounded acquisition and later independent review described in the fleet contract.

The launcher establishes `/comfy/` as the relative asset root, exchanges a user-entered credential only through `POST /auth/session` with `kind:"ui"`, retains only the returned CSRF token in same-tab storage/memory, clears the credential field, adds `X-CSRF-Token` to unsafe same-origin API fetch/XHR calls, and blocks other origins and unclassified paths. It does not contain an upstream worker address or credential. See `TRANSPORT.md` for the pinned-source route inventory and explicit unavailable surfaces.
