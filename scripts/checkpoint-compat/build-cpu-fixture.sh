#!/usr/bin/env bash
set -euo pipefail

readonly PINNED_COMMIT=62acc89c26c66076cb72e049f307fbe93b8b9750
readonly REPOSITORY=https://github.com/ggml-org/llama.cpp.git

fail() { printf 'checkpoint-fixture-build: %s\n' "$1" >&2; exit 1; }

[[ $# -eq 3 ]] || fail 'usage: build-cpu-fixture.sh PRIVATE_ROOT PATCH_FILE OUTPUT_JSON'
[[ "$(id -u)" -ne 0 ]] || fail 'refusing to build as root'
private_root=$(realpath -e -- "$1") || fail 'private root must already exist'
patch_file=$(realpath -e -- "$2") || fail 'patch file does not exist'
output_json=$3
[[ -d "$private_root" && -w "$private_root" ]] || fail 'private root is not writable'
[[ "$(stat -c %u -- "$private_root")" == "$(id -u)" ]] || fail 'private root owner mismatch'
case "$private_root" in
  "$HOME"/.cache/checkpoint-compat.*) ;;
  *) fail 'private root must be below the current unprivileged user cache' ;;
esac
[[ "$output_json" == "$private_root"/* ]] || fail 'provenance output must remain in private root'
command -v timeout >/dev/null || fail 'GNU timeout is required for bounded fixture commands'

source_dir="$private_root/source"
build_dir="$private_root/build"
[[ ! -e "$source_dir" && ! -e "$build_dir" ]] || fail 'source/build targets already exist'
timeout --signal=TERM --kill-after=5s 300s git clone --no-checkout --filter=blob:none --depth=1 "$REPOSITORY" "$source_dir"
timeout --signal=TERM --kill-after=5s 300s git -C "$source_dir" fetch --depth=1 origin "$PINNED_COMMIT"
timeout --signal=TERM --kill-after=5s 30s git -C "$source_dir" checkout --detach "$PINNED_COMMIT"
[[ "$(git -C "$source_dir" rev-parse HEAD)" == "$PINNED_COMMIT" ]] || fail 'pinned commit mismatch'
[[ -z "$(git -C "$source_dir" status --porcelain --untracked-files=all)" ]] || fail 'source checkout is not clean'
timeout --signal=TERM --kill-after=5s 30s git -C "$source_dir" apply --check "$patch_file"
timeout --signal=TERM --kill-after=5s 30s git -C "$source_dir" apply "$patch_file"
expected_patch_status=$' M include/llama.h\n M src/llama-context.cpp\n M src/llama-kv-cache.cpp\n M src/llama-kv-cache.h\n M tools/server/server-context.cpp\n M tools/server/server-context.h\n M tools/server/server.cpp'
actual_patch_status=$(git -C "$source_dir" status --porcelain --untracked-files=all)
[[ "$actual_patch_status" == "$expected_patch_status" ]] || fail 'applied source tree differs from the exact seven-file patch allowlist'
expected_patch_names=$'include/llama.h\nsrc/llama-context.cpp\nsrc/llama-kv-cache.cpp\nsrc/llama-kv-cache.h\ntools/server/server-context.cpp\ntools/server/server-context.h\ntools/server/server.cpp'
actual_patch_names=$(git -C "$source_dir" diff --name-only)
[[ "$actual_patch_names" == "$expected_patch_names" ]] || fail 'actual applied diff names differ from the exact seven-file allowlist'

timeout --signal=TERM --kill-after=5s 300s cmake -S "$source_dir" -B "$build_dir" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLAMA_BUILD_TESTS=OFF \
  -DLLAMA_BUILD_EXAMPLES=ON \
  -DLLAMA_BUILD_SERVER=ON \
  -DGGML_CUDA=OFF -DGGML_VULKAN=OFF -DGGML_OPENCL=OFF -DGGML_SYCL=OFF
timeout --signal=TERM --kill-after=5s 600s cmake --build "$build_dir" --target llama-server --parallel 2

server="$build_dir/bin/llama-server"
[[ -x "$server" ]] || fail 'CPU server binary missing'
timeout --signal=TERM --kill-after=5s 30s git -C "$source_dir" diff --check
python3 - "$source_dir" "$patch_file" "$server" "$output_json" <<'PY'
import hashlib
import json
import os
import pathlib
import subprocess
import sys

source, patch, server, output = map(pathlib.Path, sys.argv[1:])
def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()
payload = {
    'pinnedCommit': '62acc89c26c66076cb72e049f307fbe93b8b9750',
    'sourceHead': subprocess.run(['git', '-C', str(source), 'rev-parse', 'HEAD'], check=True, text=True,
                                 capture_output=True, timeout=10).stdout.strip(),
    'patchSha256': digest(patch),
    'serverSha256': digest(server),
    'sourcePath': str(source),
    'buildPath': str(server.parent.parent),
}
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(payload, sort_keys=True, separators=(',', ':')) + '\n', encoding='utf-8')
PY
printf 'pinned patched llama.cpp CPU server built in private workspace\n'
