#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 /path/to/vram-governor-node-agent-*.tar.gz" >&2
  exit 2
fi

archive=$(realpath "$1")
test_root=$(mktemp -d /tmp/vram-governor-package.XXXXXX)
cleanup() {
  rm -rf -- "$test_root"
}
trap cleanup EXIT

tar -xzf "$archive" -C "$test_root"
package_root=$(find "$test_root" -mindepth 1 -maxdepth 1 -type d -print -quit)
[[ -n "$package_root" ]]

bash -n "$package_root/install.sh"
bash -n "$package_root/uninstall.sh"
bash -n "$package_root/runtime-profile/switch-runtime-profile.sh"
bash "$package_root/install.sh" --help >/dev/null
chmod 0755 "$package_root/vram-governor-node-agent"
file "$package_root/vram-governor-node-agent" | grep -q 'ELF 64-bit.*x86-64'
"$package_root/vram-governor-node-agent" -h >/dev/null
grep -q '^EnvironmentFile=-/etc/vram-governor/node-agent.env$' "$package_root/vram-governor-node-agent.service"
grep -q '^ExecStart=/usr/libexec/vram-governor/switch-runtime-profile.sh %i$' "$package_root/runtime-profile/vram-runtime-profile-switch@.service"
grep -q 'subject.user !== "vram-governor"' "$package_root/runtime-profile/90-vram-runtime-profile-switch.rules"
test -f "$package_root/docs/llamacpp-node-setup.md"
test -f "$package_root/docs/connect-gpu-nodes-to-lb.md"
test -f "$package_root/docs/ollama-multi-profile.md"
grep -q 'docs/llamacpp-node-setup.md' "$package_root/README.txt"

echo "node-agent package verification passed"
