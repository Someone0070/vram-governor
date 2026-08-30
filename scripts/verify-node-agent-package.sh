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
bash "$package_root/install.sh" --help >/dev/null
chmod 0755 "$package_root/vram-governor-node-agent"
file "$package_root/vram-governor-node-agent" | grep -q 'ELF 64-bit.*x86-64'
"$package_root/vram-governor-node-agent" -h >/dev/null
grep -q '^EnvironmentFile=-/etc/vram-governor/node-agent.env$' "$package_root/vram-governor-node-agent.service"

echo "node-agent package verification passed"
