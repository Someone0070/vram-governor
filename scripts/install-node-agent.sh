#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: sudo $0 /path/to/node-agent /path/to/node-agent.yaml" >&2
  echo "for a guided bundle, build scripts/build-node-agent-package.ps1 instead" >&2
  exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
  echo "run this installer with sudo" >&2
  exit 1
fi

binary_path=$(realpath "$1")
config_path=$(realpath "$2")
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
unit_path=$(realpath "$script_dir/../deploy/vram-governor-node-agent.service")

test -x "$binary_path"
test -r "$config_path"
test -r "$unit_path"

getent group vram-governor >/dev/null || groupadd --system vram-governor
id vram-governor >/dev/null 2>&1 || useradd --system --gid vram-governor --home-dir /var/lib/vram-governor --shell /usr/sbin/nologin vram-governor
install -d -m 0750 -o root -g vram-governor /etc/vram-governor
install -d -o vram-governor -g vram-governor -m 0750 /var/lib/vram-governor
install -m 0755 "$binary_path" /usr/local/bin/vram-governor-node-agent
install -o root -g vram-governor -m 0640 "$config_path" /etc/vram-governor/node-agent.yaml
install -m 0644 "$unit_path" /etc/systemd/system/vram-governor-node-agent.service
systemctl daemon-reload
systemctl enable --now vram-governor-node-agent.service
systemctl --no-pager --full status vram-governor-node-agent.service
