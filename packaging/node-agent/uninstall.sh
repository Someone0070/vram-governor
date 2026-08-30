#!/usr/bin/env bash
set -euo pipefail

purge="false"
if [[ ${1:-} == "--purge" ]]; then
  purge="true"
elif [[ $# -gt 0 ]]; then
  echo "usage: sudo ./uninstall.sh [--purge]" >&2
  exit 2
fi
if [[ ${EUID} -ne 0 ]]; then
  echo "run this uninstaller with sudo" >&2
  exit 1
fi

systemctl disable --now vram-governor-node-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/vram-governor-node-agent.service
rm -f /usr/local/bin/vram-governor-node-agent
rm -rf /etc/vram-governor
systemctl daemon-reload
if [[ "$purge" == "true" ]]; then
  rm -rf /var/lib/vram-governor
  userdel vram-governor 2>/dev/null || true
  groupdel vram-governor 2>/dev/null || true
  echo "Removed the agent, configuration, durable state, user, and group."
else
  echo "Removed the agent and configuration. Durable state remains in /var/lib/vram-governor."
fi
