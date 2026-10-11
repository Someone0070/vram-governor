#!/usr/bin/env bash
set -euo pipefail

[[ ${EUID} -eq 0 ]] || { echo "run this uninstaller with sudo" >&2; exit 1; }
systemctl disable --now vram-governor-controller.service 2>/dev/null || true
rm -f /etc/systemd/system/vram-governor-controller.service
rm -f /usr/local/bin/vram-governor-controller
rm -f /usr/local/libexec/vram-governor/validate-controller.sh
rm -f /usr/local/libexec/vram-governor/apply-migrations.sh
systemctl daemon-reload
echo "Controller service and binary removed. Configuration, TLS material, migrations, PostgreSQL data, and /var/lib/vram-governor were preserved."
