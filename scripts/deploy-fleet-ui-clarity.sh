#!/usr/bin/env bash
set -euo pipefail

binary=/usr/local/bin/vram-governor-controller
candidate=/root/vram-governor-controller-fleet-controls-20260914-linux-amd64
backup="/root/vram-governor-controller.before-fleet-ui-$(date -u +%Y%m%dT%H%M%SZ)"
expected=17262fc25ca5f006bb71d31e71ee7f017181be79deeaab4783c050e9e088492d

[[ ${EUID} -eq 0 && -r "$candidate" ]]
actual=$(sha256sum "$candidate")
[[ ${actual%% *} == "$expected" ]] || { echo 'candidate checksum mismatch' >&2; exit 1; }
chmod 0700 "$candidate"
CONTROLLER_BINARY="$candidate" /usr/local/libexec/vram-governor/validate-controller.sh /etc/vram-governor/controller.yaml /etc/vram-governor/controller.env
cp -a "$binary" "$backup"
install -m 0755 "$candidate" /usr/local/bin/.vram-governor-controller.fleet-ui-new
mv -Tf /usr/local/bin/.vram-governor-controller.fleet-ui-new "$binary"
if ! systemctl restart vram-governor-controller.service ||
   ! curl --fail --silent --show-error --retry 5 --retry-delay 1 --retry-connrefused --max-time 5 --cacert /etc/vram-governor/tls/controller.crt https://10.0.0.115:8443/healthz >/dev/null; then
    install -m 0755 "$backup" /usr/local/bin/.vram-governor-controller.fleet-ui-rollback
    mv -Tf /usr/local/bin/.vram-governor-controller.fleet-ui-rollback "$binary"
    systemctl restart vram-governor-controller.service
    echo 'fleet UI deployment rolled back' >&2
    exit 1
fi
echo 'fleet_ui_clarity_deployed=True'
echo "binary_backup=$backup"
