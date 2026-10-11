#!/usr/bin/env bash
set -euo pipefail

binary=/usr/local/bin/vram-governor-controller
config=/etc/vram-governor/controller.yaml
candidate_binary=/root/vram-governor-controller-passwordless-admin-20260914-linux-amd64
candidate_config=/root/controller-passwordless-admin-lan.candidate.yaml
stamp=$(date -u +%Y%m%dT%H%M%SZ)
binary_backup="/root/vram-governor-controller.before-passwordless-admin-${stamp}"
config_backup="/etc/vram-governor/controller.yaml.before-passwordless-admin-${stamp}"

[[ ${EUID} -eq 0 && -r "$candidate_binary" && -r "$candidate_config" ]]
[[ $(systemctl is-active vram-governor-controller.service) == active ]]
cp -a "$binary" "$binary_backup"
cp -a "$config" "$config_backup"
install -m 0755 "$candidate_binary" /usr/local/bin/.vram-governor-controller.passwordless-new
install -m 0640 -o root -g vram-governor "$candidate_config" /etc/vram-governor/.controller.yaml.passwordless-new

rollback() {
    install -m 0755 "$binary_backup" /usr/local/bin/.vram-governor-controller.rollback
    install -m 0640 -o root -g vram-governor "$config_backup" /etc/vram-governor/.controller.yaml.rollback
    mv -Tf /usr/local/bin/.vram-governor-controller.rollback "$binary"
    mv -Tf /etc/vram-governor/.controller.yaml.rollback "$config"
    systemctl restart vram-governor-controller.service
    echo 'deployment_failed_and_rolled_back=True' >&2
}

mv -Tf /usr/local/bin/.vram-governor-controller.passwordless-new "$binary"
mv -Tf /etc/vram-governor/.controller.yaml.passwordless-new "$config"
if ! systemctl restart vram-governor-controller.service ||
   ! systemctl is-active --quiet vram-governor-controller.service ||
   ! curl --fail --silent --show-error --retry 5 --retry-delay 1 --retry-connrefused --max-time 5 --cacert /etc/vram-governor/tls/controller.crt https://10.0.0.115:8443/healthz >/dev/null; then
    rollback
    exit 1
fi
echo 'passwordless_admin_lan_active=True'
echo "binary_backup=$binary_backup"
echo "config_backup=$config_backup"
