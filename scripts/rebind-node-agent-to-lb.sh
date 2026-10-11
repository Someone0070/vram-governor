#!/usr/bin/env bash
# Run interactively as root on an existing Linux GPU node-agent host.
# Preserves runtime discovery configuration; does not touch GPU power or workloads.
set -euo pipefail

if [[ ${EUID} -ne 0 || $# -ne 1 ]]; then
  echo 'usage: sudo bash rebind-node-agent-to-lb.sh --trust-only|rtx3080-node|rtx3090-node|cmp170-node' >&2
  exit 2
fi
node_id=$1
case "$node_id" in
  --trust-only|rtx3080-node|rtx3090-node|cmp170-node) ;;
  *) echo 'unknown node ID' >&2; exit 2 ;;
esac
config=/etc/vram-governor/node-agent.yaml
environment=/etc/vram-governor/node-agent.env
if [[ "$node_id" != --trust-only ]]; then
  [[ -f "$config" && -f "$environment" ]] || {
    echo 'existing node-agent config/env not found; use the packaged installer for a fresh node' >&2
    exit 1
  }
fi
for command in openssl curl update-ca-certificates systemctl python3; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }
done

certificate=$(mktemp)
trap 'rm -f -- "$certificate"' EXIT
openssl s_client -connect 10.0.0.115:8443 -servername 10.0.0.115 -showcerts </dev/null 2>/dev/null \
  | openssl x509 -outform PEM -out "$certificate"
expected='EB:87:30:8E:A1:9A:33:A3:0C:E6:B8:FE:55:7B:DB:88:80:1E:15:21:DC:84:F1:0E:AD:C1:22:6D:2F:33:2C:E8'
actual=$(openssl x509 -in "$certificate" -noout -fingerprint -sha256)
[[ "${actual#*=}" == "$expected" ]] || { echo 'LB certificate fingerprint mismatch; stopped' >&2; exit 1; }
install -m 0644 "$certificate" /usr/local/share/ca-certificates/vram-governor-lb.crt
update-ca-certificates >/dev/null
curl --fail --silent --show-error --max-time 10 https://10.0.0.115:8443/healthz >/dev/null
if [[ "$node_id" == --trust-only ]]; then
  echo 'Pinned LB certificate trusted and HTTPS health verified.'
  exit 0
fi

[[ -t 0 ]] || { echo 'interactive terminal required to read secrets without echo' >&2; exit 1; }
read -r -s -p "Paste ${node_id} token from LB credential file: " node_token
echo
read -r -s -p 'Paste VRAM_NODE_COMMAND_SECRET from LB credential file: ' command_secret
echo
[[ "$node_token" =~ ^[A-Za-z0-9._~+_-]+$ ]] || { echo 'invalid or missing node token' >&2; exit 2; }
[[ "$command_secret" =~ ^[A-Za-z0-9._~+_-]{32,}$ ]] || { echo 'invalid or missing command secret' >&2; exit 2; }

stamp=$(date -u +%Y%m%dT%H%M%SZ)
cp -a -- "$config" "$config.$stamp.bak"
cp -a -- "$environment" "$environment.$stamp.bak"
python3 - "$config" "$node_id" <<'PY'
from pathlib import Path
import re
import sys

path = Path(sys.argv[1])
node_id = sys.argv[2]
body = path.read_text(encoding='utf-8')
def set_field(key, value):
    global body
    pattern = re.compile(r'(?m)^' + re.escape(key) + r':[^\n]*$')
    if len(pattern.findall(body)) > 1:
        raise RuntimeError('duplicate top-level field: ' + key)
    line = key + ': "' + value + '"'
    body = pattern.sub(lambda _: line, body) if pattern.search(body) else line + '\n' + body

set_field('controller_url', 'wss://10.0.0.115:8443/ws/node')
set_field('node_id', node_id)
set_field('token_env', 'VRAM_NODE_TOKEN')
set_field('command_signing_secret_env', 'VRAM_NODE_COMMAND_SECRET')
if re.search(r'(?m)^token:', body):
    set_field('token', '')
if re.search(r'(?m)^command_signing_secret:', body):
    set_field('command_signing_secret', '')
if node_id == 'cmp170-node':
    set_field('power_control_mode', 'dont_touch')
path.write_text(body, encoding='utf-8')
PY
chown root:vram-governor "$config"
chmod 0640 "$config"
umask 0077
printf 'VRAM_NODE_TOKEN=%s\nVRAM_NODE_COMMAND_SECRET=%s\n' "$node_token" "$command_secret" >"$environment"
chown root:vram-governor "$environment"
chmod 0640 "$environment"
unset node_token command_secret
systemctl restart vram-governor-node-agent.service
systemctl --no-pager --full status vram-governor-node-agent.service
echo "Rebound ${node_id} to 10.0.0.115; inspect the LB Admin node inventory for connection."
