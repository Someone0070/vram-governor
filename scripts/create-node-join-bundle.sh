#!/usr/bin/env bash
# Create a transferable, root-only worker join bundle on the controller.
set -euo pipefail

output=""
controller_url=""
credentials_file="/root/vram-governor-controller-credentials.env"
certificate="/etc/vram-governor/tls/controller.crt"

usage() {
  cat <<'EOF'
Usage: sudo ./scripts/create-node-join-bundle.sh --output DIR --controller-url wss://HOST:8443/ws/node

Options:
  --credentials-file FILE  Root-only file containing FLEET_ENROLLMENT_TOKEN and VRAM_NODE_COMMAND_SECRET
  --certificate FILE       Controller TLS certificate (default /etc/vram-governor/tls/controller.crt)
  --output DIR             New, nonexistent directory for the bundle
  --controller-url URL     Worker-facing wss://.../ws/node URL

Transfer the bundle through trusted SSH/SCP. Give the certificate file SHA-256
digest to the worker installer by a separate trusted channel. The bundle
contains a fleet-wide enrollment secret: protect it and rotate it if exposed.
EOF
}

while (($#)); do
  case "$1" in
    --output|--controller-url|--credentials-file|--certificate)
      (($# >= 2)) || { echo "missing value for $1" >&2; exit 2; }
      case "$1" in
        --output) output=$2 ;; --controller-url) controller_url=$2 ;;
        --credentials-file) credentials_file=$2 ;; --certificate) certificate=$2 ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

[[ "$(uname -s)" == Linux && ${EUID} -eq 0 ]] || { echo "run as root on the Linux controller" >&2; exit 1; }
[[ "$output" == /* && ! -e "$output" && ! -L "$output" ]] || { echo "--output must name a new absolute directory" >&2; exit 2; }
[[ "$controller_url" =~ ^wss://[A-Za-z0-9.:-]+/ws/node$ ]] || { echo "controller URL must be wss://HOST:PORT/ws/node" >&2; exit 2; }
[[ -f "$credentials_file" && -r "$credentials_file" && ! -L "$credentials_file" && -f "$certificate" && -r "$certificate" ]] || { echo "credentials or controller certificate is unreadable" >&2; exit 1; }
for executable in install sha256sum stat mkdir; do
  command -v "$executable" >/dev/null || { echo "required command not found: $executable" >&2; exit 1; }
done
credentials_owner=$(stat -c %u -- "$credentials_file")
credentials_permissions=$(stat -c %a -- "$credentials_file")
[[ "$credentials_owner" == 0 ]] && (( (8#$credentials_permissions & 077) == 0 )) || { echo "credential file must be root-owned and private" >&2; exit 1; }

enrollment_token=""; command_secret=""
while IFS='=' read -r key value || [[ -n "$key" ]]; do
  case "$key" in
    FLEET_ENROLLMENT_TOKEN) enrollment_token=$value ;;
    VRAM_NODE_COMMAND_SECRET) command_secret=$value ;;
  esac
done < "$credentials_file"
[[ "$enrollment_token" =~ ^[A-Za-z0-9._~+-]{32,}$ ]] || { echo "missing/invalid FLEET_ENROLLMENT_TOKEN" >&2; exit 1; }
[[ "$command_secret" =~ ^[A-Za-z0-9._~+-]{32,}$ ]] || { echo "missing/invalid VRAM_NODE_COMMAND_SECRET" >&2; exit 1; }

umask 0077
mkdir -m 0700 -- "$output"
install -m 0600 -- "$certificate" "$output/controller-ca.pem"
{
  printf 'CONTROLLER_URL=%s\n' "$controller_url"
  printf 'FLEET_ENROLLMENT_TOKEN=%s\n' "$enrollment_token"
  printf 'NODE_COMMAND_SECRET=%s\n' "$command_secret"
} > "$output/join.env"
chmod 0600 -- "$output/join.env"
fingerprint=$(sha256sum -- "$output/controller-ca.pem")
fingerprint=${fingerprint%% *}
unset enrollment_token command_secret
echo "Join bundle created at: $output"
echo "Controller certificate file SHA-256: $fingerprint"
echo "Transfer over trusted SSH. Do not put join.env in Git, chat, or a world-readable location."
