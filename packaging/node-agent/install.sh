#!/usr/bin/env bash
set -euo pipefail

agent_name="vram-governor-node-agent"
config_dir="/etc/vram-governor"
state_dir="/var/lib/vram-governor"
binary_path="/usr/local/bin/${agent_name}"
unit_path="/etc/systemd/system/${agent_name}.service"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

controller_url=""
node_id=""
node_name=""
location_class="remote"
power_mode="manual"
comfy_endpoint=""
comfy_public_endpoint=""
accelerator_index="0"
skip_checks="false"
upgrade_only="false"

usage() {
  cat <<'EOF'
VRAM Governor node-agent installer

Usage:
  sudo ./install.sh [options]

Options:
  --controller-url URL          Controller WebSocket URL ending in /ws/node
  --node-id ID                 Stable unique node ID
  --node-name NAME             Fleet display name (defaults to hostname)
  --location local|remote      Scheduling locality label (default: remote)
  --power-mode MODE            auto|manual|off|dont_touch|external
  --comfy-endpoint URL         Node-local ComfyUI URL (for example http://127.0.0.1:8188)
  --comfy-public-endpoint URL  Controller-reachable ComfyUI URL
  --accelerator-index N        GPU index used by ComfyUI (default: 0)
  --upgrade                    Replace binary/unit and preserve all configuration
  --skip-connectivity-check    Install even if controller/Comfy checks fail
  -h, --help                   Show this help

Secrets are read without echo unless VRAM_NODE_TOKEN and
VRAM_NODE_COMMAND_SECRET are already set in the environment.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --controller-url) controller_url=${2:?missing controller URL}; shift 2 ;;
    --node-id) node_id=${2:?missing node ID}; shift 2 ;;
    --node-name) node_name=${2:?missing node name}; shift 2 ;;
    --location) location_class=${2:?missing location}; shift 2 ;;
    --power-mode) power_mode=${2:?missing power mode}; shift 2 ;;
    --comfy-endpoint) comfy_endpoint=${2:?missing ComfyUI endpoint}; shift 2 ;;
    --comfy-public-endpoint) comfy_public_endpoint=${2:?missing public ComfyUI endpoint}; shift 2 ;;
    --accelerator-index) accelerator_index=${2:?missing accelerator index}; shift 2 ;;
    --upgrade) upgrade_only="true"; shift ;;
    --skip-connectivity-check) skip_checks="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "run this installer with sudo" >&2
  exit 1
fi
for command in install systemctl getent id; do
  command -v "$command" >/dev/null || { echo "required command not found: $command" >&2; exit 1; }
done
[[ -r "${script_dir}/${agent_name}" ]] || { echo "package is missing ${agent_name}" >&2; exit 1; }
[[ -r "${script_dir}/${agent_name}.service" ]] || { echo "package is missing systemd unit" >&2; exit 1; }

if [[ "$upgrade_only" == "true" ]]; then
  [[ -r "${config_dir}/node-agent.yaml" ]] || { echo "cannot upgrade: ${config_dir}/node-agent.yaml does not exist" >&2; exit 1; }
  install -m 0755 "${script_dir}/${agent_name}" "$binary_path"
  install -m 0644 "${script_dir}/${agent_name}.service" "$unit_path"
  systemctl daemon-reload
  systemctl enable --now "${agent_name}.service"
  systemctl restart "${agent_name}.service"
  sleep 1
  systemctl --no-pager --full status "${agent_name}.service"
  echo "Upgraded ${agent_name}; existing configuration and durable state were preserved."
  exit 0
fi

default_name=$(hostname -s 2>/dev/null || hostname)
default_id=$(printf '%s' "$default_name" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9._-]+/-/g; s/^-+|-+$//g')
if [[ -t 0 ]]; then
  [[ -n "$controller_url" ]] || { read -r -p "Controller WebSocket URL: " controller_url; }
  [[ -n "$node_id" ]] || { read -r -p "Node ID [${default_id}]: " node_id; node_id=${node_id:-$default_id}; }
  [[ -n "$node_name" ]] || { read -r -p "Node name [${default_name}]: " node_name; node_name=${node_name:-$default_name}; }
  if [[ -z "$comfy_endpoint" ]]; then
    read -r -p "Local ComfyUI URL (blank to disable discovery): " comfy_endpoint
  fi
else
  node_id=${node_id:-$default_id}
  node_name=${node_name:-$default_name}
fi

[[ "$controller_url" =~ ^wss?://[^/]+(/.*)?$ ]] || { echo "controller URL must be an absolute ws:// or wss:// URL" >&2; exit 2; }
[[ "$controller_url" == */ws/node ]] || { echo "controller URL must end in /ws/node" >&2; exit 2; }
[[ "$node_id" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "node ID may contain only letters, digits, dot, underscore, and dash" >&2; exit 2; }
[[ "$node_name" =~ ^[A-Za-z0-9._[:space:]-]+$ ]] || { echo "node name contains unsupported characters" >&2; exit 2; }
for value in "$controller_url" "$comfy_endpoint" "$comfy_public_endpoint"; do
  [[ "$value" != *'"'* && "$value" != *'\'* && "$value" != *$'\n'* && "$value" != *$'\r'* ]] || {
    echo "URLs may not contain quotes, backslashes, or control characters" >&2
    exit 2
  }
done
[[ "$location_class" == "local" || "$location_class" == "remote" ]] || { echo "location must be local or remote" >&2; exit 2; }
case "$power_mode" in auto|manual|off|dont_touch|external) ;; *) echo "invalid power mode" >&2; exit 2 ;; esac
[[ "$accelerator_index" =~ ^[0-9]+$ ]] || { echo "accelerator index must be a non-negative integer" >&2; exit 2; }

node_token=${VRAM_NODE_TOKEN:-}
command_secret=${VRAM_NODE_COMMAND_SECRET:-}
if [[ -z "$node_token" && -t 0 ]]; then read -r -s -p "Node credential token: " node_token; echo; fi
if [[ -z "$command_secret" && -t 0 ]]; then read -r -s -p "Command signing secret: " command_secret; echo; fi
[[ "$node_token" =~ ^[A-Za-z0-9._~+-]+$ ]] || { echo "node token is missing or contains unsupported characters" >&2; exit 2; }
[[ "$command_secret" =~ ^[A-Za-z0-9._~+-]{32,}$ ]] || { echo "command signing secret must contain at least 32 safe characters" >&2; exit 2; }

if [[ -n "$comfy_endpoint" ]]; then
  [[ "$comfy_endpoint" =~ ^https?:// ]] || { echo "ComfyUI endpoint must be http:// or https://" >&2; exit 2; }
  comfy_public_endpoint=${comfy_public_endpoint:-$comfy_endpoint}
fi

if [[ "$skip_checks" != "true" ]]; then
  command -v curl >/dev/null || { echo "curl is required for preflight checks (or use --skip-connectivity-check)" >&2; exit 1; }
  controller_health=${controller_url/ws:/http:}
  controller_health=${controller_health/wss:/https:}
  controller_health=${controller_health%/ws/node}/healthz
  curl --fail --silent --show-error --max-time 10 "$controller_health" >/dev/null || {
    echo "controller health check failed: $controller_health" >&2
    exit 1
  }
  if [[ -n "$comfy_endpoint" ]]; then
    curl --fail --silent --show-error --max-time 15 "${comfy_endpoint%/}/system_stats" >/dev/null || {
      echo "ComfyUI discovery check failed: ${comfy_endpoint%/}/system_stats" >&2
      exit 1
    }
  fi
fi

getent group vram-governor >/dev/null || groupadd --system vram-governor
id vram-governor >/dev/null 2>&1 || useradd --system --gid vram-governor --home-dir "$state_dir" --shell /usr/sbin/nologin vram-governor
install -d -m 0750 -o root -g vram-governor "$config_dir"
install -d -m 0750 -o vram-governor -g vram-governor "$state_dir"

timestamp=$(date -u +%Y%m%dT%H%M%SZ)
[[ ! -f "${config_dir}/node-agent.yaml" ]] || cp -a "${config_dir}/node-agent.yaml" "${config_dir}/node-agent.yaml.${timestamp}.bak"
[[ ! -f "${config_dir}/node-agent.env" ]] || cp -a "${config_dir}/node-agent.env" "${config_dir}/node-agent.env.${timestamp}.bak"

install -m 0755 "${script_dir}/${agent_name}" "$binary_path"
install -m 0644 "${script_dir}/${agent_name}.service" "$unit_path"

umask 0077
cat >"${config_dir}/node-agent.env" <<EOF
VRAM_NODE_TOKEN=${node_token}
VRAM_NODE_COMMAND_SECRET=${command_secret}
EOF
chown root:vram-governor "${config_dir}/node-agent.env"
chmod 0640 "${config_dir}/node-agent.env"

cat >"${config_dir}/node-agent.yaml" <<EOF
controller_url: "${controller_url}"
token_env: "VRAM_NODE_TOKEN"
command_signing_secret_env: "VRAM_NODE_COMMAND_SECRET"
command_state_path: "${state_dir}/node-command-state.json"
node_id: "${node_id}"
node_name: "${node_name}"
log_level: "info"
location_class: "${location_class}"
power_control_mode: "${power_mode}"
heartbeat_interval_seconds: 2
capability_refresh_seconds: 30
reconnect_min_seconds: 1
reconnect_max_seconds: 15
llamacpp:
  servers: []
comfyui:
  endpoint: "${comfy_endpoint}"
  public_endpoint: "${comfy_public_endpoint}"
  accelerator_index: ${accelerator_index}
EOF
chown root:vram-governor "${config_dir}/node-agent.yaml"
chmod 0640 "${config_dir}/node-agent.yaml"

systemctl daemon-reload
systemctl enable --now "${agent_name}.service"
systemctl restart "${agent_name}.service"
sleep 1
systemctl --no-pager --full status "${agent_name}.service"
echo
echo "Installed ${agent_name} for node ${node_id}."
echo "Configuration: ${config_dir}/node-agent.yaml"
echo "Logs: journalctl -u ${agent_name}.service -f"
