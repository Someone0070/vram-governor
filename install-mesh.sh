#!/usr/bin/env bash
# Clone-local role selector. Delegates configuration validation and service
# installation to the existing controller/node-agent package installers.
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
role=""
upgrade=false
dry_run=false
config=""
environment_file=""
tls_cert=""
tls_key=""
join_bundle=""
expected_fingerprint=""
node_id=""
node_name=""
location=""
power_mode=""
comfy_endpoint=""
comfy_public_endpoint=""

usage() {
  cat <<'EOF'
Install VRAM Governor from a checked-out repository on a Linux systemd host.

Usage:
  sudo ./install-mesh.sh --role lb --upgrade
  sudo ./install-mesh.sh --role lb --config FILE --environment-file FILE [--tls-cert FILE --tls-key FILE]
  sudo ./install-mesh.sh --role head --join-bundle DIR --expected-fingerprint SHA256
  sudo ./install-mesh.sh --role slave --join-bundle DIR --expected-fingerprint SHA256

Without --role on a terminal, choose LB, head GPU node, or slave GPU node.
--dry-run checks the selected path without building or installing anything.

Controller first install requires prepared PostgreSQL, HTTPS S3 storage, TLS,
and validated controller YAML/environment files. The existing controller
installer remains authoritative for those production prerequisites.

Head/slave join bundle is generated on the LB using
scripts/create-node-join-bundle.sh and transferred over a trusted channel.
Its enrollment token and command secret never belong in command arguments.

Options:
  --role lb|head|slave       controller/worker are deprecated aliases for lb/slave
  --upgrade                  Preserve installed configuration and state
  --config FILE              New controller YAML
  --environment-file FILE    New controller environment file
  --tls-cert FILE            Optional certificate to install at the default controller TLS path
  --tls-key FILE             Matching private key to install at the default controller TLS path
  --join-bundle DIR          Worker bundle containing join.env and controller-ca.pem
  --expected-fingerprint HEX Independent SHA-256 file digest of controller CA
  --node-id ID               Optional; worker installer otherwise prompts/defaults
  --node-name NAME           Optional; worker installer otherwise prompts/defaults
  --location local|remote    Head defaults local; slave defaults remote
  --power-mode MODE          Head defaults dont_touch; slave defaults manual
  --comfy-endpoint URL       Optional node-local ComfyUI endpoint
  --comfy-public-endpoint URL  Optional controller-reachable ComfyUI endpoint
  --dry-run
  -h, --help
EOF
}

while (($#)); do
  case "$1" in
    --role|--config|--environment-file|--tls-cert|--tls-key|--join-bundle|--expected-fingerprint|--node-id|--node-name|--location|--power-mode|--comfy-endpoint|--comfy-public-endpoint)
      (($# >= 2)) || { echo "missing value for $1" >&2; exit 2; }
      case "$1" in
        --role) role=$2 ;; --config) config=$2 ;; --environment-file) environment_file=$2 ;;
        --tls-cert) tls_cert=$2 ;; --tls-key) tls_key=$2 ;;
        --join-bundle) join_bundle=$2 ;; --expected-fingerprint) expected_fingerprint=$2 ;;
        --node-id) node_id=$2 ;; --node-name) node_name=$2 ;; --location) location=$2 ;;
        --power-mode) power_mode=$2 ;; --comfy-endpoint) comfy_endpoint=$2 ;;
        --comfy-public-endpoint) comfy_public_endpoint=$2 ;;
      esac
      shift 2 ;;
    --upgrade) upgrade=true; shift ;;
    --dry-run) dry_run=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z "$role" && -t 0 ]]; then
  echo "Install this machine as: 1) Dedicated LB  2) Always-on head GPU node  3) Slave GPU node"
  read -r -p "Choose 1, 2, or 3: " choice
  case "$choice" in 1) role=lb ;; 2) role=head ;; 3) role=slave ;; *) echo "invalid role" >&2; exit 2 ;; esac
fi
case "$role" in
  controller) role=lb ;;
  worker) role=slave ;;
  lb|head|slave) ;;
  *) echo "choose --role lb, head, or slave" >&2; exit 2 ;;
esac
if [[ "$role" != lb ]]; then
  [[ -n "$location" ]] || { if [[ "$role" == head ]]; then location=local; else location=remote; fi; }
  [[ -n "$power_mode" ]] || { if [[ "$role" == head ]]; then power_mode=dont_touch; else power_mode=manual; fi; }
  [[ "$location" == local || "$location" == remote ]] || { echo "--location must be local or remote" >&2; exit 2; }
  [[ "$power_mode" == auto || "$power_mode" == manual || "$power_mode" == off || "$power_mode" == dont_touch || "$power_mode" == external ]] || { echo "invalid --power-mode" >&2; exit 2; }
fi
if [[ -t 0 && "$upgrade" == false ]]; then
  if [[ "$role" == lb ]]; then
    [[ -n "$config" ]] || read -r -p "Prepared controller YAML path: " config
    [[ -n "$environment_file" ]] || read -r -p "Prepared controller environment path: " environment_file
  else
    [[ -n "$join_bundle" ]] || read -r -p "Trusted join-bundle directory: " join_bundle
    [[ -n "$expected_fingerprint" ]] || read -r -p "Controller certificate SHA-256 (verified separately): " expected_fingerprint
  fi
fi

if [[ "$role" == lb ]]; then
  [[ -z "$join_bundle" && -z "$expected_fingerprint" && -z "$node_id" && -z "$node_name" && -z "$location" && -z "$power_mode" && -z "$comfy_endpoint" && -z "$comfy_public_endpoint" ]] || { echo "head/slave options cannot be used for LB" >&2; exit 2; }
  if [[ "$upgrade" == true ]]; then
    [[ -z "$config" && -z "$environment_file" && -z "$tls_cert" && -z "$tls_key" ]] || { echo "--upgrade preserves controller config and TLS" >&2; exit 2; }
    [[ -r /etc/vram-governor/controller.yaml && -r /etc/vram-governor/controller.env ]] || { echo "existing controller config is incomplete" >&2; exit 1; }
  else
    [[ -n "$config" && -n "$environment_file" ]] || { echo "first controller install requires --config and --environment-file" >&2; exit 2; }
    [[ -r "$config" && -r "$environment_file" ]] || { echo "controller config/environment file is unreadable" >&2; exit 1; }
    [[ -z "$tls_cert" && -z "$tls_key" || -n "$tls_cert" && -n "$tls_key" ]] || { echo "--tls-cert and --tls-key must be supplied together" >&2; exit 2; }
    [[ -z "$tls_cert" || -r "$tls_cert" && -r "$tls_key" ]] || { echo "controller TLS input is unreadable" >&2; exit 1; }
    [[ ! -e /etc/vram-governor/controller.yaml && ! -e /etc/vram-governor/controller.env ]] || { echo "controller is already configured; use --upgrade or the packaged installer deliberately" >&2; exit 1; }
  fi
else
  [[ -z "$config" && -z "$environment_file" && -z "$tls_cert" && -z "$tls_key" ]] || { echo "LB options cannot be used for head/slave" >&2; exit 2; }
  if [[ "$upgrade" == true ]]; then
    [[ -z "$join_bundle" && -z "$expected_fingerprint" && -z "$node_id" && -z "$node_name" && -z "$comfy_endpoint" && -z "$comfy_public_endpoint" ]] || { echo "head/slave --upgrade preserves existing join and runtime configuration" >&2; exit 2; }
    [[ -r /etc/vram-governor/node-agent.yaml ]] || { echo "no installed worker configuration to upgrade" >&2; exit 1; }
  else
    [[ -d "$join_bundle" && -r "$join_bundle/join.env" && -r "$join_bundle/controller-ca.pem" ]] || { echo "worker needs a readable --join-bundle directory" >&2; exit 2; }
    [[ ! -L "$join_bundle/join.env" && ! -L "$join_bundle/controller-ca.pem" ]] || { echo "join bundle files must not be symlinks" >&2; exit 2; }
    [[ ! -e /etc/vram-governor/node-agent.yaml ]] || { echo "worker already configured; use --upgrade or deliberately re-enroll with the packaged installer" >&2; exit 1; }
    [[ "$expected_fingerprint" =~ ^[A-Fa-f0-9]{64}$ ]] || { echo "supply an independent 64-character certificate file SHA-256" >&2; exit 2; }
    command -v sha256sum >/dev/null || { echo "sha256sum is required" >&2; exit 1; }
    actual_fingerprint=$(sha256sum -- "$join_bundle/controller-ca.pem")
    actual_fingerprint=${actual_fingerprint%% *}
    [[ "${actual_fingerprint,,}" == "${expected_fingerprint,,}" ]] || { echo "controller certificate fingerprint mismatch; refusing join" >&2; exit 1; }
    # Parse only a fixed set of literal key=value fields. Never source/eval a
    # transferred bundle, and never echo secret values.
    controller_url=""; enrollment_token=""; command_secret=""
    while IFS='=' read -r key value || [[ -n "$key" ]]; do
      case "$key" in
        CONTROLLER_URL) controller_url=$value ;;
        FLEET_ENROLLMENT_TOKEN) enrollment_token=$value ;;
        NODE_COMMAND_SECRET) command_secret=$value ;;
        '') ;;
        *) echo "unexpected join bundle field" >&2; exit 2 ;;
      esac
    done < "$join_bundle/join.env"
    [[ "$controller_url" =~ ^wss://[A-Za-z0-9.:-]+/ws/node$ ]] || { echo "invalid controller URL in join bundle" >&2; exit 2; }
    [[ "$enrollment_token" =~ ^[A-Za-z0-9._~+-]{32,}$ ]] || { echo "invalid enrollment token in join bundle" >&2; exit 2; }
    [[ "$command_secret" =~ ^[A-Za-z0-9._~+-]{32,}$ ]] || { echo "invalid command secret in join bundle" >&2; exit 2; }
  fi
fi

if [[ "$dry_run" == true ]]; then
  echo "Dry run: role=$role location=${location:-n/a} power_mode=${power_mode:-n/a}; would build and invoke the existing package installer. No configuration, secret, or service was changed."
  exit 0
fi

[[ "$(uname -s)" == Linux ]] || { echo "installation requires Linux" >&2; exit 1; }
[[ ${EUID} -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
for executable in go install systemctl mktemp cp; do
  command -v "$executable" >/dev/null || { echo "required command not found: $executable" >&2; exit 1; }
done
if [[ "$role" != lb && "$upgrade" == false ]]; then
  permissions=$(stat -c %a -- "$join_bundle/join.env")
  (( (8#$permissions & 077) == 0 )) || { echo "join.env must not be group/world-readable" >&2; exit 1; }
fi

stage=$(mktemp -d -t vram-mesh-install.XXXXXXXX)
cleanup() { [[ -z "${stage:-}" || ! -d "$stage" ]] || rm -r -- "$stage"; }
trap cleanup EXIT

if [[ "$role" == lb ]]; then
  cp -a -- "$repo_dir/deploy/controller/." "$stage/"
  cp -a -- "$repo_dir/migrations" "$stage/migrations"
  go -C "$repo_dir" build -buildvcs=false -o "$stage/vram-governor-controller" ./cmd/controller
  if [[ "$upgrade" == true ]]; then
    bash "$stage/install.sh" --upgrade
  else
    bash "$stage/install.sh" # creates service user and directories without starting
    if [[ -n "$tls_cert" ]]; then
      [[ ! -e /etc/vram-governor/tls/controller.crt && ! -e /etc/vram-governor/tls/controller.key ]] || { echo "existing controller TLS will not be overwritten" >&2; exit 1; }
      install -m 0640 -o root -g vram-governor -- "$tls_cert" /etc/vram-governor/tls/controller.crt
      install -m 0640 -o root -g vram-governor -- "$tls_key" /etc/vram-governor/tls/controller.key
    fi
    bash "$stage/install.sh" --config "$config" --environment-file "$environment_file" --no-start
    command -v runuser >/dev/null && command -v psql >/dev/null || { echo "runuser and psql are required to initialize the database" >&2; exit 1; }
    # The existing migration helper replays every historical SQL file. Only
    # do that automatically against the documented local, empty database.
    if ! grep -Eq '^database_url: "postgresql:///vram_governor\?host=/var/run/postgresql"$' "$config"; then
      echo "controller installed without starting: custom database URL requires a reviewed migration procedure" >&2
      exit 1
    fi
    existing_schema=$(runuser -u vram-governor -- psql 'postgresql:///vram_governor?host=/var/run/postgresql' -Atqc "SELECT to_regclass('public.nodes') IS NOT NULL")
    [[ "$existing_schema" == f ]] || { echo "controller installed without starting: database is not empty; review migrations before starting" >&2; exit 1; }
    runuser -u vram-governor -- /usr/local/libexec/vram-governor/apply-migrations.sh
    systemctl enable --now vram-governor-controller.service
    systemctl --no-pager --full status vram-governor-controller.service
  fi
  echo "Controller installed. Create a trusted worker join bundle with scripts/create-node-join-bundle.sh."
else
  cp -a -- "$repo_dir/packaging/node-agent/." "$stage/"
  cp -- "$repo_dir/deploy/vram-governor-node-agent.service" "$stage/"
  go -C "$repo_dir" build -buildvcs=false -o "$stage/vram-governor-node-agent" ./cmd/node-agent
  if [[ "$upgrade" == true ]]; then
    bash "$stage/install.sh" --upgrade
  else
    args=(--controller-url "$controller_url" --controller-ca "$join_bundle/controller-ca.pem" --location "$location" --power-mode "$power_mode")
    [[ -z "$node_id" ]] || args+=(--node-id "$node_id")
    [[ -z "$node_name" ]] || args+=(--node-name "$node_name")
    [[ -z "$comfy_endpoint" ]] || args+=(--comfy-endpoint "$comfy_endpoint")
    [[ -z "$comfy_public_endpoint" ]] || args+=(--comfy-public-endpoint "$comfy_public_endpoint")
    VRAM_ENROLLMENT_TOKEN="$enrollment_token" VRAM_NODE_COMMAND_SECRET="$command_secret" bash "$stage/install.sh" "${args[@]}"
    unset enrollment_token command_secret
    echo "Worker join submitted. Confirm the node appears in the controller Fleet view."
  fi
fi
