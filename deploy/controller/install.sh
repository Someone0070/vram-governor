#!/usr/bin/env bash
set -euo pipefail

service_name="vram-governor-controller"
config_dir="/etc/vram-governor"
state_dir="/var/lib/vram-governor"
libexec_dir="/usr/local/libexec/vram-governor"
migration_dir="/usr/local/share/vram-governor/migrations"
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

config_source=""
environment_source=""
upgrade="false"
no_start="false"

usage() {
  cat <<'EOF'
VRAM Governor dedicated-controller installer

Usage:
  sudo ./install.sh --config FILE --environment-file FILE [--no-start]
  sudo ./install.sh --upgrade [--no-start]

With no configuration arguments, the installer places examples under
/etc/vram-governor and exits without enabling the service.

Options:
  --config FILE             Fully rendered production controller YAML
  --environment-file FILE   Root-readable controller environment file
  --upgrade                 Replace program files and preserve existing config
  --no-start                Install but do not enable or start the service
  -h, --help                Show this help
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) config_source=${2:?missing config path}; shift 2 ;;
    --environment-file) environment_source=${2:?missing environment path}; shift 2 ;;
    --upgrade) upgrade="true"; shift ;;
    --no-start) no_start="true"; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

[[ ${EUID} -eq 0 ]] || { echo "run this installer with sudo" >&2; exit 1; }
for command in install systemctl getent id; do
  command -v "$command" >/dev/null || { echo "required command not found: $command" >&2; exit 1; }
done
for package_file in "$service_name" "$service_name.service" validate-controller.sh apply-migrations.sh controller.yaml.template controller.env.example; do
  [[ -r "$script_dir/$package_file" ]] || { echo "package is missing $package_file" >&2; exit 1; }
done
[[ -d "$script_dir/migrations" ]] || { echo "package is missing migrations" >&2; exit 1; }

if [[ "$upgrade" == "true" ]]; then
  [[ -z "$config_source" && -z "$environment_source" ]] || { echo "--upgrade preserves config; do not combine it with config arguments" >&2; exit 2; }
  [[ -r "$config_dir/controller.yaml" && -r "$config_dir/controller.env" ]] || { echo "existing controller configuration is incomplete" >&2; exit 1; }
  config_source="$config_dir/controller.yaml"
  environment_source="$config_dir/controller.env"
elif [[ -n "$config_source" || -n "$environment_source" ]]; then
  [[ -n "$config_source" && -n "$environment_source" ]] || { echo "--config and --environment-file are required together" >&2; exit 2; }
  [[ -r "$config_source" && -r "$environment_source" ]] || { echo "configuration input is not readable" >&2; exit 1; }
fi

if [[ -n "$config_source" ]]; then
  CONTROLLER_BINARY="$script_dir/$service_name" "$script_dir/validate-controller.sh" "$config_source" "$environment_source"
fi

getent group vram-governor >/dev/null || groupadd --system vram-governor
id vram-governor >/dev/null 2>&1 || useradd --system --gid vram-governor --home-dir "$state_dir" --shell /usr/sbin/nologin vram-governor
install -d -m 0750 -o root -g vram-governor "$config_dir" "$config_dir/tls"
install -d -m 0750 -o vram-governor -g vram-governor "$state_dir"
install -d -m 0755 -o root -g root "$libexec_dir" "$migration_dir"

install -m 0755 "$script_dir/$service_name" "/usr/local/bin/$service_name"
install -m 0755 "$script_dir/validate-controller.sh" "$libexec_dir/validate-controller.sh"
install -m 0755 "$script_dir/apply-migrations.sh" "$libexec_dir/apply-migrations.sh"
install -m 0644 "$script_dir/$service_name.service" "/etc/systemd/system/$service_name.service"
install -m 0640 -o root -g vram-governor "$script_dir/controller.yaml.template" "$config_dir/controller.yaml.example"
install -m 0640 -o root -g vram-governor "$script_dir/controller.env.example" "$config_dir/controller.env.example"
for migration in "$script_dir"/migrations/[0-9][0-9][0-9][0-9]_*.sql; do
  install -m 0644 "$migration" "$migration_dir/$(basename "$migration")"
done

if [[ -z "$config_source" ]]; then
  systemctl daemon-reload
  echo "Installed controller program files and configuration examples."
  echo "Render $config_dir/controller.yaml.example and controller.env.example, then rerun install.sh with both files."
  exit 0
fi

if [[ "$upgrade" != "true" ]]; then
  timestamp=$(date -u +%Y%m%dT%H%M%SZ)
  [[ ! -f "$config_dir/controller.yaml" ]] || cp -a "$config_dir/controller.yaml" "$config_dir/controller.yaml.$timestamp.bak"
  [[ ! -f "$config_dir/controller.env" ]] || cp -a "$config_dir/controller.env" "$config_dir/controller.env.$timestamp.bak"
  install -m 0640 -o root -g vram-governor "$config_source" "$config_dir/controller.yaml"
  install -m 0640 -o root -g vram-governor "$environment_source" "$config_dir/controller.env"
fi

systemctl daemon-reload
if [[ "$no_start" == "true" ]]; then
  echo "Installed $service_name without enabling or starting it."
else
  systemctl enable --now "$service_name.service"
  systemctl restart "$service_name.service"
  systemctl --no-pager --full status "$service_name.service"
fi

echo "Configuration: $config_dir/controller.yaml"
echo "Migrations: sudo -u vram-governor $libexec_dir/apply-migrations.sh"
echo "Logs: journalctl -u $service_name.service -f"
