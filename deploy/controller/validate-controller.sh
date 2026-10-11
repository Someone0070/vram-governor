#!/usr/bin/env bash
set -euo pipefail

config_path=${1:-/etc/vram-governor/controller.yaml}
environment_path=${2:-/etc/vram-governor/controller.env}
controller_binary=${CONTROLLER_BINARY:-/usr/local/bin/vram-governor-controller}

for path in "$config_path" "$environment_path" "$controller_binary"; do
  [[ -r "$path" ]] || { echo "required controller file is not readable: $path" >&2; exit 1; }
done

if grep -Eq '__[A-Z0-9_]+__' "$config_path" "$environment_path"; then
  echo "controller configuration still contains __PLACEHOLDER__ values" >&2
  exit 1
fi

while IFS= read -r line || [[ -n "$line" ]]; do
  line=${line%$'\r'}
  [[ -z "$line" || "$line" == \#* ]] && continue
  [[ "$line" == *=* ]] || { echo "invalid environment line" >&2; exit 1; }
  key=${line%%=*}
  value=${line#*=}
  [[ "$key" =~ ^[A-Z_][A-Z0-9_]*$ ]] || { echo "invalid environment key: $key" >&2; exit 1; }
  export "$key=$value"
done <"$environment_path"

command_secret=${VRAM_NODE_COMMAND_SECRET:-}
[[ ${#command_secret} -ge 32 ]] || {
  echo "VRAM_NODE_COMMAND_SECRET must contain at least 32 characters" >&2
  exit 1
}

exec "$controller_binary" -config "$config_path" -check-config
