#!/usr/bin/env bash
set -euo pipefail

selection="${1:-}"
if [[ ! "$selection" =~ ^([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+)$ ]]; then
  echo "expected an allowlisted target:profile identifier" >&2
  exit 64
fi

target="${BASH_REMATCH[1]}"
profile="${BASH_REMATCH[2]}"
profile_root="/etc/vram-governor/runtime-profiles"
source_file="${profile_root}/${target}/${profile}.env"
destination_dir="/etc/vram-governor/ollama-profiles"
destination_file="${destination_dir}/${target}.env"

if [[ ! -f "$source_file" || -L "$source_file" ]]; then
  echo "profile is not installed as a regular file: ${target}:${profile}" >&2
  exit 66
fi
read -r owner mode < <(stat -Lc '%U %a' -- "$source_file")
if [[ "$owner" != "root" || $((8#$mode & 8#022)) -ne 0 ]]; then
  echo "profile must be root-owned and not group/world writable" >&2
  exit 77
fi
if grep -Evq '^(#|$|[A-Z][A-Z0-9_]*=[A-Za-z0-9_.:/,@+-]+)$' "$source_file"; then
  echo "profile contains unsupported environment syntax" >&2
  exit 65
fi

install -d -m 0755 -o root -g root -- "$destination_dir"
temporary="$(mktemp "${destination_dir}/.${target}.XXXXXX")"
trap 'rm -f -- "$temporary"' EXIT
install -m 0644 -o root -g root -- "$source_file" "$temporary"
mv -f -- "$temporary" "$destination_file"
trap - EXIT

/usr/bin/systemctl restart "ollama-profile@${target}.service"
/usr/bin/systemctl is-active --quiet "ollama-profile@${target}.service"
