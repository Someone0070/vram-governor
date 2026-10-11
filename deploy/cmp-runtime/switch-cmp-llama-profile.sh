#!/usr/bin/env bash
set -euo pipefail

profile="${1:-}"
case "$profile" in
  ctx-8k-4|ctx-32k-1|ctx-32k-2) ;;
  *) echo "profile is not allowlisted" >&2; exit 64 ;;
esac

source_file="/etc/vram-governor/cmp-llama-profiles/${profile}.env"
destination="/etc/vram-governor/cmp-llama-profile.env"
if [[ ! -f "$source_file" || -L "$source_file" ]]; then
  echo "profile is not installed as a regular file" >&2
  exit 66
fi
read -r owner mode < <(stat -Lc '%U %a' -- "$source_file")
if [[ "$owner" != root || $((8#$mode & 8#022)) -ne 0 ]]; then
  echo "profile must be root-owned and not group/world writable" >&2
  exit 77
fi
if grep -Evq '^(#|$|LLAMA_(CTX_SIZE|PARALLEL|PROFILE_ID)=[A-Za-z0-9_.-]+)$' "$source_file"; then
  echo "profile contains unsupported environment syntax" >&2
  exit 65
fi

probe_model="${LLAMA_PROFILE_PROBE_MODEL:-nanbeige-fast_latest}"
previous_model="$(python3 - <<'PY'
import json, urllib.request
try:
    with urllib.request.urlopen('http://127.0.0.1:8080/v1/models', timeout=2) as r:
        rows = json.load(r).get('data', [])
    for row in rows:
        status = row.get('status')
        if isinstance(status, dict):
            status = status.get('value') or status.get('status') or status.get('state')
        if str(status).lower() in ('loaded', 'ready'):
            print(row.get('id', ''))
            break
except Exception:
    pass
PY
)"
model="${previous_model:-$probe_model}"

temporary="$(mktemp /etc/vram-governor/.cmp-llama-profile.XXXXXX)"
trap 'rm -f -- "$temporary"' EXIT
install -m 0644 -o root -g root -- "$source_file" "$temporary"
mv -f -- "$temporary" "$destination"
trap - EXIT

systemctl restart llama-server.service
for _ in {1..100}; do
  if curl -fsS --max-time 2 http://127.0.0.1:8080/v1/models >/dev/null; then break; fi
  sleep 0.2
done
curl -fsS --max-time 120 -H 'Content-Type: application/json' \
  --data "$(MODEL="$model" python3 -c 'import json,os; print(json.dumps({"model":os.environ["MODEL"]}))')" \
  http://127.0.0.1:8080/models/load >/dev/null
