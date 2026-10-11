#!/usr/bin/env bash
# Read-only deployment checks except for one tiny artifact upload to the new store.
# Run as root on the dedicated LB after provisioning.
set -euo pipefail

base=https://10.0.0.115:8443
cert=/etc/vram-governor/tls/controller.crt
source /root/vram-governor-controller-credentials.env

for service in postgresql.service vram-garage.service nginx.service vram-governor-controller.service lb-proxy.service; do
  [[ $(systemctl is-active "$service") == active ]] || { echo "inactive: $service" >&2; exit 1; }
done
runuser -u vram-governor -- /usr/local/libexec/vram-governor/validate-controller.sh >/dev/null
[[ $(curl --silent --show-error --cacert "$cert" "$base/healthz") == '{"status":"ok"}' ]]
for path in /admin/ /studio/ /chat/; do
  [[ $(curl --silent --show-error --cacert "$cert" --output /dev/null --write-out '%{http_code}' "$base$path") == 200 ]]
done

unauth=$(curl --silent --show-error --cacert "$cert" --output /dev/null --write-out '%{http_code}' "$base/admin/api/overview")
[[ "$unauth" == 401 || "$unauth" == 403 ]] || { echo "unauthenticated admin returned $unauth" >&2; exit 1; }
wrong_plane=$(curl --silent --show-error --cacert "$cert" -H "Authorization: Bearer $INTERACTIVE_UI_TOKEN" --output /dev/null --write-out '%{http_code}' "$base/admin/api/overview")
[[ "$wrong_plane" == 403 ]] || { echo "UI-plane admin returned $wrong_plane" >&2; exit 1; }

overview=$(curl --fail --silent --show-error --cacert "$cert" -H "Authorization: Bearer $ADMIN_TOKEN" "$base/admin/api/overview")
printf '%s' "$overview" | python3 -c 'import json,sys; x=json.load(sys.stdin); assert "nodes" in x; print("connected_nodes=" + str(sum(1 for n in x["nodes"] if n.get("observed",{}).get("connectivity") == "connected"))); print("node_ids=" + ",".join(n.get("id", "?") for n in x["nodes"]))'

plug=$(curl --fail --silent --show-error --cacert "$cert" -H "Authorization: Bearer $ADMIN_TOKEN" "$base/admin/api/smart-plugs")
printf '%s' "$plug" | python3 -c 'import json,sys; x=json.load(sys.stdin); p=x["smart_plugs"]; assert len(p)==1 and p[0]["node_id"]=="cmp170-node" and p[0]["control_enabled"] is False and p[0]["reachable"] is True; print("cmp170_plug_read_only_reachable")'

comfy_status=$(curl --silent --show-error --cacert "$cert" -H "Authorization: Bearer $COMFY_MCP_TOKEN" --output /dev/null --write-out '%{http_code}' "$base/queue")
[[ "$comfy_status" == 200 ]] || { echo "Comfy MCP queue returned $comfy_status" >&2; exit 1; }
models_status=$(curl --silent --show-error --cacert "$cert" -H "Authorization: Bearer $INTERACTIVE_UI_TOKEN" --output /dev/null --write-out '%{http_code}' "$base/v1/models")
[[ "$models_status" == 200 ]] || { echo "OpenAI model inventory returned $models_status" >&2; exit 1; }

upload=$(curl --fail --silent --show-error --cacert "$cert" -H "Authorization: Bearer $INTERACTIVE_UI_TOKEN" -F 'file=@/etc/hostname;type=text/plain' "$base/api/v1/artifacts")
artifact_id=$(printf '%s' "$upload" | python3 -c 'import json,sys; print(json.load(sys.stdin)["artifact_id"])')
[[ -n "$artifact_id" ]]
download=$(curl --fail --silent --show-error --cacert "$cert" -H "Authorization: Bearer $INTERACTIVE_UI_TOKEN" "$base/api/v1/artifacts/$artifact_id/content")
[[ "$download" == "$(cat /etc/hostname)" ]] || { echo 'artifact round-trip mismatch' >&2; exit 1; }

[[ $(curl --silent --show-error --cacert /etc/garage/tls/s3.crt --output /dev/null --write-out '%{http_code}' https://127.0.0.1:9443/) == 403 ]]
[[ $(systemctl is-active lb-proxy.service) == active ]]
echo 'LB live verification passed'
