#!/usr/bin/env bash
set -euo pipefail

state=/var/lib/vram-governor/comfy-harness/state.json
before="$(sha256sum "$state" | cut -d' ' -f1)"
count="$(python3 -c 'import json; print(len(json.load(open("/var/lib/vram-governor/comfy-harness/state.json"))["executions"]))')"
systemctl restart comfy-harness.service
sleep 1
systemctl is-active --quiet comfy-harness.service
after="$(sha256sum "$state" | cut -d' ' -f1)"
test "$before" = "$after"
test "$count" -gt 0
echo "durable_execution_count=$count"
echo "harness_restart_state_preserved=True"
