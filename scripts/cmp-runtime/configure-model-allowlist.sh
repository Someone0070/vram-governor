#!/usr/bin/env bash
set -euo pipefail

install -d -m 0755 /etc/vram-governor/llama-models
for model in /mnt/models/ollama/*.gguf; do
  case "$(basename "$model")" in qwen3.5_*.gguf) continue ;; esac
  ln -sfn "$model" "/etc/vram-governor/llama-models/$(basename "$model")"
done
chmod 0755 /usr/libexec/vram-governor/switch-cmp-llama-profile.sh
systemctl daemon-reload
systemctl restart llama-server.service vram-governor-node-agent.service
sleep 2
systemctl is-active --quiet llama-server.service vram-governor-node-agent.service
echo "compatible_model_allowlist_configured=True"
