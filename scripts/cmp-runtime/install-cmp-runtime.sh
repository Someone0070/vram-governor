#!/usr/bin/env bash
set -euo pipefail

stage="${1:-/root/vram-cmp-runtime-stage}"
test -s "$stage/vram-governor-comfy-harness"
test -s "$stage/vram-governor-node-agent"
test -s /etc/vram-governor/comfy-harness.env

install -d -m 0755 /usr/libexec/vram-governor /etc/vram-governor/cmp-llama-profiles
install -d -m 0755 /etc/vram-governor/llama-models
# The installed llama.cpp build rejects the Qwen 3.5 GGUF metadata currently
# present on this host. Advertise the remaining files instead of offering
# lifecycle buttons for models already proven unloadable.
for model in /mnt/models/ollama/*.gguf; do
  case "$(basename "$model")" in qwen3.5_*.gguf) continue ;; esac
  ln -sfn "$model" "/etc/vram-governor/llama-models/$(basename "$model")"
done
install -d -m 0750 -o vram-governor -g vram-governor /var/lib/vram-governor/comfy-harness
install -m 0755 "$stage/vram-governor-comfy-harness" /usr/local/bin/vram-governor-comfy-harness
install -m 0755 "$stage/vram-governor-node-agent" /usr/local/bin/vram-governor-node-agent
install -m 0755 "$stage/switch-cmp-llama-profile.sh" /usr/libexec/vram-governor/switch-cmp-llama-profile.sh
install -m 0644 "$stage/ctx-8k-4.env" "$stage/ctx-32k-1.env" "$stage/ctx-32k-2.env" /etc/vram-governor/cmp-llama-profiles/
install -m 0644 "$stage/ctx-8k-4.env" /etc/vram-governor/cmp-llama-profile.env
install -d -m 0755 /etc/systemd/system/llama-server.service.d
install -m 0644 "$stage/llama-server-router.conf" /etc/systemd/system/llama-server.service.d/router.conf
install -m 0644 "$stage/comfy-harness.service" /etc/systemd/system/comfy-harness.service
install -m 0644 "$stage/vram-cmp-llama-profile@.service" /etc/systemd/system/vram-cmp-llama-profile@.service
install -m 0644 "$stage/vram-governor-runtime-tunnel.service" /etc/systemd/system/vram-governor-runtime-tunnel.service
install -m 0644 "$stage/90-vram-cmp-llama-profile.rules" /etc/polkit-1/rules.d/90-vram-cmp-llama-profile.rules
install -m 0640 -o root -g vram-governor "$stage/node-agent.yaml" /etc/vram-governor/node-agent.yaml

if [[ ! -s /etc/vram-governor/runtime-tunnel-ed25519 ]]; then
  ssh-keygen -q -t ed25519 -N '' -C vram-cmp-runtime-tunnel -f /etc/vram-governor/runtime-tunnel-ed25519
fi
chown vram-governor:vram-governor /etc/vram-governor/runtime-tunnel-ed25519
chmod 0600 /etc/vram-governor/runtime-tunnel-ed25519
chmod 0644 /etc/vram-governor/runtime-tunnel-ed25519.pub

systemctl daemon-reload
systemctl enable comfy-harness.service vram-governor-runtime-tunnel.service >/dev/null
systemctl restart llama-server.service comfy-harness.service
echo "CMP runtime files installed; authorize the printed public key on the LB before starting the tunnel"
cat /etc/vram-governor/runtime-tunnel-ed25519.pub
