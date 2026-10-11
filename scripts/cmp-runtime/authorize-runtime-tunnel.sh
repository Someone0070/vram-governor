#!/usr/bin/env bash
set -euo pipefail

public_key="$(tr -d '\r\n')"
if [[ ! "$public_key" =~ ^ssh-ed25519\ [A-Za-z0-9+/=]+\ vram-cmp-runtime-tunnel$ ]]; then
  echo "tunnel public key is malformed" >&2
  exit 64
fi
account=vram-runtime-tunnel
home=/var/lib/vram-runtime-tunnel
if ! id "$account" >/dev/null 2>&1; then
  useradd --system --home-dir "$home" --create-home --shell /usr/sbin/nologin "$account"
fi
group="$(id -gn "$account")"
install -d -m 0700 -o "$account" -g "$group" "$home/.ssh"
entry="restrict,port-forwarding,permitlisten=\"127.0.0.1:9444\",permitlisten=\"127.0.0.1:9445\" $public_key"
printf '%s\n' "$entry" > "$home/.ssh/authorized_keys"
chown "$account:$group" "$home/.ssh/authorized_keys"
chmod 0600 "$home/.ssh/authorized_keys"
echo "runtime tunnel key authorized"
