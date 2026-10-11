#!/usr/bin/env bash
set -euo pipefail

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
installer="$repo_dir/install-mesh.sh"
fixture=$(mktemp -d -t vram-mesh-test.XXXXXXXX)
cleanup() { [[ ! -d "$fixture" ]] || rm -r -- "$fixture"; }
trap cleanup EXIT

mkdir -- "$fixture/join"
printf '%s\n' 'test certificate bytes' > "$fixture/join/controller-ca.pem"
cat > "$fixture/join/join.env" <<'EOF'
CONTROLLER_URL=wss://10.0.0.115:8443/ws/node
FLEET_ENROLLMENT_TOKEN=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
NODE_COMMAND_SECRET=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
EOF
chmod 0600 -- "$fixture/join/join.env"
fingerprint=$(sha256sum -- "$fixture/join/controller-ca.pem")
fingerprint=${fingerprint%% *}

output=$(bash "$installer" --role head --join-bundle "$fixture/join" --expected-fingerprint "$fingerprint" --dry-run)
[[ "$output" == *"role=head location=local power_mode=dont_touch"* && "$output" == *"No configuration, secret, or service was changed."* ]] || { echo "head defaults did not pass" >&2; exit 1; }

output=$(bash "$installer" --role slave --join-bundle "$fixture/join" --expected-fingerprint "$fingerprint" --dry-run)
[[ "$output" == *"role=slave location=remote power_mode=manual"* ]] || { echo "slave defaults did not pass" >&2; exit 1; }

output=$(bash "$installer" --role worker --join-bundle "$fixture/join" --expected-fingerprint "$fingerprint" --dry-run)
[[ "$output" == *"role=slave location=remote power_mode=manual"* ]] || { echo "worker alias did not pass" >&2; exit 1; }

if bash "$installer" --role head --join-bundle "$fixture/join" --expected-fingerprint "$(printf '0%.0s' {1..64})" --dry-run > "$fixture/rejected.out" 2>&1; then
  echo "mismatched fingerprint was accepted" >&2; exit 1
fi
[[ "$(<"$fixture/rejected.out")" == *"fingerprint mismatch"* ]] || { echo "fingerprint rejection reason missing" >&2; exit 1; }

if bash "$installer" --role wrong --dry-run > "$fixture/rejected.out" 2>&1; then
  echo "invalid role was accepted" >&2; exit 1
fi

printf 'safe.example\n' > "$fixture/controller.yaml"
printf 'safe.example\n' > "$fixture/controller.env"
output=$(bash "$installer" --role lb --config "$fixture/controller.yaml" --environment-file "$fixture/controller.env" --dry-run)
[[ "$output" == *"role=lb location=n/a power_mode=n/a"* ]] || { echo "LB dry run did not pass" >&2; exit 1; }

output=$(bash "$installer" --role controller --config "$fixture/controller.yaml" --environment-file "$fixture/controller.env" --dry-run)
[[ "$output" == *"role=lb location=n/a power_mode=n/a"* ]] || { echo "controller alias did not pass" >&2; exit 1; }

if bash "$installer" --role lb --config "$fixture/controller.yaml" --environment-file "$fixture/controller.env" --power-mode dont_touch --dry-run > "$fixture/rejected.out" 2>&1; then
  echo "LB accepted a worker power option" >&2; exit 1
fi

echo "Mesh installer dry-run tests passed."
