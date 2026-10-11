#!/bin/bash
# Fixed GPU performance profile for the VRAM Governor node agent (root).
# idle:   lock the memory clock to the card's lowest supported value (P8-class
#         idle power with models kept resident in VRAM)
# active: reset clocks to driver defaults before work
set -euo pipefail
GPU=${VRAM_GPU_INDEX:-0}
case "${1:-}" in
  idle)
    min=$(/usr/bin/nvidia-smi -i "$GPU" --query-supported-clocks=mem --format=csv,noheader,nounits | sort -n | head -1)
    [[ "$min" =~ ^[0-9]+$ ]] || { echo "no supported memory clock reported" >&2; exit 1; }
    /usr/bin/nvidia-smi -i "$GPU" -lmc "$min" >/dev/null ;;
  active)
    /usr/bin/nvidia-smi -i "$GPU" -rmc >/dev/null ;;
  *) echo "usage: gpu-clock.sh idle|active" >&2; exit 2 ;;
esac
