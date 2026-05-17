#!/usr/bin/env bash
#
# download-model.sh — fetch the Ternary-Bonsai-8B Q2_0 GGUF weights for
# the SN360-ES Tier 2 LLM. Designed to run inside the Kubernetes init
# container declared in deployments/llm/deployment.yaml: it downloads
# the model into the shared `models` volume so the main llama-server
# container can mmap it on startup.
#
# Configuration via environment variables:
#   MODEL_URL  — full URL to the .gguf file (HuggingFace LFS resolve URL)
#   MODEL_DIR  — destination directory on the volume (default /models)
#   MODEL_FILE — destination filename (default Ternary-Bonsai-8B-Q2_0.gguf)
#   HF_TOKEN   — optional HuggingFace token for private/gated mirrors
#
# The script is idempotent: if the destination file already exists with
# a non-zero size, it skips the download. This lets restarted pods reuse
# weights that have already been pulled into a PVC.

set -euo pipefail

MODEL_URL="${MODEL_URL:-https://huggingface.co/prism-ml/Ternary-Bonsai-8B-gguf/resolve/main/Ternary-Bonsai-8B-Q2_0.gguf}"
MODEL_DIR="${MODEL_DIR:-/models}"
MODEL_FILE="${MODEL_FILE:-Ternary-Bonsai-8B-Q2_0.gguf}"

mkdir -p "$MODEL_DIR"
dest="${MODEL_DIR%/}/${MODEL_FILE}"

if [[ -s "$dest" ]]; then
    echo "download-model: $dest already present ($(stat -c %s "$dest") bytes), skipping download." >&2
    exit 0
fi

echo "download-model: fetching $MODEL_URL -> $dest" >&2

auth_header=()
if [[ -n "${HF_TOKEN:-}" ]]; then
    auth_header=(-H "Authorization: Bearer ${HF_TOKEN}")
fi

# Use a temp file and atomic rename so a crash partway through doesn't
# leave a half-written .gguf that llama-server will happily try to mmap.
tmp="${dest}.partial"
trap 'rm -f "$tmp"' EXIT

curl --fail --location --show-error \
    --connect-timeout 30 --retry 5 --retry-delay 10 \
    "${auth_header[@]}" \
    -o "$tmp" \
    "$MODEL_URL"

mv "$tmp" "$dest"
trap - EXIT

echo "download-model: ready at $dest ($(stat -c %s "$dest") bytes)" >&2
