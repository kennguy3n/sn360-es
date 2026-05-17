#!/bin/sh
#
# download-model.sh — fetch the Ternary-Bonsai-8B Q2_0 GGUF weights for
# the SN360-ES Tier 2 LLM. Designed to run inside the Kubernetes init
# container declared in deployments/llm/deployment.yaml: it downloads
# the model into the shared `models` volume so the main llama-server
# container can mmap it on startup.
#
# The script is POSIX sh, not bash. The init container image
# (curlimages/curl) is Alpine-based and only ships busybox ash as
# /bin/sh, so we deliberately avoid bash-only features: no arrays,
# no [[ ]], no `set -o pipefail`. The optional auth header is built
# via the positional-parameter trick (`set --`) instead.
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

set -eu

MODEL_URL="${MODEL_URL:-https://huggingface.co/prism-ml/Ternary-Bonsai-8B-gguf/resolve/main/Ternary-Bonsai-8B-Q2_0.gguf}"
MODEL_DIR="${MODEL_DIR:-/models}"
MODEL_FILE="${MODEL_FILE:-Ternary-Bonsai-8B-Q2_0.gguf}"

mkdir -p "$MODEL_DIR"
dest="${MODEL_DIR%/}/${MODEL_FILE}"

# file_size prints the byte count of $1 in a portable way. BusyBox ash
# on Alpine has neither `stat -c` (coreutils-only) nor `stat -f` (BSD),
# so fall back to `wc -c` which is in every POSIX environment.
file_size() {
    wc -c <"$1" | tr -d ' \n\t'
}

if [ -s "$dest" ]; then
    echo "download-model: $dest already present ($(file_size "$dest") bytes), skipping download." >&2
    exit 0
fi

echo "download-model: fetching $MODEL_URL -> $dest" >&2

# Build the optional Authorization header in $@ so it expands to zero
# args when HF_TOKEN is unset (rather than the single empty arg that a
# quoted shell variable would otherwise produce and that would confuse
# curl into thinking it had received an empty positional URL).
set --
if [ -n "${HF_TOKEN:-}" ]; then
    set -- -H "Authorization: Bearer ${HF_TOKEN}"
fi

# Use a temp file and atomic rename so a crash partway through doesn't
# leave a half-written .gguf that llama-server will happily try to mmap.
tmp="${dest}.partial"
trap 'rm -f "$tmp"' EXIT

curl --fail --location --show-error \
    --connect-timeout 30 --retry 5 --retry-delay 10 \
    "$@" \
    -o "$tmp" \
    "$MODEL_URL"

mv "$tmp" "$dest"
trap - EXIT

echo "download-model: ready at $dest ($(file_size "$dest") bytes)" >&2
