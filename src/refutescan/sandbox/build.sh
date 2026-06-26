#!/usr/bin/env bash
# Build the refutescan sandbox image. The image is host/daemon state, not part
# of the pip install — build it once before using sandbox="docker". Re-run after
# changing the Dockerfile or toolrunner.py, or after the docker host is pruned.
set -euo pipefail
cd "$(dirname "$0")"
IMAGE="${REFUTESCAN_SANDBOX_IMAGE:-refutescan-sandbox:current}"
echo "Building ${IMAGE} ..."
docker build -t "${IMAGE}" .
echo "Done. Image: ${IMAGE}"
docker images "${IMAGE}" --format '  {{.Repository}}:{{.Tag}}  {{.Size}}  (built {{.CreatedSince}})'
