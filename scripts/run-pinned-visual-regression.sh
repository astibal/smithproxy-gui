#!/usr/bin/env bash

set -euo pipefail

readonly PLAYWRIGHT_IMAGE="mcr.microsoft.com/playwright@sha256:47b510dd9230bf0b9bfc9b20102241e577ea7a99334ab4c3ca19f19770e9b8ea"

docker run --rm \
  --user "$(id -u):$(id -g)" \
  --ipc=host \
  -e HOME=/tmp \
  -e PLAYWRIGHT_VISUAL_BASELINE=linux-noble \
  -e PATH=/work/node_modules/.bin:/usr/local/bin:/usr/bin:/bin \
  -v "${PWD}:/work" \
  -w /work \
  "${PLAYWRIGHT_IMAGE}" \
  bash -lc \
  'vite preview --host 127.0.0.1 >/tmp/vite.log 2>&1 &
  sleep 2
  playwright test --project=chromium --grep "Saslik visual regression"'
