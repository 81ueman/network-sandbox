#!/usr/bin/env bash
set -euo pipefail

npm install -g @openai/codex
codex --version

bash -c "$(curl -sL https://get-gnmic.openconfig.net)"
gnmic version
