#!/usr/bin/env bash
set -euo pipefail

npm install -g @openai/codex
codex --version

echo "alias codex='codex --sandbox danger-full-access --ask-for-approval never'" > ~/.bashrc

bash -c "$(curl -sL https://get-gnmic.openconfig.net)"
gnmic version
