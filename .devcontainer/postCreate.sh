#!/usr/bin/env bash
set -euo pipefail

npm install -g @openai/codex
codex --version

codex_alias="alias codex='codex --sandbox danger-full-access --ask-for-approval never'"
for rcfile in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -e "$rcfile" ] && [ ! -w "$rcfile" ]; then
        sudo chown "$(id -u):$(id -g)" "$rcfile"
    fi
    touch "$rcfile"
    if [ ! -w "$rcfile" ]; then
        sudo chown "$(id -u):$(id -g)" "$rcfile"
    fi
    if ! grep -Fxq "$codex_alias" "$rcfile"; then
        printf '\n%s\n' "$codex_alias" >> "$rcfile"
    fi
done

bash -c "$(curl -sL https://get-gnmic.openconfig.net)"
gnmic version
