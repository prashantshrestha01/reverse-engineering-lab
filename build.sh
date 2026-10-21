#!/bin/sh
# Build the vault exercise binary.
# -O0 and -g, and no strip: symbols are kept on purpose. This binary is a
# study target - objdump is supposed to show you validate_input by name.
set -e
cd "$(dirname "$0")"
gcc -O0 -g -Wall -Wextra -o vault src/vault.c
echo "built ./vault"
