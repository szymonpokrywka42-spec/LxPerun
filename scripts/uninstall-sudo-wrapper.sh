#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this script with sudo:" >&2
  echo "  sudo bash scripts/uninstall-sudo-wrapper.sh" >&2
  exit 1
fi

rm -f /usr/local/bin/lxperun /usr/local/bin/lxperun-sys
echo "Removed /usr/local/bin/lxperun and /usr/local/bin/lxperun-sys"
