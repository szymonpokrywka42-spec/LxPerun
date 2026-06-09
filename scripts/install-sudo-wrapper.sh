#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Run this script with sudo:" >&2
  echo "  sudo bash scripts/install-sudo-wrapper.sh" >&2
  exit 1
fi

user_name="${SUDO_USER:-${USER:-}}"
if [[ -z "${user_name}" ]]; then
  echo "Unable to determine the non-root user." >&2
  exit 1
fi

user_home="$(getent passwd "${user_name}" | cut -d: -f6)"
if [[ -z "${user_home}" ]]; then
  echo "Unable to resolve home directory for ${user_name}." >&2
  exit 1
fi

install_wrapper() {
  local command_name="$1"
  local source_path="${user_home}/.local/bin/${command_name}"
  local target_path="/usr/local/bin/${command_name}"

  if [[ ! -x "${source_path}" ]]; then
    echo "Skipping ${command_name}: ${source_path} not found or not executable." >&2
    return 0
  fi

  cat > "${target_path}" <<EOF
#!/usr/bin/env bash
exec "${source_path}" "\$@"
EOF
  chmod 755 "${target_path}"
  echo "Installed ${target_path} -> ${source_path}"
}

install_wrapper "lxperun"
install_wrapper "lxperun-sys"
