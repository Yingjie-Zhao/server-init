#!/usr/bin/env bash
# server-init remote bootstrap entrypoint: detect the distro and dispatch to a lib/<os>.sh backend.
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  cat <<'USAGE'
Usage:
  sudo bash bootstrap-linux.sh prepare --admin-user USER --admin-pubkey 'SSH_PUBLIC_KEY' --ssh-port PORT [--swap-size-mib MiB]
  sudo bash bootstrap-linux.sh lockdown --admin-user USER
USAGE
}

die() { printf '[server-init-bootstrap] error: %s\n' "$*" >&2; exit 1; }
require_root() { [[ "${EUID}" -eq 0 ]] || die 'run as root'; }

load_os_release() {
  # Env var can override the path, consistent with SERVER_INIT_SWAP_FILE etc. in common.sh, to ease testing
  local os_release="${SERVER_INIT_OS_RELEASE:-/etc/os-release}"
  [[ -r "$os_release" ]] || die "missing ${os_release}; unsupported Linux distribution"
  # shellcheck disable=SC1090
  . "$os_release"
  OS_ID="${ID:-}"
  OS_ID_LIKE="${ID_LIKE:-}"
  OS_VERSION_ID="${VERSION_ID:-}"
}

# Takes OS_ID and OS_ID_LIKE, prints the backend name; returns 1 when unsupported.
# All three current backends are systemd distros; Alpine (OpenRC) and friends need a separate service-management contract.
server_init_select_backend() {
  local os_id="$1" os_id_like="$2"
  case "$os_id" in debian|ubuntu) printf 'debian\n'; return 0 ;; esac
  case "$os_id" in rhel|centos|rocky|almalinux|fedora) printf 'rhel\n'; return 0 ;; esac
  case "$os_id" in arch) printf 'arch\n'; return 0 ;; esac
  case " $os_id_like " in *' debian '*) printf 'debian\n'; return 0 ;; esac
  case " $os_id_like " in *' rhel '*|*' fedora '*) printf 'rhel\n'; return 0 ;; esac
  case " $os_id_like " in *' arch '*) printf 'arch\n'; return 0 ;; esac
  return 1
}

load_backend() {
  local backend="$1"
  # shellcheck source=lib/common.sh
  source "$SCRIPT_DIR/lib/common.sh"
  # shellcheck source=lib/debian.sh
  source "$SCRIPT_DIR/lib/${backend}.sh"
}

run_prepare() {
  local admin_user='' admin_pubkey='' ssh_port='' swap_size_mib='0'
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --admin-user) admin_user="${2:-}"; shift 2 ;;
      --admin-pubkey) admin_pubkey="${2:-}"; shift 2 ;;
      --ssh-port) ssh_port="${2:-}"; shift 2 ;;
      --swap-size-mib) swap_size_mib="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown prepare argument: $1" ;;
    esac
  done
  [[ -n "$admin_user" ]] || die 'missing --admin-user'
  [[ -n "$admin_pubkey" ]] || die 'missing --admin-pubkey'
  [[ -n "$ssh_port" ]] || die 'missing --ssh-port'
  local backend
  # detect_backend runs in a command-substitution subshell, so the variables its load_os_release
  # sets never reach this shell; the log line below references OS_ID/OS_VERSION_ID,
  # so load them again in the current shell
  load_os_release
  backend="$(detect_backend)"
  load_backend "$backend"
  server_init_log "detected supported distribution: ${PRETTY_NAME:-$OS_ID $OS_VERSION_ID} (backend: $backend)"
  case "$backend" in
    debian) server_init_debian_prepare "$admin_user" "$admin_pubkey" "$ssh_port" "$swap_size_mib" ;;
    rhel) server_init_rhel_prepare "$admin_user" "$admin_pubkey" "$ssh_port" "$swap_size_mib" ;;
    arch) server_init_arch_prepare "$admin_user" "$admin_pubkey" "$ssh_port" "$swap_size_mib" ;;
    *) die "no prepare implementation for backend: $backend" ;;
  esac
}

run_lockdown() {
  local admin_user=''
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --admin-user) admin_user="${2:-}"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown lockdown argument: $1" ;;
    esac
  done
  [[ -n "$admin_user" ]] || die 'missing --admin-user'
  local backend
  backend="$(detect_backend)"
  load_backend "$backend"
  case "$backend" in
    debian) server_init_debian_lockdown "$admin_user" ;;
    rhel) server_init_rhel_lockdown "$admin_user" ;;
    arch) server_init_arch_lockdown "$admin_user" ;;
    *) die "no lockdown implementation for backend: $backend" ;;
  esac
}

# Every backend requires systemd (fail2ban, firewall and automatic updates all depend on it)
detect_backend() {
  load_os_release
  command -v systemctl >/dev/null 2>&1 || die 'server-init requires systemd; this distribution is not supported'
  server_init_select_backend "$OS_ID" "$OS_ID_LIKE" \
    || die "unsupported distribution: ${PRETTY_NAME:-$OS_ID $OS_VERSION_ID}"
}

main() {
  local command="${1:-}"
  [[ -n "$command" ]] || { usage; exit 1; }
  shift || true
  case "$command" in
    prepare) require_root; run_prepare "$@" ;;
    lockdown) require_root; run_lockdown "$@" ;;
    -h|--help) usage ;;
    *) usage; die "unknown command: $command" ;;
  esac
}

# source guard: tests can source this file and call server_init_select_backend directly
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main "$@"
fi
