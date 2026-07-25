# shellcheck shell=bash
# server-init Arch Linux backend: pacman + UFW.
# Shared logic lives in common.sh; this file keeps only distro differences.

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

server_init_install_packages_arch() {
  server_init_log 'syncing and upgrading packages'
  pacman -Syu --noconfirm
  server_init_log 'installing base packages'
  pacman -S --needed --noconfirm sudo openssh curl wget ca-certificates gnupg ufw fail2ban vim htop jq rsync
}

server_init_arch_prepare() {
  local admin_user="$1" admin_pubkey="$2" ssh_port="$3" swap_size_mib="${4:-0}"
  server_init_validate_ssh_port "$ssh_port"
  server_init_validate_swap_size_mib "$swap_size_mib"
  server_init_install_packages_arch
  server_init_configure_swap "$swap_size_mib"
  server_init_create_admin_user "$admin_user" "$admin_pubkey" wheel
  server_init_ensure_sshd_config_include
  server_init_write_ssh_hardening 'prohibit-password'
  server_init_reload_ssh
  server_init_configure_ufw "$ssh_port"
  server_init_configure_fail2ban "$ssh_port"
  # No automatic upgrades on Arch: unattended upgrades are a known source of breakage on rolling releases
  server_init_log 'automatic package upgrades are intentionally not configured on Arch'
  server_init_log 'prepare complete; verify admin SSH and sudo before lockdown'
}

server_init_arch_lockdown() {
  local admin_user="$1"
  server_init_validate_username "$admin_user"
  server_init_admin_has_key_and_sudo "$admin_user" wheel || server_init_die "admin user $admin_user is not ready; refusing to disable root SSH"
  server_init_write_ssh_hardening 'no'
  server_init_reload_ssh
  server_init_log 'lockdown complete'
}
