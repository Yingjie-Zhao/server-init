# shellcheck shell=bash
# server-init Debian/Ubuntu backend: apt + UFW + unattended-upgrades.
# Shared logic lives in common.sh; this file keeps only distro differences.

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

server_init_install_packages_debian() {
  server_init_log 'updating apt metadata and upgrading packages'
  export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a
  apt-get update
  apt-get -y dist-upgrade
  server_init_log 'installing base packages'
  apt-get install -y sudo openssh-server curl wget ca-certificates gnupg lsb-release ufw fail2ban unattended-upgrades vim htop jq rsync needrestart
}

server_init_configure_unattended_upgrades() {
  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF
  systemctl enable --now unattended-upgrades >/dev/null 2>&1 || true
}

server_init_debian_prepare() {
  local admin_user="$1" admin_pubkey="$2" ssh_port="$3" swap_size_mib="${4:-0}"
  server_init_validate_ssh_port "$ssh_port"
  server_init_validate_swap_size_mib "$swap_size_mib"
  server_init_install_packages_debian
  server_init_configure_swap "$swap_size_mib"
  server_init_create_admin_user "$admin_user" "$admin_pubkey" sudo
  server_init_ensure_sshd_config_include
  server_init_write_ssh_hardening 'prohibit-password'
  server_init_reload_ssh
  server_init_configure_ufw "$ssh_port"
  server_init_configure_fail2ban "$ssh_port"
  server_init_configure_unattended_upgrades
  server_init_log 'prepare complete; verify admin SSH and sudo before lockdown'
}

server_init_debian_lockdown() {
  local admin_user="$1"
  server_init_validate_username "$admin_user"
  server_init_admin_has_key_and_sudo "$admin_user" sudo || server_init_die "admin user $admin_user is not ready; refusing to disable root SSH"
  server_init_write_ssh_hardening 'no'
  server_init_reload_ssh
  server_init_log 'lockdown complete'
}
