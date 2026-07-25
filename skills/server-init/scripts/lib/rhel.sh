# shellcheck shell=bash
# server-init RHEL-family backend (RHEL/CentOS Stream/Rocky/Alma/Fedora): dnf + firewalld + dnf-automatic.
# Shared logic lives in common.sh; this file keeps only distro differences.

# shellcheck source=common.sh
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

server_init_install_packages_rhel() {
  server_init_log 'upgrading packages and installing base packages'
  dnf -y upgrade
  dnf install -y sudo openssh-server curl wget ca-certificates gnupg2 firewalld vim jq rsync tar dnf-automatic
  # Fedora's official repos carry fail2ban; the rest of the RHEL family needs EPEL
  if ! dnf install -y fail2ban 2>/dev/null; then
    server_init_log 'fail2ban not in enabled repos; enabling EPEL'
    dnf install -y epel-release || server_init_die 'fail2ban unavailable and EPEL cannot be enabled'
    dnf install -y fail2ban
  fi
  # htop lives in EPEL on the RHEL family (possibly just enabled above) and in the official
  # repos on Fedora; it is a convenience, not a hardening requirement,
  # so a failed install must not abort prepare
  dnf install -y htop || server_init_log 'htop unavailable; skipping'
}

# firewalld follows a different model than UFW: keep the distro default zone (usually allowing
# only ssh/dhcpv6-client) and just make sure the current SSH port is allowed;
# existing rules stay untouched (DHCPv6 and friends may be required by the cloud provider).
server_init_configure_firewalld() {
  local ssh_port="$1" fw_bin
  server_init_validate_ssh_port "$ssh_port"
  fw_bin="$(server_init_find_cmd firewall-cmd)" || server_init_die 'firewall-cmd not found after package install'
  systemctl enable --now firewalld
  "$fw_bin" --permanent --add-port="${ssh_port}/tcp" >/dev/null
  "$fw_bin" --reload
  if "$fw_bin" --query-port="${ssh_port}/tcp" >/dev/null 2>&1; then
    printf '[server-init-state] component=firewalld status=running ssh_port=%s allows_ssh_port=true\n' "$ssh_port"
  else
    server_init_die "firewalld does not allow TCP/${ssh_port} after reload"
  fi
}

server_init_configure_dnf_automatic() {
  # dnf4 (RHEL 9 family): the dnf-automatic package ships /etc/dnf/automatic.conf, edit in place;
  # dnf5 (Fedora 42+): the file is %ghost, the package only ships a /usr/share template,
  # so create a minimal config ourselves
  local conf="$SERVER_INIT_DNF_AUTOMATIC_CONF"
  if [[ -f "$conf" ]]; then
    # Rewrite via a temp file instead of sed -i: BSD sed (macOS) and GNU sed disagree on -i semantics
    local tmp
    tmp="$(mktemp)"
    sed 's/^apply_updates = .*/apply_updates = yes/' "$conf" > "$tmp"
    cat "$tmp" > "$conf"
    rm -f "$tmp"
  else
    printf '[commands]\napply_updates = yes\n' > "$conf"
  fi
  systemctl enable --now dnf-automatic.timer
}

server_init_rhel_prepare() {
  local admin_user="$1" admin_pubkey="$2" ssh_port="$3" swap_size_mib="${4:-0}"
  server_init_validate_ssh_port "$ssh_port"
  server_init_validate_swap_size_mib "$swap_size_mib"
  # Create swap before running dnf: dnf loads repo metadata into memory, and on 512MB-class
  # machines without swap it gets OOM-killed (observed during the fail2ban install)
  server_init_configure_swap "$swap_size_mib"
  server_init_install_packages_rhel
  server_init_create_admin_user "$admin_user" "$admin_pubkey" wheel
  server_init_ensure_sshd_config_include
  server_init_write_ssh_hardening 'prohibit-password'
  server_init_reload_ssh
  server_init_configure_firewalld "$ssh_port"
  server_init_configure_fail2ban "$ssh_port"
  server_init_configure_dnf_automatic
  server_init_log 'prepare complete; verify admin SSH and sudo before lockdown'
}

server_init_rhel_lockdown() {
  local admin_user="$1"
  server_init_validate_username "$admin_user"
  server_init_admin_has_key_and_sudo "$admin_user" wheel || server_init_die "admin user $admin_user is not ready; refusing to disable root SSH"
  server_init_write_ssh_hardening 'no'
  server_init_reload_ssh
  server_init_log 'lockdown complete'
}
