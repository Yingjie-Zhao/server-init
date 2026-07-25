# shellcheck shell=bash
# server-init shared backend logic: sourced by lib/<os>.sh, never executed directly.
# Platform differences (packages, firewall, automatic updates) live in the distro backends.

SERVER_INIT_HARDENING_FILE="/etc/ssh/sshd_config.d/10-server-init-hardening.conf"
SERVER_INIT_FAIL2BAN_JAIL="/etc/fail2ban/jail.d/server-init-sshd.local"
SERVER_INIT_SWAP_FILE="${SERVER_INIT_SWAP_FILE:-/swapfile}"
SERVER_INIT_FSTAB="${SERVER_INIT_FSTAB:-/etc/fstab}"
SERVER_INIT_SYSCTL_SWAP_FILE="${SERVER_INIT_SYSCTL_SWAP_FILE:-/etc/sysctl.d/99-server-init-swap.conf}"
SERVER_INIT_MEMINFO="${SERVER_INIT_MEMINFO:-/proc/meminfo}"
SERVER_INIT_DNF_AUTOMATIC_CONF="${SERVER_INIT_DNF_AUTOMATIC_CONF:-/etc/dnf/automatic.conf}"

server_init_log() { printf '[server-init-bootstrap] %s\n' "$*"; }
server_init_die() { printf '[server-init-bootstrap] error: %s\n' "$*" >&2; exit 1; }

server_init_find_cmd() {
  command -v "$1" 2>/dev/null && return 0
  local path
  for path in /usr/sbin/"$1" /usr/bin/"$1" /sbin/"$1" /bin/"$1"; do
    [[ -x "$path" ]] && { printf '%s\n' "$path"; return 0; }
  done
  return 1
}

# ---------- input validation ----------

server_init_validate_username() {
  local username="$1"
  [[ "$username" =~ ^[a-z_][a-z0-9_-]*$ ]] || server_init_die "invalid username: $username"
}

server_init_validate_ssh_port() {
  local port="$1"
  [[ "$port" =~ ^[0-9]+$ ]] || server_init_die "invalid SSH port: $port"
  (( port >= 1 && port <= 65535 )) || server_init_die "invalid SSH port: $port"
}

server_init_validate_swap_size_mib() {
  local size_mib="$1"
  [[ "$size_mib" =~ ^[0-9]+$ ]] || server_init_die "invalid swap size MiB: $size_mib"
  (( size_mib >= 0 )) || server_init_die "invalid swap size MiB: $size_mib"
}

server_init_validate_pubkey() {
  local pubkey="$1"
  [[ "$pubkey" =~ ^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp256|ecdsa-sha2-nistp384|ecdsa-sha2-nistp521|sk-ssh-ed25519@openssh.com|sk-ecdsa-sha2-nistp256@openssh.com)[[:space:]]+[^[:space:]]+ ]] \
    || server_init_die 'invalid SSH public key'
}

# ---------- sshd ----------

server_init_sshd_bin() {
  server_init_find_cmd sshd || server_init_die 'sshd not found'
}

server_init_test_sshd_config() {
  local bin
  bin="$(server_init_sshd_bin)"
  "$bin" -t
}

server_init_reload_ssh() {
  server_init_test_sshd_config
  systemctl reload ssh.service >/dev/null 2>&1 || systemctl reload sshd.service >/dev/null 2>&1 || service ssh reload
}

# Some distros (the RHEL family, some Arch images) ship an sshd_config without an Include
# for the drop-in directory. sshd uses first-match semantics, so the Include must precede
# the main config, otherwise drop-ins never take effect.
server_init_ensure_sshd_config_include() {
  local main_config="/etc/ssh/sshd_config"
  grep -Eq '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d' "$main_config" && return 0
  install -d -m 0755 /etc/ssh/sshd_config.d
  cp "$main_config" "${main_config}.server-init.bak"
  { printf 'Include /etc/ssh/sshd_config.d/*.conf\n\n'; cat "${main_config}.server-init.bak"; } > "$main_config"
  if ! server_init_test_sshd_config; then
    cp "${main_config}.server-init.bak" "$main_config"
    server_init_die 'adding sshd_config.d Include broke sshd configuration; restored backup'
  fi
  server_init_log 'added Include for /etc/ssh/sshd_config.d to sshd_config'
}

server_init_write_ssh_hardening() {
  local permit_root_login="$1"
  install -d -m 0755 /etc/ssh/sshd_config.d
  cat > "$SERVER_INIT_HARDENING_FILE" <<EOF
# Managed by server-init
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin ${permit_root_login}
EOF
}

# ---------- admin user and sudoers ----------

# Older sudo or minimal images may ship an /etc/sudoers without the sudoers.d includedir.
server_init_ensure_sudoers_include() {
  local sudoers="/etc/sudoers"
  grep -Eq '^[[:space:]]*[@#]includedir[[:space:]]+/etc/sudoers\.d' "$sudoers" && return 0
  cp "$sudoers" "${sudoers}.server-init.bak"
  printf '\n@includedir /etc/sudoers.d\n' >> "$sudoers"
  if ! visudo -c >/dev/null 2>&1; then
    cp "${sudoers}.server-init.bak" "$sudoers"
    server_init_die 'adding sudoers.d includedir broke sudoers; restored backup'
  fi
  server_init_log 'added @includedir for /etc/sudoers.d to sudoers'
}

# All distros use useradd plus a '*' password: '*' means "no password login, account not locked",
# so public-key login works; '!' (the useradd default) makes sshd treat the account as locked.
server_init_create_admin_user() {
  local username="$1" pubkey="$2" sudo_group="$3" home_dir auth_file sudoers_file
  server_init_validate_username "$username"
  server_init_validate_pubkey "$pubkey"
  if id "$username" >/dev/null 2>&1; then
    server_init_log "admin user exists: $username"
  else
    useradd -m -s /bin/bash "$username"
    usermod -p '*' "$username"
  fi
  usermod -aG "$sudo_group" "$username"
  server_init_ensure_sudoers_include
  sudoers_file="/etc/sudoers.d/90-${username}-nopasswd"
  printf '%s ALL=(ALL) NOPASSWD:ALL\n' "$username" > "$sudoers_file"
  chmod 0440 "$sudoers_file"
  visudo -cf "$sudoers_file" >/dev/null
  home_dir="$(getent passwd "$username" | cut -d: -f6)"
  [[ -n "$home_dir" ]] || server_init_die "cannot resolve home directory for $username"
  install -d -m 0700 -o "$username" -g "$username" "$home_dir/.ssh"
  auth_file="$home_dir/.ssh/authorized_keys"
  touch "$auth_file"
  chown "$username:$username" "$auth_file"
  chmod 0600 "$auth_file"
  if ! grep -qxF "$pubkey" "$auth_file"; then printf '%s\n' "$pubkey" >> "$auth_file"; fi
  chown "$username:$username" "$auth_file"
  chmod 0600 "$auth_file"
}

server_init_admin_has_key_and_sudo() {
  local username="$1" sudo_group="$2" home_dir
  id "$username" >/dev/null 2>&1 || return 1
  id -nG "$username" | tr ' ' '\n' | grep -qx "$sudo_group" || return 1
  home_dir="$(getent passwd "$username" | cut -d: -f6)"
  [[ -s "$home_dir/.ssh/authorized_keys" ]] || return 1
}

# ---------- UFW (shared by Debian/Arch) ----------

server_init_ufw_allows_port() {
  local ufw_bin="$1" ssh_port="$2"
  "$ufw_bin" status 2>/dev/null | grep -Eq "(^|[[:space:]])${ssh_port}(/tcp)?([[:space:]]+on[[:space:]]+[^[:space:]]+)?[[:space:]]+ALLOW"
}

server_init_print_ufw_status() {
  local ufw_bin="$1" ssh_port="$2" status allows
  status="$("$ufw_bin" status 2>/dev/null | awk -F': ' 'NR==1 {print tolower($2)}')"
  if server_init_ufw_allows_port "$ufw_bin" "$ssh_port"; then allows=true; else allows=false; fi
  printf '[server-init-state] component=ufw status=%s ssh_port=%s allows_ssh_port=%s\n' "${status:-unknown}" "$ssh_port" "$allows"
}

server_init_configure_ufw() {
  local ssh_port="$1" ufw_bin
  server_init_validate_ssh_port "$ssh_port"
  ufw_bin="$(server_init_find_cmd ufw)" || server_init_die 'ufw not found after package install'
  "$ufw_bin" default deny incoming
  "$ufw_bin" default allow outgoing
  "$ufw_bin" allow "${ssh_port}/tcp"
  "$ufw_bin" --force enable
  server_init_print_ufw_status "$ufw_bin" "$ssh_port"
}

# ---------- fail2ban (shared by all distros) ----------

server_init_configure_fail2ban() {
  local ssh_port="$1"
  server_init_validate_ssh_port "$ssh_port"
  install -d -m 0755 /etc/fail2ban/jail.d
  cat > "$SERVER_INIT_FAIL2BAN_JAIL" <<EOF
[sshd]
enabled = true
port = ${ssh_port}
backend = systemd
maxretry = 5
findtime = 10m
bantime = 1h
EOF
  systemctl enable --now fail2ban
  systemctl restart fail2ban
}

# ---------- swap (shared by all distros) ----------

server_init_swap_total_mib() {
  awk '/SwapTotal:/ {printf "%d", ($2 + 1023) / 1024}' "$SERVER_INIT_MEMINFO" 2>/dev/null || printf '0'
}

server_init_swap_mount_dir() {
  dirname "$SERVER_INIT_SWAP_FILE"
}

server_init_root_free_mib_for_swap() {
  df -Pm "$(server_init_swap_mount_dir)" 2>/dev/null | awk 'NR==2 {print $4}'
}

server_init_swap_file_size_mib() {
  local bytes
  bytes="$(stat -c %s "$SERVER_INIT_SWAP_FILE" 2>/dev/null || printf '0')"
  [[ "$bytes" =~ ^[0-9]+$ ]] || bytes='0'
  printf '%d' $(( (bytes + 1048575) / 1048576 ))
}

server_init_write_swappiness() {
  install -d -m 0755 "$(dirname "$SERVER_INIT_SYSCTL_SWAP_FILE")"
  cat > "$SERVER_INIT_SYSCTL_SWAP_FILE" <<'EOF'
# Managed by server-init
vm.swappiness=10
EOF
  sysctl -w vm.swappiness=10 >/dev/null 2>&1 || true
}

server_init_fstab_has_swapfile() {
  awk -v path="$SERVER_INIT_SWAP_FILE" '$1 == path && $2 == "none" && $3 == "swap" && $4 == "sw" && $5 == "0" && $6 == "0" { found = 1 } END { exit found ? 0 : 1 }' "$SERVER_INIT_FSTAB" 2>/dev/null
}

server_init_ensure_swap_fstab() {
  touch "$SERVER_INIT_FSTAB"
  if ! server_init_fstab_has_swapfile; then
    printf '%s none swap sw 0 0\n' "$SERVER_INIT_SWAP_FILE" >> "$SERVER_INIT_FSTAB"
  fi
}

server_init_create_swap_file() {
  local size_mib="$1"
  # btrfs requires a NOCOW swapfile, otherwise swapon fails with Invalid argument;
  # +C must be set on the empty file before any data is written.
  # When non-GNU stat (e.g. macOS) errors out, treat the filesystem as non-btrfs
  local fstype
  fstype="$(stat -f -c %T "$(server_init_swap_mount_dir)" 2>/dev/null || true)"
  if [[ "$fstype" == 'btrfs' ]]; then
    : > "$SERVER_INIT_SWAP_FILE"
    chattr +C "$SERVER_INIT_SWAP_FILE"
  fi
  if command -v fallocate >/dev/null 2>&1; then
    fallocate -l "${size_mib}M" "$SERVER_INIT_SWAP_FILE" || dd if=/dev/zero of="$SERVER_INIT_SWAP_FILE" bs=1M count="$size_mib" status=none
  else
    dd if=/dev/zero of="$SERVER_INIT_SWAP_FILE" bs=1M count="$size_mib" status=none
  fi
  chmod 0600 "$SERVER_INIT_SWAP_FILE"
  if ! mkswap "$SERVER_INIT_SWAP_FILE" >/dev/null; then
    rm -f "$SERVER_INIT_SWAP_FILE"
    server_init_die "failed to initialize swap file: $SERVER_INIT_SWAP_FILE"
  fi
  if ! swapon "$SERVER_INIT_SWAP_FILE"; then
    rm -f "$SERVER_INIT_SWAP_FILE"
    server_init_die "failed to enable swap file: $SERVER_INIT_SWAP_FILE"
  fi
}

server_init_configure_swap() {
  local requested_mib="$1" active_mib free_mib required_free_mib
  server_init_validate_swap_size_mib "$requested_mib"
  if (( requested_mib == 0 )); then
    server_init_log 'swap provisioning skipped'
    return 0
  fi

  active_mib="$(server_init_swap_total_mib)"
  [[ "$active_mib" =~ ^[0-9]+$ ]] || active_mib='0'
  if (( active_mib >= requested_mib )); then
    server_init_log "active swap already satisfies request: ${active_mib}MiB >= ${requested_mib}MiB"
    server_init_write_swappiness
    return 0
  fi

  if [[ -e "$SERVER_INIT_SWAP_FILE" ]]; then
    if server_init_fstab_has_swapfile; then
      local file_mib
      file_mib="$(server_init_swap_file_size_mib)"
      if (( file_mib >= requested_mib )); then
        chmod 0600 "$SERVER_INIT_SWAP_FILE"
        server_init_log "activating existing server-init swap file: ${SERVER_INIT_SWAP_FILE} (${file_mib}MiB)"
        swapon "$SERVER_INIT_SWAP_FILE" || server_init_die "failed to enable existing server-init swap file: $SERVER_INIT_SWAP_FILE"
        server_init_write_swappiness
        return 0
      fi
      server_init_die "existing server-init swap file is smaller than requested; refusing to resize automatically: $SERVER_INIT_SWAP_FILE"
    fi
    server_init_die "existing non-server-init swap path exists; refusing to overwrite: $SERVER_INIT_SWAP_FILE"
  fi

  free_mib="$(server_init_root_free_mib_for_swap)"
  [[ "$free_mib" =~ ^[0-9]+$ ]] || server_init_die 'cannot determine free disk space before creating swap'
  required_free_mib=$(( requested_mib + 256 ))
  (( free_mib >= required_free_mib )) || server_init_die "not enough free disk for ${requested_mib}MiB swap; need at least ${required_free_mib}MiB free, found ${free_mib}MiB"

  server_init_log "creating swap file: ${SERVER_INIT_SWAP_FILE} (${requested_mib}MiB)"
  server_init_create_swap_file "$requested_mib"
  server_init_ensure_swap_fstab
  server_init_write_swappiness
}
