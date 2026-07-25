# shellcheck shell=sh
# server-init remote read-only probe.
# Injected by the local CLI via `ssh ... sh -s`; __SSH_PORT__ and __FORCE_SUDO__
# are replaced with validated values by the CLI before execution (port is digits-only, so injection-safe).
set +e
ssh_port=__SSH_PORT__
force_sudo=__FORCE_SUDO__
find_bin() {
  command -v "$1" 2>/dev/null && return 0
  for path in /usr/sbin/"$1" /usr/bin/"$1" /sbin/"$1" /bin/"$1"; do
    [ -x "$path" ] && { printf '%s\n' "$path"; return 0; }
  done
  return 1
}
run_privileged() {
  if [ "${use_privileged:-false}" = "true" ] && [ -n "${sudo_bin:-}" ]; then "$sudo_bin" -n "$@"; else "$@"; fi
}
printf 'remote_schema_version=server-init.remote.probe.v1\n'
printf 'user=%s\n' "$(id -un 2>/dev/null)"
printf 'uid=%s\n' "$(id -u 2>/dev/null)"
printf 'hostname=%s\n' "$(hostname 2>/dev/null)"
printf 'ssh_port=%s\n' "$ssh_port"
if [ -r /etc/os-release ]; then
  . /etc/os-release
  printf 'os_id=%s\n' "${ID:-}"
  printf 'os_id_like=%s\n' "${ID_LIKE:-}"
  printf 'os_version_id=%s\n' "${VERSION_ID:-}"
  printf 'os_pretty_name=%s\n' "${PRETTY_NAME:-}"
fi
printf 'kernel=%s\n' "$(uname -srm 2>/dev/null)"
printf 'mem_total_kb=%s\n' "$(awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null)"
printf 'mem_available_kb=%s\n' "$(awk '/MemAvailable:/ {print $2}' /proc/meminfo 2>/dev/null)"
printf 'swap_total_kb=%s\n' "$(awk '/SwapTotal:/ {print $2}' /proc/meminfo 2>/dev/null)"
printf 'swap_free_kb=%s\n' "$(awk '/SwapFree:/ {print $2}' /proc/meminfo 2>/dev/null)"
printf 'root_disk_total_kb=%s\n' "$(df -Pk / 2>/dev/null | awk 'NR==2 {print $2}')"
printf 'root_disk_available_kb=%s\n' "$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')"
printf 'root_disk_used_percent=%s\n' "$(df -Pk / 2>/dev/null | awk 'NR==2 {gsub("%", "", $5); print $5}')"
find_bin sudo >/dev/null 2>&1; printf 'has_sudo=%s\n' "$?"
find_bin systemctl >/dev/null 2>&1; printf 'has_systemctl=%s\n' "$?"
find_bin apt-get >/dev/null 2>&1; printf 'has_apt_get=%s\n' "$?"
find_bin dnf >/dev/null 2>&1; printf 'has_dnf=%s\n' "$?"
find_bin pacman >/dev/null 2>&1; printf 'has_pacman=%s\n' "$?"
find_bin ufw >/dev/null 2>&1; printf 'has_ufw=%s\n' "$?"
find_bin firewall-cmd >/dev/null 2>&1; printf 'has_firewall_cmd=%s\n' "$?"
find_bin fail2ban-client >/dev/null 2>&1; printf 'has_fail2ban_client=%s\n' "$?"
find_bin sshd >/dev/null 2>&1; printf 'has_sshd=%s\n' "$?"
sudo_bin="$(find_bin sudo || true)"
sudo_status=127
if [ -n "$sudo_bin" ]; then "$sudo_bin" -n true >/dev/null 2>&1; sudo_status="$?"; fi
printf 'sudo_nopasswd=%s\n' "$sudo_status"
use_privileged=false
if [ "$(id -u 2>/dev/null)" = "0" ]; then use_privileged=false
elif [ "$sudo_status" = "0" ]; then use_privileged=true
elif [ "$force_sudo" = "1" ]; then use_privileged=true
fi
sshd_bin="$(find_bin sshd || true)"
if [ -n "$sshd_bin" ]; then
  run_privileged "$sshd_bin" -t >/dev/null 2>&1
  printf 'sshd_config_ok=%s\n' "$?"
  sshd_t_output="$(run_privileged "$sshd_bin" -T 2>/dev/null || true)"
  printf 'sshd_ports_csv=%s\n' "$(printf '%s\n' "$sshd_t_output" | awk '$1=="port" {printf "%s%s", sep, $2; sep=","}')"
  printf 'permit_root_login=%s\n' "$(printf '%s\n' "$sshd_t_output" | awk '$1=="permitrootlogin" {print $2; exit}')"
  printf 'password_authentication=%s\n' "$(printf '%s\n' "$sshd_t_output" | awk '$1=="passwordauthentication" {print $2; exit}')"
  printf 'kbd_interactive_authentication=%s\n' "$(printf '%s\n' "$sshd_t_output" | awk '$1=="kbdinteractiveauthentication" {print $2; exit}')"
  printf 'pubkey_authentication=%s\n' "$(printf '%s\n' "$sshd_t_output" | awk '$1=="pubkeyauthentication" {print $2; exit}')"
else
  printf 'sshd_config_ok=127\n'
fi
ufw_bin="$(find_bin ufw || true)"
if [ -n "$ufw_bin" ]; then
  ufw_status_output="$(run_privileged "$ufw_bin" status 2>/dev/null || true)"
  ufw_rules_output="$(run_privileged "$ufw_bin" status numbered 2>/dev/null || true)"
  printf 'ufw_status=%s\n' "$(printf '%s\n' "$ufw_status_output" | awk -F': ' 'NR==1 {print tolower($2)}')"
  printf '%s\n' "$ufw_rules_output" | grep -Eq "(^|[[:space:]])${ssh_port}(/tcp)?([[:space:]]+on[[:space:]]+[^[:space:]]+)?[[:space:]]+ALLOW"; printf 'ufw_allows_ssh_port=%s\n' "$?"
else
  printf 'ufw_status=missing\n'
  printf 'ufw_allows_ssh_port=127\n'
fi
fwcmd="$(find_bin firewall-cmd || true)"
if [ -n "$fwcmd" ]; then
  fw_state="$(run_privileged "$fwcmd" --state 2>/dev/null || true)"
  printf 'firewalld_status=%s\n' "${fw_state:-unknown}"
  run_privileged "$fwcmd" --query-port="${ssh_port}/tcp" >/dev/null 2>&1; printf 'firewalld_allows_ssh_port=%s\n' "$?"
else
  printf 'firewalld_status=missing\n'
  printf 'firewalld_allows_ssh_port=127\n'
fi
systemctl_bin="$(find_bin systemctl || true)"
if [ -n "$systemctl_bin" ] && "$systemctl_bin" is-active --quiet fail2ban 2>/dev/null; then printf 'fail2ban_active=true\n'; else printf 'fail2ban_active=false\n'; fi
fail2ban_bin="$(find_bin fail2ban-client || true)"
if [ -n "$fail2ban_bin" ]; then
  fail2ban_status="$(run_privileged "$fail2ban_bin" status sshd 2>/dev/null || true)"
  printf 'fail2ban_sshd_banned=%s\n' "$(printf '%s\n' "$fail2ban_status" | awk -F: '/Currently banned/ {gsub(/[[:space:]]/, "", $2); print $2; exit}')"
else
  printf 'fail2ban_sshd_banned=0\n'
fi
