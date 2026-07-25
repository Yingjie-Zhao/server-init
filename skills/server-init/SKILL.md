---
name: server-init
description: Conversational bootstrap of a fresh server with a security baseline. Read-only probe, hardening, lockout-proof lockdown. Use when the user mentions setting up or initializing a new server, SSH hardening, or a server security baseline.
---

# server-init: conversational server bootstrap

server-init turns "set up a fresh server securely" into a conversation with verification gates. The agent drives the local CLI through three stages; each stage emits stable JSON, and **a stage may only start after the previous one reports `ok: true`**.

In the commands below, `bin/server-init.mjs` is relative to **this skill's install directory** (the CLI and scripts ship with the skill, self-contained). Remote scripts are uploaded and executed by the CLI automatically; never copy them by hand.

## Principles

- Read-only first, changes second: run preflight before any change and act on facts.
- Never lock the user out: prepare keeps root login untouched; verify proves a **new admin connection** independently; the CLI forces a fresh verify before lockdown.
- Only ever attempt login with one confirmed `(host, port, user, identity)` tuple; stop after an authentication failure instead of cycling through usernames or keys.
- Initial access is SSH key authentication only, never username/password. Getting the public key onto the server is the user's prerequisite; when it is missing, guide the user through it instead of doing it for them.
- First-seen host keys use TOFU (accept-new); a changed, previously recorded key must stop the flow and be reported, never bypassed.
- Secrets (private keys, passwords, tokens) are never written into any file, repo, log or reply.
- Anything that can affect SSH or the firewall is done one host at a time, and the user is reminded to keep an out-of-band console (web console, serial console, recovery mode) open as a recovery path.

## Security tradeoff

The admin user gets **passwordless sudo** so the agent can act without a password prompt, which makes the local private key a root equivalent. Tell the user to protect it with a passphrase and ssh-agent, or a hardware key. If the user does not accept this, delete `/etc/sudoers.d/90-<admin>-nopasswd` after bootstrap and use password-protected sudo, at the cost of being present for privileged commands.

## Main flow

1. **Collect connection info and confirm prerequisites**: host (IP or domain), SSH port (default 22), initial user, local private key path, the admin username to create, and the admin public key path.

   Initial access is SSH key authentication only (no username/password); installing the public key is done by the user before starting, e.g. `ssh-copy-id -i ~/.ssh/id_ed25519.pub USER@HOST` or via the machine's console.

   The initial user depends on the machine image: often root, or a sudo-capable user such as `ubuntu` or `ec2-user`. A non-root initial user must have passwordless sudo and prepare needs `--use-sudo`; preflight elevates automatically when it detects passwordless sudo, no extra flag needed.

   How to confirm: go straight to step 2 and run preflight; `auth_failed` means the prerequisite is not done — guide the user through it and retry.
2. **preflight** (read-only):

   ```bash
   node bin/server-init.mjs preflight --host HOST --user root --identity-file ~/.ssh/id_ed25519
   ```

   Interpret the JSON for the user: whether the OS is supported (Debian/Ubuntu, RHEL family, Arch; all require systemd), memory and swap (suggest `--swap-size-mib 2048` when RAM ≤ 1 GiB with no swap), and the current sshd/firewall/fail2ban state.
3. **Confirm decisions in conversation**: admin username, swap size. Continue only after the user confirms.
4. **prepare** (makes changes, takes a few minutes, upgrades system packages):

   ```bash
   node bin/server-init.mjs bootstrap prepare \
     --host HOST --ssh-user root --identity-file ~/.ssh/id_ed25519 \
     --admin-user ADMIN --admin-pubkey-file ~/.ssh/id_ed25519.pub \
     [--swap-size-mib 2048]
   ```

   Report afterwards: admin created (passwordless sudo), SSH hardening drop-in, firewall (only the SSH port allowed), fail2ban, automatic security updates.
5. **verify** (safety gate, must authenticate as admin):

   ```bash
   node bin/server-init.mjs bootstrap verify \
     --host HOST --admin-user ADMIN --admin-identity-file ~/.ssh/id_ed25519
   ```

   Continue only on `ok: true`; fix any critical findings first.
6. **lockdown** (finalize, disables root SSH):

   ```bash
   node bin/server-init.mjs bootstrap lockdown \
     --host HOST --admin-user ADMIN --admin-identity-file ~/.ssh/id_ed25519
   ```

   Summarize the final state to the user afterwards.

## JSON contract

Every command prints `server-init.result.v1` JSON on stdout: `ok` (boolean), `stage`, `facts` (system facts), `findings` (array; `severity` is critical/warning). Exit codes: 0 success, 1 failure, 2 usage error. Translate each finding's `message` and `suggested_action` into plain language for the user.

## Troubleshooting

- `auth_failed`: the prerequisite is not done — confirm the public key is installed for the right user (see step 1), or use the correct identity file.
- `tcp_timeout` / `banner_timeout`: check firewall/security-group rules and sshd health; use the out-of-band console when needed.
- `sudo_failed` in verify: the admin's passwordless sudo is not set up; inspect `/etc/sudoers.d/` over the initial connection.
- When SSH is unavailable entirely, inspect from the out-of-band console:

  ```bash
  sudo systemctl status ssh --no-pager
  sudo journalctl -u ssh -n 100 --no-pager
  sudo ss -ltnp
  sudo sshd -t
  sudo ufw status numbered          # UFW distros
  sudo firewall-cmd --list-all      # firewalld distros
  sudo fail2ban-client status sshd
  ```
