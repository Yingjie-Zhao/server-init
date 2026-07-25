# server-init

[中文文档](README.zh-CN.md)

[![ci](https://github.com/Yingjie-Zhao/server-init/actions/workflows/ci.yml/badge.svg)](https://github.com/Yingjie-Zhao/server-init/actions/workflows/ci.yml)

**Initialize a server by talking to an AI agent.** The agent probes the machine, confirms the plan with you, then hardens and verifies it in gated stages, each stage proven before the next one starts.

## What it does

- Creates an admin user with your SSH key and passwordless sudo
- Hardens sshd via drop-in config: key-only login, no root login
- Enables the firewall with only the SSH port allowed (UFW or firewalld)
- Installs and enables fail2ban and automatic security updates
- Optionally creates a swap file
- Disables root SSH only after the new admin connection is proven to work

Supported distros: Debian/Ubuntu, RHEL family (RHEL/CentOS Stream/Rocky/Alma/Fedora), Arch Linux. All require systemd.

## Install

Requirements: Node.js ≥ 20 and an AI agent that supports Agent Skills.

```bash
npx skills add Yingjie-Zhao/server-init
```

## Use

Just talk to your agent:

> "I have a fresh server at 203.0.113.10. Initialize it for me: admin user deer, lock it down when ready."

The agent runs a read-only probe, confirms the plan (admin name, swap), then drives three gated stages: **prepare → verify → lockdown**. You approve each step; the tool proves each step.

## Security note

The admin user has passwordless sudo, so the local private key is a root equivalent. Protect it with a passphrase and ssh-agent, or a hardware key.
