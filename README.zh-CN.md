# server-init

[![ci](https://github.com/Yingjie-Zhao/server-init/actions/workflows/ci.yml/badge.svg)](https://github.com/Yingjie-Zhao/server-init/actions/workflows/ci.yml)

**与 AI Agent 对话，初始化一台服务器。** Agent 先探测机器，和你确认方案，然后分阶段加固、验证、收口。每一步验证完成后才开始下一步，确保执行无误。

## 它做什么

- 创建 admin 用户：你的 SSH 公钥 + 免密 sudo
- 通过 drop-in 配置加固 sshd：仅密钥登录、禁 root
- 启用防火墙，只放行 SSH 端口（UFW 或 firewalld）
- 安装并启用 fail2ban 与自动安全更新
- 可选创建 swap
- 新 admin 连接验证通过后，才关闭 root SSH

支持：Debian/Ubuntu、RHEL 系（RHEL/CentOS Stream/Rocky/Alma/Fedora）、Arch Linux，均需 systemd。

## 安装

需要：Node.js ≥ 20，以及一个支持 Agent Skills 的 AI Agent。

```bash
npx skills add Yingjie-Zhao/server-init
```

## 使用

直接对 Agent 说：

> "我有台新服务器 203.0.113.10，帮我初始化一下。admin 用户叫 deer，装好后做安全收口。"

Agent 会只读探测机器，与你确认方案（admin 用户名、swap），然后驱动闸门式流程：**prepare → verify → lockdown**。每一步你批准，每一步工具自证。

## 安全提示

admin 用户是免密 sudo，本地私钥等同于 root。请为私钥设置密码短语并使用 ssh-agent，或使用硬件密钥。
