#!/usr/bin/env node
// server-init local CLI: the deterministic backend for preflight and the three bootstrap stages.
// Design rule: all remote logic lives in the bash scripts under scripts/;
// this file only does SSH orchestration and stable JSON output.
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';

export const SCHEMA_VERSION = 'server-init.result.v1';

// ---------- basic utilities ----------

export function nowIso() {
  return new Date().toISOString().replace(/\.\d{3}Z$/, 'Z');
}

// Expand ~ and $VAR, matching Python's expanduser/expandvars behaviour
export function expand(p) {
  if (p == null) return null;
  let s = String(p);
  if (s === '~') s = os.homedir();
  else if (s.startsWith('~/')) s = path.join(os.homedir(), s.slice(2));
  return s.replace(/\$(\w+)|\$\{([^}]+)\}/g, (match, plain, braced) => process.env[plain ?? braced] ?? match);
}

// Shell single-quote escaping, equivalent to shlex.quote
export function shq(s) {
  return `'${String(s).replaceAll("'", `'\\''`)}'`;
}

// Run synchronously and normalize the result; timeouts map to returncode 124, like GNU timeout
export function run(cmd, { input = null, timeoutSec = 60 } = {}) {
  const result = spawnSync(cmd[0], cmd.slice(1), {
    input: input ?? undefined,
    encoding: 'utf8',
    timeout: timeoutSec * 1000,
    maxBuffer: 32 * 1024 * 1024,
  });
  const timedOut = Boolean(result.error && result.error.code === 'ETIMEDOUT');
  let stderr = result.stderr ?? '';
  if (timedOut) stderr = `${stderr}\ncommand timed out after ${timeoutSec}s`.trim();
  else if (result.error) stderr = `${stderr}\n${result.error.message}`.trim();
  return {
    returncode: timedOut ? 124 : (result.status ?? 1),
    stdout: result.stdout ?? '',
    stderr,
    timedOut,
  };
}

// ---------- stable JSON output ----------

export function finding(severity, code, message, { evidence, suggestedAction } = {}) {
  const item = { severity, code, message };
  if (evidence) item.evidence = evidence;
  if (suggestedAction) item.suggested_action = suggestedAction;
  return item;
}

export function basePayload(stage, { host = null, ok = false, facts = null, findings = null, ...extra } = {}) {
  const payload = {
    schema_version: SCHEMA_VERSION,
    generated_at: nowIso(),
    ok,
    stage,
    findings: findings ?? [],
    facts: facts ?? {},
  };
  if (host !== null) payload.host = host;
  return Object.assign(payload, extra);
}

export function emit(payload) {
  process.stdout.write(`${JSON.stringify(payload, null, 2)}\n`);
}

// ---------- SSH failure classification ----------

export function classifySshFailure(result) {
  const text = `${result.stderr}\n${result.stdout}`.trim().toLowerCase();
  if (result.timedOut) return 'timeout';
  if (text.includes('connection timed out during banner exchange')) return 'banner_timeout';
  if (text.includes('operation timed out') || text.includes('connection timed out')) return 'tcp_timeout';
  if (text.includes('connection refused')) return 'tcp_refused';
  if (text.includes('no route to host') || text.includes('network is unreachable')) return 'network_unreachable';
  if (text.includes('permission denied (publickey') || text.includes('too many authentication failures')) return 'auth_failed';
  if (text.includes('host key verification failed')) return 'host_key_failed';
  const isSudoFailure = text.includes('sudo:') && (
    text.includes('a password is required')
    || text.includes('password is required')
    || text.includes('not in the sudoers')
    || text.includes('not allowed to execute')
  );
  if (isSudoFailure) return 'sudo_failed';
  if (result.returncode !== 0) return 'remote_command_failed';
  return 'none';
}

export function sshFailureFinding(result, context = 'ssh command failed') {
  const code = classifySshFailure(result);
  // Keep the tail, not the head: package-manager output is verbose and the real error (e.g. mkswap/swapon) is at the end
  const raw = result.stderr.trim() || result.stdout.trim() || `exit code ${result.returncode}`;
  const evidence = raw.slice(-4000);
  const messages = {
    timeout: 'SSH command timed out.',
    banner_timeout: 'SSH TCP connection opened but the server did not complete the SSH banner exchange.',
    tcp_timeout: 'SSH TCP connection timed out.',
    tcp_refused: 'SSH TCP connection was refused.',
    network_unreachable: 'Target network is unreachable.',
    auth_failed: 'SSH public-key authentication failed.',
    host_key_failed: 'SSH host key verification failed.',
    sudo_failed: 'Remote sudo check failed.',
    remote_command_failed: context,
  };
  const actions = {
    banner_timeout: 'Check sshd health, fail2ban, and system load from the provider console.',
    tcp_timeout: 'Check network path, firewall rules, and whether sshd is listening.',
    tcp_refused: 'Check sshd service status and the configured SSH port.',
    auth_failed: 'Install the matching public key or use the correct identity file.',
    host_key_failed: 'Verify the server identity before changing known_hosts.',
    sudo_failed: 'Ensure the selected admin account has passwordless sudo.',
  };
  return finding('critical', code, messages[code] ?? context, { evidence, suggestedAction: actions[code] });
}

// ---------- SSH/SCP command construction ----------

// Security baseline: no passwords, TOFU accepts new host keys; never bypass with StrictHostKeyChecking=no
export function sshBase(host, sshPort, user, identity, { connectTimeout = 10 } = {}) {
  const cmd = [
    'ssh',
    '-o', 'BatchMode=yes',
    '-o', 'PasswordAuthentication=no',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', `ConnectTimeout=${connectTimeout}`,
    '-p', String(sshPort),
  ];
  if (identity) cmd.push('-o', 'IdentitiesOnly=yes', '-i', expand(identity));
  cmd.push(`${user}@${host}`);
  return cmd;
}

export function buildScpCmd(host, sshPort, user, identity, localPath, remotePath) {
  const cmd = [
    'scp',
    '-o', 'BatchMode=yes',
    '-o', 'PasswordAuthentication=no',
    '-o', 'StrictHostKeyChecking=accept-new',
    '-o', 'ConnectTimeout=10',
    '-P', String(sshPort),
  ];
  if (identity) cmd.push('-o', 'IdentitiesOnly=yes', '-i', expand(identity));
  cmd.push(String(localPath), `${user}@${host}:${remotePath}`);
  return cmd;
}

export function scpTo(host, sshPort, user, identity, localPath, remotePath) {
  return run(buildScpCmd(host, sshPort, user, identity, localPath, remotePath), { timeoutSec: 60 });
}

export function sshScript(host, sshPort, user, identity, script, { timeoutSec = 60 } = {}) {
  return run([...sshBase(host, sshPort, user, identity), 'sh', '-s'], { input: script, timeoutSec });
}

export function sshCommand(host, sshPort, user, identity, remoteCommand, { timeoutSec = 60 } = {}) {
  return run([...sshBase(host, sshPort, user, identity), remoteCommand], { timeoutSec });
}

// ---------- probe ----------

export function parseKeyValues(text) {
  const data = {};
  for (const line of text.split('\n')) {
    const idx = line.indexOf('=');
    if (idx > -1) data[line.slice(0, idx).trim()] = line.slice(idx + 1).trim();
  }
  return data;
}

const BOOLEAN_FACTS = new Set([
  'has_sudo', 'has_systemctl', 'has_apt_get', 'has_dnf', 'has_pacman', 'has_ufw',
  'has_firewall_cmd', 'has_fail2ban_client', 'has_sshd', 'sudo_nopasswd',
  'sshd_config_ok', 'ufw_allows_ssh_port', 'firewalld_allows_ssh_port',
]);
const INTEGER_FACTS = new Set([
  'uid', 'ssh_port', 'fail2ban_sshd_banned', 'mem_total_kb',
  'mem_available_kb', 'swap_total_kb', 'swap_free_kb',
  'root_disk_total_kb', 'root_disk_available_kb', 'root_disk_used_percent',
]);

// The probe emits strings only; normalize to booleans/integers/arrays so agents can consume facts directly
export function normalizeFacts(facts) {
  const normalized = {};
  for (const [key, value] of Object.entries(facts)) {
    if (BOOLEAN_FACTS.has(key)) normalized[key] = value === '0';
    else if (INTEGER_FACTS.has(key)) normalized[key] = /^\d+$/.test(value) ? Number.parseInt(value, 10) : value;
    else if (key.endsWith('_csv')) normalized[key.slice(0, -4)] = value.split(',').filter(Boolean);
    else if (value === 'true' || value === 'false') normalized[key] = value === 'true';
    else normalized[key] = value;
  }
  return normalized;
}

export function buildProbeScript(sshPort, { useSudo = false } = {}) {
  // Digits-only port, so interpolating the probe template has no shell injection surface
  if (!/^\d+$/.test(String(sshPort))) throw new Error(`invalid SSH port for probe: ${sshPort}`);
  const template = fs.readFileSync(new URL('../scripts/probe.sh', import.meta.url), 'utf8');
  return template
    .replaceAll('__SSH_PORT__', String(sshPort))
    .replaceAll('__FORCE_SUDO__', useSudo ? '1' : '0');
}

export function runProbe(stage, { host, sshPort, user, identity, timeoutSec = 60, useSudo = false }) {
  const result = sshScript(host, sshPort, user, identity, buildProbeScript(sshPort, { useSudo }), { timeoutSec });
  if (result.returncode !== 0) {
    return [null, [sshFailureFinding(result, `${stage} probe failed`)]];
  }
  return [normalizeFacts(parseKeyValues(result.stdout)), []];
}

// ---------- preflight ----------

export function preflight(opts) {
  const [facts, findings] = runProbe('preflight', {
    host: opts.host, sshPort: opts.sshPort, user: opts.user,
    identity: opts.identityFile, timeoutSec: opts.timeout,
  });
  const ok = facts !== null;
  emit(basePayload('preflight', { host: opts.host, ok, facts, findings }));
  return ok ? 0 : 1;
}

// ---------- bootstrap ----------

function readValueOrFile(value, filePath) {
  if (filePath) return fs.readFileSync(expand(filePath), 'utf8').trim();
  if (value) return value.trim();
  throw new Error('missing required value or file');
}

function remoteMkdir(host, sshPort, user, identity) {
  const result = sshCommand(host, sshPort, user, identity, 'mktemp -d /tmp/server-init.XXXXXX');
  if (result.returncode !== 0) throw new Error(result.stderr.trim() || result.stdout.trim());
  return result.stdout.trim();
}

function copyBootstrapScripts(host, sshPort, user, identity, remoteDir) {
  const mkdir = sshCommand(host, sshPort, user, identity, `mkdir -p ${shq(remoteDir)}/lib`);
  if (mkdir.returncode !== 0) throw new Error(mkdir.stderr.trim() || mkdir.stdout.trim());
  const scriptsRoot = new URL('../scripts/', import.meta.url);
  const files = [[new URL('bootstrap-linux.sh', scriptsRoot), `${remoteDir}/bootstrap-linux.sh`]];
  // Copy every distro backend under lib/ wholesale: adding one (e.g. lib/arch.sh) needs no CLI change
  const libDir = fileURLToPath(new URL('lib/', scriptsRoot));
  for (const entry of fs.readdirSync(libDir)) {
    if (entry.endsWith('.sh')) files.push([new URL(`lib/${entry}`, scriptsRoot), `${remoteDir}/lib/${entry}`]);
  }
  for (const [local, remote] of files) {
    const result = scpTo(host, sshPort, user, identity, fileURLToPath(local), remote);
    if (result.returncode !== 0) throw new Error(result.stderr.trim() || result.stdout.trim());
  }
}

function sudoPrefix(user, useSudo = false) {
  return user === 'root' && !useSudo ? '' : 'sudo -n ';
}

function cleanupRemote(host, sshPort, user, identity, remoteDir, { useSudo = false } = {}) {
  const prefix = sudoPrefix(user, useSudo);
  return sshCommand(host, sshPort, user, identity, `${prefix}rm -rf ${shq(remoteDir)}`, { timeoutSec: 30 });
}

export function bootstrapPrepare(opts) {
  const findings = [];
  const adminPubkey = readValueOrFile(opts.adminPubkey, opts.adminPubkeyFile);
  let remoteDir = null;
  try {
    remoteDir = remoteMkdir(opts.host, opts.sshPort, opts.sshUser, opts.identityFile);
    copyBootstrapScripts(opts.host, opts.sshPort, opts.sshUser, opts.identityFile, remoteDir);
    const prefix = sudoPrefix(opts.sshUser, opts.useSudo);
    const cmd = (
      `${prefix}bash ${shq(remoteDir)}/bootstrap-linux.sh prepare `
      + `--admin-user ${shq(opts.adminUser)} `
      + `--admin-pubkey ${shq(adminPubkey)} `
      + `--ssh-port ${shq(opts.sshPort)} `
      + `--swap-size-mib ${shq(opts.swapSizeMib)}`
    );
    const result = sshCommand(opts.host, opts.sshPort, opts.sshUser, opts.identityFile, cmd, { timeoutSec: opts.timeout });
    if (result.returncode !== 0) {
      findings.push(sshFailureFinding(result, 'bootstrap prepare failed'));
      emit(basePayload('bootstrap.prepare', {
        host: opts.host, ok: false, findings,
        stdout: result.stdout, stderr: result.stderr,
        next_step: 'Fix prepare errors, then run bootstrap verify.',
      }));
      return 1;
    }
    emit(basePayload('bootstrap.prepare', {
      host: opts.host, ok: true,
      facts: { ssh_port: opts.sshPort, admin_user: opts.adminUser, swap_size_mib: opts.swapSizeMib },
      stdout: result.stdout, stderr: result.stderr,
      next_step: 'Run bootstrap verify with the admin identity before lockdown.',
    }));
    return 0;
  } finally {
    if (remoteDir) cleanupRemote(opts.host, opts.sshPort, opts.sshUser, opts.identityFile, remoteDir, { useSudo: opts.useSudo });
  }
}

// verify is the safety gate for lockdown: any critical finding must block finalization
export function verifyFindings(facts, sshPort) {
  const findings = [];
  if (!facts.sudo_nopasswd) {
    findings.push(finding('critical', 'admin_sudo_unavailable', 'Admin user cannot run sudo without a password.', { suggestedAction: 'Fix the admin sudoers rule before lockdown.' }));
  }
  if (!facts.sshd_config_ok) {
    findings.push(finding('critical', 'sshd_config_invalid', 'sshd configuration validation failed.', { suggestedAction: 'Run sshd -t from the provider console.' }));
  }
  const ufwActive = facts.ufw_status === 'active';
  const firewalldActive = facts.firewalld_status === 'running';
  // An active firewall that misses the SSH port is a lockout risk; no active firewall is only a warning
  if (ufwActive && !facts.ufw_allows_ssh_port) {
    findings.push(finding('critical', 'ufw_missing_ssh_allow', `UFW is active but does not allow SSH port ${sshPort}.`, { suggestedAction: `Allow TCP/${sshPort} before lockdown.` }));
  }
  if (firewalldActive && facts.firewalld_allows_ssh_port === false) {
    findings.push(finding('critical', 'firewalld_missing_ssh_allow', `firewalld is running but does not allow SSH port ${sshPort}.`, { suggestedAction: `Add TCP/${sshPort} to the active firewalld zone before lockdown.` }));
  }
  if (!ufwActive && !firewalldActive) {
    findings.push(finding('warning', 'no_active_firewall', 'Neither UFW nor firewalld is active.'));
  }
  if (facts.fail2ban_active === false) {
    findings.push(finding('warning', 'fail2ban_inactive', 'fail2ban is not active.'));
  }
  return findings;
}

export function bootstrapVerify(opts, { printPayload = true } = {}) {
  const [facts, findings] = runProbe('bootstrap.verify', {
    host: opts.host, sshPort: opts.sshPort, user: opts.adminUser,
    identity: opts.adminIdentityFile, timeoutSec: opts.timeout, useSudo: true,
  });
  if (facts === null) {
    const payload = basePayload('bootstrap.verify', { host: opts.host, ok: false, findings });
    if (printPayload) emit(payload);
    return { code: 1, payload };
  }
  findings.push(...verifyFindings(facts, opts.sshPort));
  const ok = !findings.some((item) => item.severity === 'critical');
  const payload = basePayload('bootstrap.verify', {
    host: opts.host, ok, facts, findings,
    next_step: 'Run bootstrap lockdown only after this verify stage is ok.',
  });
  if (printPayload) emit(payload);
  return { code: ok ? 0 : 1, payload };
}

export function bootstrapLockdown(opts) {
  // Force a fresh verify before lockdown: if verify fails, never touch root login
  const verify = bootstrapVerify(opts, { printPayload: false });
  if (verify.code !== 0) {
    emit(Object.assign(verify.payload, {
      stage: 'bootstrap.lockdown', ok: false, blocked: true,
      next_step: 'Fix bootstrap verify findings before lockdown; no remote lockdown was attempted.',
    }));
    return 1;
  }
  const findings = [];
  let remoteDir = null;
  try {
    remoteDir = remoteMkdir(opts.host, opts.sshPort, opts.adminUser, opts.adminIdentityFile);
    copyBootstrapScripts(opts.host, opts.sshPort, opts.adminUser, opts.adminIdentityFile, remoteDir);
    const cmd = `sudo -n bash ${shq(remoteDir)}/bootstrap-linux.sh lockdown --admin-user ${shq(opts.adminUser)}`;
    const result = sshCommand(opts.host, opts.sshPort, opts.adminUser, opts.adminIdentityFile, cmd, { timeoutSec: opts.timeout });
    if (result.returncode !== 0) {
      findings.push(sshFailureFinding(result, 'bootstrap lockdown failed'));
      emit(basePayload('bootstrap.lockdown', { host: opts.host, ok: false, facts: verify.payload.facts, findings, stdout: result.stdout, stderr: result.stderr }));
      return 1;
    }
    const adminCheck = sshCommand(opts.host, opts.sshPort, opts.adminUser, opts.adminIdentityFile, 'sudo -n true', { timeoutSec: 30 });
    if (adminCheck.returncode !== 0) {
      findings.push(sshFailureFinding(adminCheck, 'post-lockdown admin verification failed'));
    }
    // Reverse check: root login must fail; success would mean lockdown did not take effect
    const rootIdentity = opts.rootIdentityFile || opts.adminIdentityFile;
    const rootCheck = sshCommand(opts.host, opts.sshPort, 'root', rootIdentity, 'true', { timeoutSec: 20 });
    const rootSshDisabled = rootCheck.returncode !== 0;
    if (!rootSshDisabled) {
      findings.push(finding('critical', 'root_ssh_still_enabled', 'root SSH still succeeded after lockdown.'));
    }
    const ok = !findings.some((item) => item.severity === 'critical');
    emit(basePayload('bootstrap.lockdown', {
      host: opts.host, ok,
      facts: { ...verify.payload.facts, root_ssh_disabled: rootSshDisabled },
      findings, stdout: result.stdout, stderr: result.stderr,
      next_step: 'Bootstrap complete; install additional modules as needed.',
    }));
    return ok ? 0 : 1;
  } finally {
    if (remoteDir) cleanupRemote(opts.host, opts.sshPort, opts.adminUser, opts.adminIdentityFile, remoteDir, { useSudo: true });
  }
}

// ---------- init: scaffold the user's personal ops repo ----------

const INVENTORY_TEMPLATE = `# server-init inventory: a git-managed host list. Connection info only, never secrets.
ssh:
  user: admin
  identity_file: ~/.ssh/id_ed25519
  port: 22

hosts: []
#  - 203.0.113.10
#  - web-1.example.com
#  Prefer stable DNS names over IPs where possible.
`;

export function init(opts) {
  const target = path.resolve(expand(opts.dir ?? '.'));
  fs.mkdirSync(target, { recursive: true });
  const inventoryPath = path.join(target, 'inventory.yaml');
  const created = [];
  const skipped = [];
  if (fs.existsSync(inventoryPath)) skipped.push('inventory.yaml');
  else {
    fs.writeFileSync(inventoryPath, INVENTORY_TEMPLATE);
    created.push('inventory.yaml');
  }
  emit(basePayload('init', {
    ok: true,
    facts: { dir: target, created, skipped },
    next_step: 'Fill in hosts, then ask your agent to run preflight and bootstrap. Keep this ops repo private and never commit secrets: no private keys, passwords, tokens, or .env files.',
  }));
  return 0;
}

// ---------- CLI parsing ----------

class UsageError extends Error {}

const COMMON = {
  host: { type: 'string' },
  'ssh-port': { type: 'string', default: '22' },
  'identity-file': { type: 'string' },
};

const COMMAND_SPECS = {
  preflight: {
    options: {
      ...COMMON,
      user: { type: 'string' },
      timeout: { type: 'string', default: '60' },
    },
    required: ['host', 'user'],
  },
  init: {
    options: { dir: { type: 'string' } },
    required: [],
  },
};

const BOOTSTRAP_STAGE_SPECS = {
  prepare: {
    options: {
      ...COMMON,
      'ssh-user': { type: 'string' },
      'use-sudo': { type: 'boolean', default: false },
      'admin-user': { type: 'string' },
      'admin-pubkey': { type: 'string' },
      'admin-pubkey-file': { type: 'string' },
      'swap-size-mib': { type: 'string', default: '0' },
      timeout: { type: 'string', default: '900' },
    },
    required: ['host', 'ssh-user', 'admin-user'],
  },
  verify: {
    options: {
      host: { type: 'string' },
      'ssh-port': { type: 'string', default: '22' },
      'admin-user': { type: 'string' },
      'admin-identity-file': { type: 'string' },
      timeout: { type: 'string', default: '60' },
    },
    required: ['host', 'admin-user'],
  },
  lockdown: {
    options: {
      host: { type: 'string' },
      'ssh-port': { type: 'string', default: '22' },
      'admin-user': { type: 'string' },
      'admin-identity-file': { type: 'string' },
      'root-identity-file': { type: 'string' },
      timeout: { type: 'string', default: '120' },
    },
    required: ['host', 'admin-user'],
  },
};

function parseStageArgs(args, spec) {
  let values;
  try {
    ({ values } = parseArgs({ args, options: spec.options, strict: true, allowPositionals: false }));
  } catch (err) {
    throw new UsageError(err.message);
  }
  const missing = spec.required.filter((name) => !values[name]);
  if (missing.length > 0) throw new UsageError(`missing required option(s): ${missing.map((n) => `--${n}`).join(' ')}`);
  return values;
}

function toInt(name, value, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  if (!/^\d+$/.test(String(value))) throw new UsageError(`--${name} must be an integer, got: ${value}`);
  const n = Number.parseInt(String(value), 10);
  if (n < min || n > max) throw new UsageError(`--${name} must be between ${min} and ${max}, got: ${n}`);
  return n;
}

const USAGE = `server-init - initialize a server by talking to an AI agent

Usage:
  server-init init [--dir PATH]
  server-init preflight --host HOST --user USER [--ssh-port 22] [--identity-file PATH] [--timeout 60]
  server-init bootstrap prepare --host HOST --ssh-user USER --admin-user USER
      (--admin-pubkey KEY | --admin-pubkey-file PATH)
      [--ssh-port 22] [--identity-file PATH] [--use-sudo] [--swap-size-mib 0] [--timeout 900]
  server-init bootstrap verify --host HOST --admin-user USER
      [--ssh-port 22] [--admin-identity-file PATH] [--timeout 60]
  server-init bootstrap lockdown --host HOST --admin-user USER
      [--ssh-port 22] [--admin-identity-file PATH] [--root-identity-file PATH] [--timeout 120]

All commands emit stable JSON on stdout. Exit codes: 0 ok, 1 failed, 2 usage error.
`;

export function parseCli(argv) {
  const [command, ...rest] = argv;
  if (command === undefined || command === '--help' || command === '-h' || command === 'help') {
    return { command: 'help' };
  }
  if (command === 'bootstrap') {
    const [stage, ...stageRest] = rest;
    const spec = BOOTSTRAP_STAGE_SPECS[stage];
    if (!spec) throw new UsageError(`bootstrap requires a stage: prepare, verify, or lockdown`);
    return { command, stage, values: parseStageArgs(stageRest, spec) };
  }
  const spec = COMMAND_SPECS[command];
  if (!spec) throw new UsageError(`unknown command: ${command}`);
  return { command, values: parseStageArgs(rest, spec) };
}

export function main(argv = process.argv.slice(2)) {
  let parsed;
  try {
    parsed = parseCli(argv);
  } catch (err) {
    if (err instanceof UsageError) {
      emit(basePayload('cli', { ok: false, findings: [finding('critical', 'usage_error', err.message)] }));
      return 2;
    }
    throw err;
  }

  try {
    if (parsed.command === 'help') {
      process.stdout.write(USAGE);
      return 0;
    }
    if (parsed.command === 'init') return init({ dir: parsed.values.dir });
    if (parsed.command === 'preflight') {
      return preflight({
        host: parsed.values.host,
        sshPort: toInt('ssh-port', parsed.values['ssh-port'], { min: 1, max: 65535 }),
        user: parsed.values.user,
        identityFile: parsed.values['identity-file'],
        timeout: toInt('timeout', parsed.values.timeout, { min: 1 }),
      });
    }
    // bootstrap's three stages
    const v = parsed.values;
    if (parsed.stage === 'prepare') {
      return bootstrapPrepare({
        host: v.host,
        sshPort: toInt('ssh-port', v['ssh-port'], { min: 1, max: 65535 }),
        sshUser: v['ssh-user'],
        identityFile: v['identity-file'],
        useSudo: v['use-sudo'],
        adminUser: v['admin-user'],
        adminPubkey: v['admin-pubkey'],
        adminPubkeyFile: v['admin-pubkey-file'],
        swapSizeMib: toInt('swap-size-mib', v['swap-size-mib']),
        timeout: toInt('timeout', v.timeout, { min: 1 }),
      });
    }
    if (parsed.stage === 'verify') {
      return bootstrapVerify({
        host: v.host,
        sshPort: toInt('ssh-port', v['ssh-port'], { min: 1, max: 65535 }),
        adminUser: v['admin-user'],
        adminIdentityFile: v['admin-identity-file'],
        timeout: toInt('timeout', v.timeout, { min: 1 }),
      }).code;
    }
    return bootstrapLockdown({
      host: v.host,
      sshPort: toInt('ssh-port', v['ssh-port'], { min: 1, max: 65535 }),
      adminUser: v['admin-user'],
      adminIdentityFile: v['admin-identity-file'],
      rootIdentityFile: v['root-identity-file'],
      timeout: toInt('timeout', v.timeout, { min: 1 }),
    });
  } catch (err) {
    emit(basePayload('error', { ok: false, findings: [finding('critical', 'internal_error', err.message)] }));
    return 1;
  }
}

// Run main only when executed as a script; tests import the functions without side effects
const invokedAsScript = process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href;
if (invokedAsScript) process.exitCode = main();
