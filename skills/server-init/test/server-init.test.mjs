import assert from 'node:assert/strict';
import { test } from 'node:test';
import { spawnSync } from 'node:child_process';
import {
  SCHEMA_VERSION,
  basePayload,
  buildProbeScript,
  buildScpCmd,
  classifySshFailure,
  finding,
  main,
  normalizeFacts,
  parseCli,
  parseKeyValues,
  sshBase,
  sshFailureFinding,
  verifyFindings,
} from '../bin/server-init.mjs';

function captureStdout(fn) {
  let out = '';
  const original = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk) => { out += chunk; return true; };
  try {
    const code = fn();
    return { code, out };
  } finally {
    process.stdout.write = original;
  }
}

test('CLI only exposes init/preflight/bootstrap and the three stages', () => {
  assert.throws(() => parseCli(['unknown']), /unknown command/);
  assert.throws(() => parseCli(['bootstrap']), /prepare, verify, or lockdown/);
  assert.throws(() => parseCli(['bootstrap', 'init']), /prepare, verify, or lockdown/);
  for (const stage of ['prepare', 'verify', 'lockdown']) {
    assert.equal(parseCli(['bootstrap', stage, ...minimalArgsFor(stage)]).stage, stage);
  }
});

function minimalArgsFor(stage) {
  if (stage === 'prepare') {
    return ['--host', '203.0.113.10', '--ssh-user', 'root', '--admin-user', 'deer', '--admin-pubkey-file', '~/.ssh/id_ed25519.pub'];
  }
  return ['--host', '203.0.113.10', '--admin-user', 'deer'];
}

test('preflight requires explicit host and user', () => {
  assert.throws(() => parseCli(['preflight', '--user', 'deer']), /--host/);
  assert.throws(() => parseCli(['preflight', '--host', 'h']), /--user/);
  const { values } = parseCli(['preflight', '--host', 'example.com', '--ssh-port', '22', '--user', 'deer', '--identity-file', '~/.ssh/id_ed25519']);
  assert.equal(values.host, 'example.com');
  assert.equal(values.user, 'deer');
  assert.equal(values['ssh-port'], '22');
});

test('bootstrap prepare defaults swap to 0 and accepts an explicit value', () => {
  const base = ['bootstrap', 'prepare', '--host', '203.0.113.10', '--ssh-user', 'root', '--admin-user', 'deer', '--admin-pubkey-file', '~/.ssh/id_ed25519.pub'];
  assert.equal(parseCli(base).values['swap-size-mib'], '0');
  assert.equal(parseCli([...base, '--swap-size-mib', '2048']).values['swap-size-mib'], '2048');
});

test('main prints usage_error JSON and returns 2 when required options are missing', () => {
  const { code, out } = captureStdout(() => main(['preflight']));
  assert.equal(code, 2);
  const payload = JSON.parse(out);
  assert.equal(payload.ok, false);
  assert.equal(payload.findings[0].code, 'usage_error');
});

test('SSH failure classification covers key scenarios', () => {
  const cases = [
    ['banner_timeout', { returncode: 255, stdout: '', stderr: 'Connection timed out during banner exchange' }],
    ['auth_failed', { returncode: 255, stdout: '', stderr: 'Permission denied (publickey).' }],
    ['sudo_failed', { returncode: 1, stdout: '', stderr: 'sudo: a password is required' }],
    ['host_key_failed', { returncode: 255, stdout: '', stderr: 'Host key verification failed.' }],
    ['tcp_refused', { returncode: 255, stdout: '', stderr: 'connect to host 203.0.113.10 port 22: Connection refused' }],
    ['timeout', { returncode: 124, stdout: '', stderr: '', timedOut: true }],
  ];
  for (const [expected, result] of cases) {
    assert.equal(classifySshFailure(result), expected, expected);
  }
});

test('SSH/SCP baseline: TOFU accepts new keys, host key checking is never disabled', () => {
  for (const cmd of [
    sshBase('example.com', 22, 'deer', '~/.ssh/id_ed25519'),
    buildScpCmd('example.com', 22, 'deer', '~/.ssh/id_ed25519', '/tmp/a', '/tmp/b'),
  ]) {
    const text = cmd.join(' ');
    assert.match(text, /StrictHostKeyChecking=accept-new/);
    assert.doesNotMatch(text, /StrictHostKeyChecking=no/);
    assert.match(text, /BatchMode=yes/);
    assert.match(text, /IdentitiesOnly=yes/);
  }
});

test('evidence keeps the tail of the output so package-manager noise does not drown the real error', () => {
  // Regression: slice(0, 4000) would cut off the real error (at the end) when dnf fails
  const noise = 'x'.repeat(5000);
  const result = { returncode: 1, stdout: '', stderr: `${noise}\nswapon: /swapfile: swapon failed: Invalid argument` };
  const item = sshFailureFinding(result, 'bootstrap prepare failed');
  assert.equal(item.code, 'remote_command_failed');
  assert.ok(item.evidence.length <= 4000);
  assert.match(item.evidence, /swapon failed: Invalid argument/);
});

test('finding structure is stable', () => {
  assert.deepEqual(
    finding('critical', 'test', 'message', { evidence: 'e', suggestedAction: 'a' }),
    { severity: 'critical', code: 'test', message: 'message', evidence: 'e', suggested_action: 'a' },
  );
});

test('verify blocks when UFW is active but the SSH port is not allowed', () => {
  const findings = verifyFindings({
    sudo_nopasswd: true,
    sshd_config_ok: true,
    ufw_status: 'active',
    ufw_allows_ssh_port: false,
    fail2ban_active: true,
  }, 22);
  assert.equal(findings[0].severity, 'critical');
  assert.equal(findings[0].code, 'ufw_missing_ssh_allow');
});

test('verify blocks when firewalld is running but the SSH port is not allowed', () => {
  const findings = verifyFindings({
    sudo_nopasswd: true,
    sshd_config_ok: true,
    ufw_status: 'missing',
    firewalld_status: 'running',
    firewalld_allows_ssh_port: false,
    fail2ban_active: true,
  }, 22);
  const critical = findings.find((f) => f.severity === 'critical');
  assert.equal(critical.code, 'firewalld_missing_ssh_allow');
});

test('verify only warns when no firewall is active', () => {
  const findings = verifyFindings({
    sudo_nopasswd: true,
    sshd_config_ok: true,
    ufw_status: 'missing',
    firewalld_status: 'missing',
    fail2ban_active: true,
  }, 22);
  assert.ok(!findings.some((f) => f.severity === 'critical'));
  assert.equal(findings.find((f) => f.code === 'no_active_firewall').severity, 'warning');
});

test('probe template: placeholders are replaced and bash -n passes', () => {
  const script = buildProbeScript(22, { useSudo: true });
  assert.ok(!script.includes('__SSH_PORT__'));
  assert.ok(!script.includes('__FORCE_SUDO__'));
  // Interface-scoped UFW rules (ufw allow in on wg0 ...) must be recognized
  assert.ok(script.includes('on[[:space:]]+[^[:space:]]+'));
  // The probe is distro-agnostic: collect facts for multiple package managers
  for (const fact of ['has_apt_get', 'has_dnf', 'has_pacman']) assert.ok(script.includes(fact));
  const syntax = spawnSync('bash', ['-n'], { input: script, encoding: 'utf8' });
  assert.equal(syntax.status, 0, syntax.stderr);
});

test('probe rejects non-numeric ports to stay injection-safe', () => {
  assert.throws(() => buildProbeScript('22; rm -rf /'), /invalid SSH port/);
});

test('key=value parsing and fact normalization', () => {
  const facts = normalizeFacts(parseKeyValues('uid=1000\nsudo_nopasswd=0\nsshd_ports_csv=22,2222\nufw_status=active\nfail2ban_active=false\n'));
  assert.equal(facts.uid, 1000);
  assert.equal(facts.sudo_nopasswd, true);
  assert.deepEqual(facts.sshd_ports, ['22', '2222']);
  assert.equal(facts.ufw_status, 'active');
  assert.equal(facts.fail2ban_active, false);
});

test('all remote scripts pass bash -n syntax check', () => {
  const scriptsDir = new URL('../scripts/', import.meta.url).pathname;
  const scripts = ['probe.sh', 'bootstrap-linux.sh', 'lib/common.sh', 'lib/debian.sh', 'lib/rhel.sh', 'lib/arch.sh'].map((f) => scriptsDir + f);
  for (const script of scripts) {
    const result = spawnSync('bash', ['-n', script], { encoding: 'utf8' });
    assert.equal(result.status, 0, `${script}: ${result.stderr}`);
  }
});

test('payload keeps the stable JSON contract', () => {
  const payload = basePayload('preflight', { host: 'example.com', ok: true, facts: { uid: 1000 } });
  assert.equal(JSON.parse(JSON.stringify(payload)).schema_version, SCHEMA_VERSION);
  assert.equal(payload.stage, 'preflight');
  assert.equal(payload.host, 'example.com');
});
