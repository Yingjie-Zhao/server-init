import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';

const DEBIAN_LIB = new URL('../scripts/lib/debian.sh', import.meta.url).pathname;
const RHEL_LIB = new URL('../scripts/lib/rhel.sh', import.meta.url).pathname;
const COMMON_LIB = new URL('../scripts/lib/common.sh', import.meta.url).pathname;
const BOOTSTRAP = new URL('../scripts/bootstrap-linux.sh', import.meta.url).pathname;
const hasBash = spawnSync('bash', ['--version'], { encoding: 'utf8' }).status === 0;

// Stub commands via PATH prefixing and redirect paths via env vars, so bash behaviour is verified safely and locally
function makeTmp() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'server-init-test-'));
}

function writeStub(dir, name, content) {
  const p = path.join(dir, name);
  fs.writeFileSync(p, content);
  fs.chmodSync(p, 0o755);
}

function runLib(env, libCall, lib = DEBIAN_LIB) {
  return spawnSync('bash', ['-c', `source '${lib}'; ${libCall}`], {
    env: { ...process.env, ...env },
    encoding: 'utf8',
  });
}

test('configure_ufw allows the explicit SSH port before enable', { skip: !hasBash }, () => {
  const tmp = makeTmp();
  const binDir = path.join(tmp, 'bin');
  fs.mkdirSync(binDir);
  const logPath = path.join(tmp, 'ufw.log');
  writeStub(binDir, 'ufw', `#!/usr/bin/env bash
printf '%s\\n' "$*" >> "$SERVER_INIT_TEST_LOG"
if [[ "$1" == "status" ]]; then
  if [[ "\${2:-}" == "numbered" ]]; then
    printf '[ 1] 2222/tcp ALLOW IN Anywhere\\n'
  else
    printf 'Status: active\\n'
  fi
fi
exit 0
`);
  const result = runLib(
    { PATH: `${binDir}:${process.env.PATH}`, SERVER_INIT_TEST_LOG: logPath },
    'server_init_configure_ufw 2222',
  );
  assert.equal(result.status, 0, result.stderr);
  const calls = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean);
  for (const expected of ['default deny incoming', 'default allow outgoing', 'allow 2222/tcp', '--force enable']) {
    assert.ok(calls.includes(expected), `missing ufw call: ${expected}`);
  }
  assert.ok(calls.indexOf('allow 2222/tcp') < calls.indexOf('--force enable'), 'must allow SSH port before enable');
});

test('lockdown refuses to disable root SSH when the admin is not ready', { skip: !hasBash }, () => {
  const result = runLib({}, 'server_init_debian_lockdown missinguser');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /refusing to disable root SSH/);
});

test('configure_swap creates the swapfile and writes fstab and sysctl', { skip: !hasBash }, () => {
  const tmp = makeTmp();
  const binDir = path.join(tmp, 'bin');
  fs.mkdirSync(binDir);
  const logPath = path.join(tmp, 'commands.log');
  const swapFile = path.join(tmp, 'swapfile');
  const fstab = path.join(tmp, 'fstab');
  const sysctlFile = path.join(tmp, 'sysctl.d', '99-server-init-swap.conf');
  const meminfo = path.join(tmp, 'meminfo');
  fs.writeFileSync(meminfo, 'MemTotal:        524288 kB\nSwapTotal:            0 kB\n');

  writeStub(binDir, 'df', `#!/usr/bin/env bash
printf 'Filesystem 1M-blocks Used Available Use%% Mounted on\\n'
printf '/dev/test 20000 1000 19000 5%% /\\n'
`);
  for (const name of ['fallocate', 'mkswap', 'swapon', 'sysctl']) {
    writeStub(binDir, name, `#!/usr/bin/env bash
printf '${name} %s\\n' "$*" >> "$SERVER_INIT_TEST_LOG"
${name === 'fallocate' ? 'target="${@: -1}"\n: > "$target"' : ''}
`);
  }

  const result = runLib(
    {
      PATH: `${binDir}:${process.env.PATH}`,
      SERVER_INIT_TEST_LOG: logPath,
      SERVER_INIT_SWAP_FILE: swapFile,
      SERVER_INIT_FSTAB: fstab,
      SERVER_INIT_SYSCTL_SWAP_FILE: sysctlFile,
      SERVER_INIT_MEMINFO: meminfo,
    },
    'server_init_configure_swap 2048',
  );
  assert.equal(result.status, 0, result.stderr);
  assert.ok(fs.existsSync(swapFile));
  assert.equal(fs.statSync(swapFile).mode & 0o777, 0o600);
  assert.match(fs.readFileSync(fstab, 'utf8'), new RegExp(`${swapFile} none swap sw 0 0`));
  assert.match(fs.readFileSync(sysctlFile, 'utf8'), /vm\.swappiness=10/);
  const calls = fs.readFileSync(logPath, 'utf8');
  assert.match(calls, new RegExp(`fallocate -l 2048M ${swapFile}`));
  assert.match(calls, new RegExp(`mkswap ${swapFile}`));
  assert.match(calls, new RegExp(`swapon ${swapFile}`));
  assert.match(calls, /sysctl -w vm\.swappiness=10/);
});

test('backend dispatch: os-release maps to the right distro backend', { skip: !hasBash }, () => {
  const cases = [
    ['debian', '', 'debian'], ['ubuntu', '', 'debian'],
    ['rhel', '', 'rhel'], ['centos', '', 'rhel'], ['rocky', '', 'rhel'],
    ['almalinux', '', 'rhel'], ['fedora', '', 'rhel'],
    ['arch', '', 'arch'],
    ['unknown', 'rhel centos', 'rhel'],
    ['unknown', 'debian', 'debian'],
    ['unknown', 'arch', 'arch'],
  ];
  for (const [id, idLike, expected] of cases) {
    const result = spawnSync('bash', ['-c', `source '${BOOTSTRAP}'; server_init_select_backend '${id}' '${idLike}'`], { encoding: 'utf8' });
    assert.equal(result.status, 0, `${id}/${idLike}`);
    assert.equal(result.stdout.trim(), expected, `${id}/${idLike}`);
  }
  for (const [id, idLike] of [['alpine', ''], ['', ''], ['gentoo', '']]) {
    const result = spawnSync('bash', ['-c', `source '${BOOTSTRAP}'; server_init_select_backend '${id}' '${idLike}'`], { encoding: 'utf8' });
    assert.notEqual(result.status, 0, `${id} should be unsupported`);
  }
});

test('run_prepare log line does not crash on unbound OS_ID after backend detection', { skip: !hasBash }, () => {
  // Regression: detect_backend runs in a command-substitution subshell, so OS_ID must be loaded
  // in the current shell beforehand; otherwise the log line's ${PRETTY_NAME:-$OS_ID $OS_VERSION_ID}
  // hits an unbound variable under set -u
  const tmp = makeTmp();
  const binDir = path.join(tmp, 'bin');
  fs.mkdirSync(binDir);
  writeStub(binDir, 'systemctl', '#!/usr/bin/env bash\nexit 0\n');
  const osRelease = path.join(tmp, 'os-release');
  fs.writeFileSync(osRelease, 'ID=debian\nPRETTY_NAME="Test Debian"\n');
  const script = [
    `source '${BOOTSTRAP}'`,
    // Truncate the destructive tail of prepare; only verify up to the log line and backend dispatch
    'load_backend() { :; }',
    'server_init_log() { printf "LOG %s\\n" "$*"; }',
    'server_init_debian_prepare() { printf "PREPARE %s\\n" "$1"; }',
    'run_prepare --admin-user deer --admin-pubkey KEY --ssh-port 22',
  ].join('; ');
  const result = spawnSync('bash', ['-c', script], {
    env: { ...process.env, PATH: `${binDir}:${process.env.PATH}`, SERVER_INIT_OS_RELEASE: osRelease },
    encoding: 'utf8',
  });
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /LOG detected supported distribution: Test Debian \(backend: debian\)/);
  assert.match(result.stdout, /PREPARE deer/);
});

test('configure_firewalld enables, allows, reloads and verifies in order', { skip: !hasBash }, () => {
  const tmp = makeTmp();
  const binDir = path.join(tmp, 'bin');
  fs.mkdirSync(binDir);
  const logPath = path.join(tmp, 'calls.log');
  writeStub(binDir, 'systemctl', `#!/usr/bin/env bash
printf 'systemctl %s\\n' "$*" >> "$SERVER_INIT_TEST_LOG"
exit 0
`);
  writeStub(binDir, 'firewall-cmd', `#!/usr/bin/env bash
printf 'firewall-cmd %s\\n' "$*" >> "$SERVER_INIT_TEST_LOG"
exit 0
`);
  const result = runLib(
    { PATH: `${binDir}:${process.env.PATH}`, SERVER_INIT_TEST_LOG: logPath },
    'server_init_configure_firewalld 2222',
    RHEL_LIB,
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /component=firewalld status=running ssh_port=2222 allows_ssh_port=true/);
  const calls = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean);
  const enableIdx = calls.indexOf('systemctl enable --now firewalld');
  const addIdx = calls.indexOf('firewall-cmd --permanent --add-port=2222/tcp');
  const reloadIdx = calls.indexOf('firewall-cmd --reload');
  assert.ok(enableIdx > -1 && addIdx > -1 && reloadIdx > -1, calls.join(' | '));
  assert.ok(enableIdx < addIdx && addIdx < reloadIdx, 'must enable, add port, then reload');
});

test('rhel package install: prepare continues when htop is unavailable (EPEL not enabled)', { skip: !hasBash }, () => {
  // Regression: htop lives in EPEL on the RHEL 9 family and was previously installed in the same
  // dnf batch as required packages; the atomic failure crashed the whole prepare.
  // htop is a convenience, so it must be skipped rather than abort
  const tmp = makeTmp();
  const binDir = path.join(tmp, 'bin');
  fs.mkdirSync(binDir);
  const logPath = path.join(tmp, 'dnf.log');
  writeStub(binDir, 'dnf', `#!/usr/bin/env bash
printf 'dnf %s\\n' "$*" >> "$SERVER_INIT_TEST_LOG"
case " $* " in
  *' htop '*) exit 1 ;;
esac
exit 0
`);
  const result = runLib(
    { PATH: `${binDir}:${process.env.PATH}`, SERVER_INIT_TEST_LOG: logPath },
    'server_init_install_packages_rhel',
    RHEL_LIB,
  );
  assert.equal(result.status, 0, result.stderr);
  assert.match(result.stdout, /htop unavailable; skipping/);
  const strict = fs.readFileSync(logPath, 'utf8').split('\n').find((l) => l.includes('firewalld'));
  assert.ok(strict && !strict.includes('htop'), `htop must not be in the required-package batch: ${strict}`);
});

test('configure_dnf_automatic: edits in place on dnf4, creates a minimal config when the file is missing on dnf5', { skip: !hasBash }, () => {
  // Regression: on Fedora 44 (dnf5) automatic.conf is %ghost, so sed failed with No such file or directory
  const tmp = makeTmp();
  const binDir = path.join(tmp, 'bin');
  fs.mkdirSync(binDir);
  const logPath = path.join(tmp, 'calls.log');
  writeStub(binDir, 'systemctl', `#!/usr/bin/env bash
printf 'systemctl %s\\n' "$*" >> "$SERVER_INIT_TEST_LOG"
exit 0
`);
  const env = { PATH: `${binDir}:${process.env.PATH}`, SERVER_INIT_TEST_LOG: logPath };

  const dnf4Conf = path.join(tmp, 'automatic-dnf4.conf');
  fs.writeFileSync(dnf4Conf, '[commands]\napply_updates = no\n');
  const dnf4 = runLib(
    { ...env, SERVER_INIT_DNF_AUTOMATIC_CONF: dnf4Conf },
    'server_init_configure_dnf_automatic',
    RHEL_LIB,
  );
  assert.equal(dnf4.status, 0, dnf4.stderr);
  assert.match(fs.readFileSync(dnf4Conf, 'utf8'), /apply_updates = yes/);

  const dnf5Conf = path.join(tmp, 'automatic-dnf5.conf');
  const dnf5 = runLib(
    { ...env, SERVER_INIT_DNF_AUTOMATIC_CONF: dnf5Conf },
    'server_init_configure_dnf_automatic',
    RHEL_LIB,
  );
  assert.equal(dnf5.status, 0, dnf5.stderr);
  assert.match(fs.readFileSync(dnf5Conf, 'utf8'), /^\[commands\]\napply_updates = yes$/m);
});

test('configure_swap sets NOCOW on the empty file before allocation on btrfs', { skip: !hasBash }, () => {
  // Regression: on Fedora (btrfs root) a fallocate'd swapfile is CoW and swapon fails with Invalid argument;
  // chattr +C must happen before any data is written to the file
  const tmp = makeTmp();
  const binDir = path.join(tmp, 'bin');
  fs.mkdirSync(binDir);
  const logPath = path.join(tmp, 'commands.log');
  const swapFile = path.join(tmp, 'swapfile');
  const fstab = path.join(tmp, 'fstab');
  const sysctlFile = path.join(tmp, 'sysctl.d', '99-server-init-swap.conf');
  const meminfo = path.join(tmp, 'meminfo');
  fs.writeFileSync(meminfo, 'MemTotal:        524288 kB\nSwapTotal:            0 kB\n');

  writeStub(binDir, 'stat', `#!/usr/bin/env bash
if [[ "\${1:-}" == "-f" ]]; then printf 'btrfs\\n'; exit 0; fi
exec /usr/bin/stat "$@"
`);
  writeStub(binDir, 'df', `#!/usr/bin/env bash
printf 'Filesystem 1M-blocks Used Available Use%% Mounted on\\n'
printf '/dev/test 20000 1000 19000 5%% /\\n'
`);
  for (const name of ['chattr', 'fallocate', 'mkswap', 'swapon', 'sysctl']) {
    writeStub(binDir, name, `#!/usr/bin/env bash
printf '${name} %s\\n' "$*" >> "$SERVER_INIT_TEST_LOG"
${name === 'fallocate' ? 'target="${@: -1}"\n: > "$target"' : ''}
`);
  }

  const result = runLib(
    {
      PATH: `${binDir}:${process.env.PATH}`,
      SERVER_INIT_TEST_LOG: logPath,
      SERVER_INIT_SWAP_FILE: swapFile,
      SERVER_INIT_FSTAB: fstab,
      SERVER_INIT_SYSCTL_SWAP_FILE: sysctlFile,
      SERVER_INIT_MEMINFO: meminfo,
    },
    'server_init_configure_swap 2048',
    COMMON_LIB,
  );
  assert.equal(result.status, 0, result.stderr);
  const calls = fs.readFileSync(logPath, 'utf8').split('\n').filter(Boolean);
  const chattrIdx = calls.indexOf(`chattr +C ${swapFile}`);
  const fallocateIdx = calls.findIndex((l) => l.startsWith('fallocate '));
  assert.ok(chattrIdx > -1, `missing chattr +C: ${calls.join(' | ')}`);
  assert.ok(chattrIdx < fallocateIdx, 'chattr +C must run before fallocate');
});

test('configure_swap rejects invalid sizes', { skip: !hasBash }, () => {
  const result = runLib({}, 'server_init_configure_swap nope');
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /invalid swap size MiB/);
});

test('configure_swap refuses to overwrite an existing path not managed by server-init', { skip: !hasBash }, () => {
  const tmp = makeTmp();
  const swapFile = path.join(tmp, 'swapfile');
  const fstab = path.join(tmp, 'fstab');
  const meminfo = path.join(tmp, 'meminfo');
  fs.writeFileSync(swapFile, 'not managed by server-init');
  fs.writeFileSync(fstab, '');
  fs.writeFileSync(meminfo, 'SwapTotal:            0 kB\n');
  const result = runLib(
    { SERVER_INIT_SWAP_FILE: swapFile, SERVER_INIT_FSTAB: fstab, SERVER_INIT_MEMINFO: meminfo },
    'server_init_configure_swap 2048',
  );
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /existing non-server-init swap path exists/);
});
