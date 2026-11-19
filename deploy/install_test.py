import os
import pathlib
import subprocess
import tempfile
import unittest


class InstallRollbackTest(unittest.TestCase):
    def run_install(self, failure, existing=False, cleanup_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            script = (pathlib.Path(__file__).parent / 'install.sh').read_text()
            # Run an instrumented copy in a private tree, never against system paths.
            for path in ('/usr/local/bin', '/etc/systemd/system', '/usr/lib/systemd/system',
                         '/lib/systemd/system', '/etc/vpn-vless', '/var/lib/vpn-vless',
                         '/run/systemd/system', '/etc/os-release'):
                script = script.replace(path, (root / path.lstrip('/')).as_posix())
            script = script.replace('$(id -u)', '0').replace('$(uname -s)', 'Linux')
            (root / 'install.sh').write_text(script, newline='\n')
            for path in ('usr/local/bin', 'etc/systemd/system', 'run/systemd/system',
                         'var/lib', 'deploy', 'cmd/vpnctl', 'stubs'):
                (root / path).mkdir(parents=True, exist_ok=True)
            (root / 'etc/os-release').write_text('ID=debian\n')
            (root / 'go.mod').write_text('module test\n')
            (root / 'deploy/vpn-vless.service').write_text('[Install]\nWantedBy=multi-user.target\n')
            if existing:
                (root / 'usr/local/bin/xray').write_text('foreign')
            stub = '''#!/bin/sh
name=${0##*/}
case "$name" in
 go) case "$1" in version) printf '%s\\n' 'go version go1.26.0 linux/amd64';; install) : > "$GOBIN/main";; build) : > "$3";; esac ;;
 getent) [ -f "$TEST_ROOT/$1" ] && /usr/bin/cat "$TEST_ROOT/$1" ;;
 groupadd) printf '%s\\n' 'vpn-vless:x:999:' > "$TEST_ROOT/group" ;;
 useradd) printf '%s\\n' 'vpn-vless:x:999:999::/nonexistent:/usr/sbin/nologin' > "$TEST_ROOT/passwd" ;;
 groupdel|userdel) [ "$CLEANUP_FAIL" != "$name" ] || exit 1; case "$name" in groupdel) rm -f "$TEST_ROOT/group";; userdel) rm -f "$TEST_ROOT/passwd";; esac ;;
 chown) : ;;
 install) [ "$FAIL_AT" != install ] || exit 1; while [ "$#" -gt 2 ]; do shift; done; cp "$1" "$2" ;;
 systemctl) printf '%s\\n' "$1" >> "$TEST_ROOT/systemctl.log"; case "$1" in
  list-unit-files) : ;;
  daemon-reload) [ "$FAIL_AT" != reload ] || exit 1 ;;
  enable) mkdir -p "$TEST_ROOT/etc/systemd/system/multi-user.target.wants"; ln -s ../vpn-vless.service "$TEST_ROOT/etc/systemd/system/multi-user.target.wants/vpn-vless.service"; if [ "$FAIL_AT" = replace ]; then rm "$TEST_ROOT/usr/local/bin/xray"; printf foreign > "$TEST_ROOT/usr/local/bin/xray"; exit 1; fi; [ "$FAIL_AT" != enable ] || exit 1 ;;
  disable) [ "$CLEANUP_FAIL" != disable ] || exit 1; rm -f "$TEST_ROOT/etc/systemd/system/multi-user.target.wants/vpn-vless.service" ;;
 esac ;;
esac
'''
            for name in ('go', 'getent', 'groupadd', 'useradd', 'groupdel', 'userdel', 'chown', 'install', 'systemctl'):
                path = root / 'stubs' / name
                path.write_text(stub, newline='\n')
                path.chmod(0o755)
            env = dict(os.environ, PATH=str(root / 'stubs') + os.pathsep + os.environ['PATH'],
                       TEST_ROOT=str(root).replace('\\', '/'), FAIL_AT=failure,
                       CLEANUP_FAIL='disable' if cleanup_failure else '')
            result = subprocess.run(['sh', str(root / 'install.sh')], cwd=root, env=env,
                                    text=True, capture_output=True)
            log = (root / 'systemctl.log').read_text() if (root / 'systemctl.log').exists() else ''
            state = {p: (root / p).exists() for p in ('usr/local/bin/xray', 'usr/local/bin/vpnctl',
                     'etc/systemd/system/vpn-vless.service', 'etc/vpn-vless', 'var/lib/vpn-vless',
                     'passwd', 'group', 'etc/systemd/system/multi-user.target.wants/vpn-vless.service')}
            return result, log, state

    def test_rollbacks(self):
        for failure in ('install', 'reload', 'enable'):
            with self.subTest(failure=failure):
                result, log, state = self.run_install(failure)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertFalse(any(state.values()), (state, result.stderr))
                self.assertEqual('disable' in log, failure == 'enable')

    def test_preexisting_target(self):
        result, log, state = self.run_install('', existing=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(state['usr/local/bin/xray'])
        self.assertFalse(any(value for key, value in state.items() if key != 'usr/local/bin/xray'))
        self.assertNotIn('disable', log)

    def test_replaced_target_is_preserved(self):
        result, log, state = self.run_install('replace')
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(state['usr/local/bin/xray'])
        self.assertIn('rollback skipped replaced target', result.stderr)
        self.assertIn('disable', log)

    def test_cleanup_failure_reported(self):
        result, log, state = self.run_install('enable', cleanup_failure=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('rollback failed: systemctl disable', result.stderr)

    def test_success(self):
        result, log, state = self.run_install('')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(all(state.values()), state)
        self.assertNotIn('disable', log)


if __name__ == '__main__':
    unittest.main()
