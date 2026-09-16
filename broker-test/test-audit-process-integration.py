import importlib.util
import os
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('integration', Path(__file__).with_name('audit-process-integration.py'))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)

class GuardTests(unittest.TestCase):
    def setUp(self):
        self.env = {'GITHUB_ACTIONS': 'true', 'RUNNER_ENVIRONMENT': 'github-hosted',
                    'GITHUB_REPOSITORY': 'tyj1987/broker', 'GITHUB_EVENT_NAME': 'push',
                    'RUNNER_OS': 'Linux', 'GITHUB_REF': 'refs/heads/chatgpt/test', 'GITHUB_SHA': 'a'*40}

    def test_environment_refusal_precedes_commands(self):
        for key in self.env:
            env = dict(self.env, **{key: 'invalid'})
            with self.subTest(key=key), patch.dict(os.environ, env, clear=True), patch.object(module, 'run') as run, patch.object(os, 'geteuid', return_value=0):
                with self.assertRaises(RuntimeError):
                    module.guard(Path('/workspace'), Path('/node'))
                run.assert_not_called()

    def test_nonroot_refusal_precedes_commands(self):
        with patch.dict(os.environ, self.env, clear=True), patch.object(os, 'geteuid', return_value=1234), patch.object(module, 'run') as run:
            with self.assertRaises(RuntimeError):
                module.guard(Path('/workspace'), Path('/node'))
            run.assert_not_called()

    def test_existing_paths_are_never_removed(self):
        with patch.dict(os.environ, self.env, clear=True), patch.object(os, 'geteuid', return_value=0), \
             patch.object(Path, 'read_text', return_value='systemd'), patch.object(Path, 'is_dir', return_value=True), \
             patch.object(Path, 'is_file', return_value=True), patch.object(Path, 'is_symlink', return_value=False), \
             patch.object(Path, 'exists', return_value=True), patch.object(module, 'run') as run, patch.object(module.shutil, 'rmtree') as remove:
            with self.assertRaisesRegex(RuntimeError, 'existing host state'):
                module.integration(Path('/workspace'), Path('/node'), Path('/output'))
            run.assert_not_called()
            remove.assert_not_called()

    def test_command_failure_does_not_reflect_arguments_or_output(self):
        result = subprocess.CompletedProcess([], 4, 'private-output', 'private-error')
        with patch.object(subprocess, 'run', return_value=result):
            with self.assertRaisesRegex(RuntimeError, '^systemctl show exited 4$'):
                module.run('systemctl', 'show', 'private-argument')
            self.assertIs(module.run('systemctl', 'show', check=False), result)
            with self.assertRaisesRegex(RuntimeError, '^command operation exited 4$'):
                module.run('/private/path', 'private-argument')

    def test_unit_diagnostics_only_include_allowlisted_properties_and_codes(self):
        status = subprocess.CompletedProcess([], 0, 'ActiveState=failed\nEnvironment=PRIVATE\nExecMainStatus=78\n', '')
        journal = subprocess.CompletedProcess([], 0, 'private-journal\naudit_exporter_failed=identity_or_release_invalid\n', '')
        from io import StringIO
        output = StringIO()
        with patch.object(module, 'run', side_effect=[status, journal]*len(module.UNITS)), patch.object(module.sys, 'stderr', output):
            module.safe_unit_diagnostics()
        self.assertIn('ActiveState=failed', output.getvalue())
        self.assertIn('identity_or_release_invalid', output.getvalue())
        self.assertNotIn('PRIVATE', output.getvalue())
        self.assertNotIn('private-journal', output.getvalue())

    def test_fixture_parent_and_umask_restore_on_success_and_failure(self):
        import tempfile
        from types import SimpleNamespace
        for fail in [False, True]:
            with tempfile.TemporaryDirectory() as name:
                path = Path(name)
                path.chmod(0o777)
                owner = SimpleNamespace(st_uid=0, st_mode=0o40777)
                before = os.umask(0o022)
                os.umask(before)
                try:
                    with patch.object(Path, 'lstat', return_value=owner):
                        with module.protected_fixture_parent(path):
                            self.assertEqual(os.stat(path).st_mode & 0o777, 0o755)
                            mask = os.umask(0o022)
                            self.assertEqual(mask, 0o022)
                            (path / 'child').mkdir()
                            self.assertEqual(os.stat(path / 'child').st_mode & 0o777, 0o755)
                            if fail:
                                raise ValueError('synthetic failure')
                except ValueError:
                    self.assertTrue(fail)
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o777)
                after = os.umask(before)
                self.assertEqual(after, before)

    def test_untrusted_fixture_parent_is_never_modified(self):
        from types import SimpleNamespace
        for mode, uid in [(0o40777, 1234), (0o120777, 0), (0o100777, 0)]:
            with patch.object(Path, 'lstat', return_value=SimpleNamespace(st_uid=uid, st_mode=mode)), patch.object(Path, 'chmod') as chmod:
                with self.assertRaises(RuntimeError):
                    with module.protected_fixture_parent(Path('/unused')):
                        self.fail('untrusted parent entered')
                chmod.assert_not_called()

    def test_every_new_directory_is_normalized_despite_permissive_inheritance(self):
        import tempfile
        with tempfile.TemporaryDirectory() as name:
            parent = Path(name)
            original = Path.mkdir
            def permissive(path):
                original(path)
                path.chmod(0o777)
            with patch.object(Path, 'mkdir', permissive), patch.object(module, 'run') as acl:
                for path in [parent / 'fixture', parent / 'fixture/releases', parent / 'fixture/releases/sha']:
                    module.make_fixture_directory(path)
                    self.assertEqual(path.stat().st_mode & 0o777, 0o755)
                    acl.assert_called_with('setfacl', '--remove-all', '--remove-default', path)
                self.assertEqual(acl.call_count, 3)

    def test_existing_directory_is_not_chmodded_or_given_acl_changes(self):
        import tempfile
        with tempfile.TemporaryDirectory() as name:
            path = Path(name)
            path.chmod(0o777)
            with patch.object(module, 'run') as acl:
                with self.assertRaises(FileExistsError):
                    module.make_fixture_directory(path)
                acl.assert_not_called()
            self.assertEqual(path.stat().st_mode & 0o777, 0o777)

    def test_acl_normalization_failure_cannot_be_ignored(self):
        import tempfile
        with tempfile.TemporaryDirectory() as name, patch.object(module, 'run', side_effect=RuntimeError('ACL failed')):
            with self.assertRaisesRegex(RuntimeError, 'ACL failed'):
                module.make_fixture_directory(Path(name) / 'new')

    def test_incomplete_work_cannot_be_reported_successful(self):
        with self.assertRaises(RuntimeError):
            module.require(False, 'incomplete integration')

class LifecycleTests(unittest.TestCase):
    def test_systemctl_watchdog_representation(self):
        for value, expected in [('2min 15s', 135000000), ('135s', 135000000),
                                ('1h 1min 15s', 3675000000), ('1ms 1us', 1001)]:
            self.assertEqual(module.duration_microseconds(value), expected)
        for value in ['', 'infinity', '135', '-1s', '1.5s', '10unknown']:
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                module.duration_microseconds(value)

    def test_restart_requires_a_new_running_pid_and_restart_counter(self):
        valid = {'ActiveState': 'active', 'MainPID': '124', 'NRestarts': '2'}
        with patch.object(module, 'property_of', side_effect=lambda unit, prop: valid[prop]):
            module.wait_for_restarted_process('fixture', 123, 1)
        for change in [{'ActiveState': 'activating'}, {'MainPID': '0'},
                       {'MainPID': '123'}, {'NRestarts': '1'}]:
            values = dict(valid, **change)
            with self.subTest(change=change), patch.object(module, 'property_of', side_effect=lambda unit, prop: values[prop]), \
                 patch.object(module.time, 'monotonic', side_effect=[0, 0, 21]), patch.object(module.time, 'sleep'):
                with self.assertRaisesRegex(RuntimeError, 'restart was not verified'):
                    module.wait_for_restarted_process('fixture', 123, 1)

    def test_failure_requires_the_verifiers_exit_code_not_just_inactivity(self):
        valid = {'ActiveState': 'activating', 'ExecMainCode': '1', 'ExecMainStatus': '69'}
        with patch.object(module, 'property_of', side_effect=lambda unit, prop: valid[prop]):
            module.wait_for_failed_verification('fixture')
        for change in [{'ActiveState': 'active'}, {'ExecMainCode': '2'},
                       {'ExecMainStatus': '0'}, {'ExecMainStatus': '9'}, {'ExecMainStatus': '78'}]:
            values = dict(valid, **change)
            with self.subTest(change=change), patch.object(module, 'property_of', side_effect=lambda unit, prop: values[prop]), \
                 patch.object(module.time, 'monotonic', side_effect=[0, 0, 81]), patch.object(module.time, 'sleep'):
                with self.assertRaisesRegex(RuntimeError, 'did not report failure'):
                    module.wait_for_failed_verification('fixture')

if __name__ == '__main__':
    unittest.main()
