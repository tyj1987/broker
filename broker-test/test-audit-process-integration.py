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

    def test_incomplete_work_cannot_be_reported_successful(self):
        with self.assertRaises(RuntimeError):
            module.require(False, 'incomplete integration')

if __name__ == '__main__':
    unittest.main()
