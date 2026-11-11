import hashlib
import json
import re
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import deploy


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        (self.root / 'report.html').write_text('report')
        self.source = self.root / 'config.json'
        self.values = dict(site_url='https://packages.example.com', ssh_host='web-production',
                           remote_root='/srv/www/project', coverage_report='report.html')
        self.config = self.load()

    def load(self):
        self.source.write_text(json.dumps(self.values))
        return deploy.DeploymentConfig.load(self.source)

    def test_config_resolves_relative_report(self):
        self.assertEqual(self.config.coverage_report, self.root / 'report.html')

    def test_rejects_invalid_settings(self):
        for key, value in [('ssh_host', '-oProxyCommand=bad'), ('ssh_host', 'host; bad'),
                           ('remote_root', '/srv/../etc'), ('remote_root', '/'),
                           ('site_url', 'https://user:password@example.com'),
                           ('site_url', 'https://example.com/path'), ('unknown', 'value')]:
            with self.subTest(key=key, value=value):
                original = self.values.copy()
                self.values[key] = value
                with self.assertRaises(ValueError):
                    self.load()
                self.values = original

    def test_dry_run_executes_nothing(self):
        with patch('sys.argv', ['deploy.py', 'deploy', '--config', str(self.source), '--dry-run']), patch.object(deploy, 'run') as run:
            deploy.main()
            run.assert_not_called()

    def test_dirty_tree_refuses_before_build_or_upload(self):
        with patch.object(deploy, 'git', return_value=' M file'), patch.object(deploy, 'run') as run:
            with self.assertRaisesRegex(ValueError, 'clean working tree'):
                deploy.deploy(self.config)
            run.assert_not_called()

    def test_changed_revision_refuses_before_remote_access(self):
        with patch.object(deploy, 'clean_revision', side_effect=['a' * 40, 'b' * 40]), patch.object(deploy, 'export_coverage'), patch.object(deploy, 'render'), patch.object(deploy, 'remote') as remote:
            with self.assertRaisesRegex(ValueError, 'revision changed'):
                deploy.deploy(self.config)
            remote.assert_not_called()

    def exercise_upload(self, fail=False):
        def render(root, output, coverage, revision):
            output.mkdir()
            (output / 'index.html').write_text('ready')
        with patch.object(deploy, 'clean_revision', return_value='a' * 40), patch.object(deploy, 'export_coverage'), patch.object(deploy, 'render', side_effect=render), patch.object(deploy, 'remote') as remote, patch.object(deploy, 'upload') as upload:
            if fail:
                upload.side_effect = subprocess.CalledProcessError(1, 'rsync')
                with self.assertRaises(subprocess.CalledProcessError):
                    deploy.deploy(self.config)
            else:
                deploy.deploy(self.config)
            scripts = [call.args[1] for call in remote.call_args_list]
        for script in scripts:
            subprocess.run(['sh', '-n'], input=script, text=True, check=True)
        return scripts

    def test_failed_upload_does_not_activate_and_releases_lock(self):
        scripts = self.exercise_upload(fail=True)
        self.assertFalse(any('mv -Tf' in script for script in scripts))
        self.assertIn('rmdir', scripts[-1])

    def test_activation_is_atomic_and_leaves_feed_untouched(self):
        scripts = self.exercise_upload()
        self.assertTrue(any('mv -Tf' in script for script in scripts))
        self.assertFalse(any('/data/' in script for script in scripts))
        self.assertIn('rmdir', scripts[-1])

    def test_manifest_records_content_and_full_revision(self):
        output = self.root / 'artifact'
        output.mkdir()
        (output / 'index.html').write_text('ready')
        deploy.artifact_manifest(output, 'a' * 40)
        manifest = json.loads((output / 'deployment.json').read_text())
        self.assertEqual(manifest['sourceRevision'], 'a' * 40)
        self.assertEqual(manifest['sha256']['index.html'], hashlib.sha256(b'ready').hexdigest())

    def test_render_builds_for_the_root_with_the_given_commit(self):
        with patch.object(deploy, 'run') as run, patch.object(deploy, 'git', return_value='v1.2.3'):
            deploy.render(self.root, self.root / 'out', self.root / 'coverage.json', 'a' * 40)
        generate = run.call_args_list[-1].args[0]
        self.assertEqual(generate[generate.index('-base') + 1], '/')
        self.assertEqual(generate[generate.index('-commit') + 1], 'a' * 40)
        self.assertEqual(generate[generate.index('-version') + 1], 'v1.2.3')

    def test_coverage_page_renders_from_the_deployed_commit_after_the_feed(self):
        revision = 'c' * 40
        uploads = []
        rendered = []

        def render(root, output, coverage, rev):
            rendered.append(rev)
            output.mkdir()
            (output / 'coverage.html').write_text('page')

        def remote(config, script, *args, capture=False):
            return subprocess.CompletedProcess([], 0, stdout=json.dumps({'sourceRevision': revision}) if capture else '')

        def export(config, output):
            output.write_text('{}')

        with patch.object(deploy, 'export_coverage', side_effect=export), patch.object(deploy, 'remote', side_effect=remote), \
                patch.object(deploy, 'upload', side_effect=lambda c, src, dst: uploads.append(dst)), \
                patch.object(deploy, 'render', side_effect=render), patch.object(deploy, 'run') as run, \
                patch.object(deploy.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
            run.return_value = subprocess.CompletedProcess([], 0, stdout=b'')
            deploy.publish_coverage(self.config)
        self.assertEqual(rendered, [revision])
        self.assertTrue(uploads[0].endswith('.json'))
        self.assertTrue(uploads[1].endswith('.html'))

    def test_coverage_archive_carries_every_path_the_generator_reads(self):
        source = (deploy.SITE / 'main.go').read_text()
        read = set(re.findall(r'read\(repo, "([^"]+)"\)', source))
        self.assertIn('api/openapi.yaml', read)
        missing = sorted(p for p in read if p.split('/')[0] not in deploy.RENDERED)
        self.assertEqual(missing, [])

    def test_deployed_revision_refuses_a_manifest_without_a_full_commit(self):
        reply = subprocess.CompletedProcess([], 0, stdout=json.dumps({'sourceRevision': 'abc123'}))
        with patch.object(deploy, 'remote', return_value=reply):
            with self.assertRaisesRegex(ValueError, 'no full sourceRevision'):
                deploy.deployed_revision(self.config)
