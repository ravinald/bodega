from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class ReferencePrivacyTests(unittest.TestCase):
    def test_site_check_rejects_an_image_scalar_loads_from_the_description(self):
        repo = Path(subprocess.check_output(
            ['git', 'rev-parse', '--show-toplevel'], text=True).strip())
        with tempfile.TemporaryDirectory(prefix='f118-privacy-') as temporary:
            root = Path(temporary)
            for name in ('site', 'docs', 'api', 'assets'):
                shutil.copytree(repo / name, root / name)
            for name in ('README.md', 'SECURITY.md', 'CONTRIBUTING.md'):
                shutil.copy2(repo / name, root / name)
            spec = root / 'api/openapi.yaml'
            body = spec.read_text()
            self.assertIn('  description: |\n', body)
            spec.write_text(body.replace(
                '  description: |\n',
                '  description: |\n    ![privacy probe](https://example.invalid/f118-probe.png)\n\n', 1))
            run = subprocess.run(
                ['go', 'test', '-count=1', '-run', '^TestBuildPublishesAPIReference$', '.'],
                cwd=root / 'site', text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=120)
            self.assertNotEqual(
                run.returncode, 0,
                'the site check accepted an external image Scalar loads from info.description:\n' + run.stdout)


if __name__ == '__main__':
    unittest.main()
