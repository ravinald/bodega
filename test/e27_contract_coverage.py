import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


class E27ContractCoverage(unittest.TestCase):
    def test_required_changes_have_regression_guards(self):
        root = Path.cwd()
        selection = "^(TestEmitSignsWhatTheRowSaysAndVerifies|TestEmitCarriesTheUpstreamProvenanceOfTheRow|TestAttestVerifyPreE27Envelope|TestE27.*)$"
        cases = [
            ("R1", "internal/attest/attest.go", "revision"),
            ("R9", "internal/audit/admission.go", "audit vocabulary"),
            ("R14", "cmd/bodega/cmd_attest.go", "help"),
            ("R15", "docs/design.md", "restore"),
            ("R16", "docs/threat-model.md", "restore"),
            ("R17", "docs/usage.md", "restore"),
            ("R19", "docs/slsa.md", "restore"),
        ]
        with tempfile.TemporaryDirectory(prefix="e27-coverage-") as temporary:
            checkout = Path(temporary)
            archive = subprocess.check_output(["git", "archive", "HEAD"], cwd=root)
            with tarfile.open(fileobj=io.BytesIO(archive)) as files:
                files.extractall(checkout, filter="data")
            baseline = subprocess.run(["go", "test", "-count=1", "-timeout", "2m", "-run", selection,
                                       "./internal/attest", "./cmd/bodega"], cwd=checkout,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
            self.assertEqual(baseline.returncode, 0, "unmodified baseline failed:\n" + baseline.stdout)
            for requirement, name, mutation in cases:
                with self.subTest(requirement=requirement):
                    target = checkout / name
                    original = target.read_text()
                    if mutation == "revision":
                        changed = original.replace('const DraftRevision = "https://github.com/', 'const DraftRevision = "https://wrong.example/')
                    elif mutation == "audit vocabulary":
                        changed = original.replace('ProvenanceUnknown = "unknown"', 'ProvenanceUnknown = "unknown-regression"')
                    else:
                        previous = subprocess.check_output(["git", "show", "origin/main:" + name], cwd=root, text=True)
                        if mutation == "help":
                            begin = "It then prints upstream-provenance and publisher-signature:"
                            end = "The trusted key IDs come from --key"
                            old = previous[previous.index(begin):previous.index(end)]
                            changed = original[:original.index(begin)] + old + original[original.index(end):]
                        else:
                            changed = previous
                    self.assertNotEqual(original, changed, "mutation was not applied")
                    target.write_text(changed)
                    try:
                        result = subprocess.run(["go", "test", "-count=1", "-timeout", "2m", "-run", selection,
                                                 "./internal/attest", "./cmd/bodega"], cwd=checkout,
                                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=180)
                        print(requirement + " mutated test output:\n" + result.stdout, flush=True)
                        self.assertTrue(result.returncode != 0 and "--- FAIL:" in result.stdout,
                                        requirement + " mutation survived: mapped tests passed with the requirement removed")
                    finally:
                        target.write_text(original)


if __name__ == "__main__":
    unittest.main()
