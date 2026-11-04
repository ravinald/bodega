import io
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest


class F107ContractCoverage(unittest.TestCase):
    def test_required_changes_have_regression_guards(self):
        root = Path.cwd()
        selection = "^(TestPypi.*|TestUnpinnedPypi.*|TestAdmitRecordsVerifiedPypiProvenance|TestPolicyProvenanceSetAndList|TestDoctorReportsProvenanceSilencedEverywhere|TestVerifyBundleBuilderSource|TestUncoveredEcosystemsRecordWhy|TestReview.*|TestF107.*)$"
        cases = [
            ("R15 usage", "docs/usage.md", "restore"),
            ("R15 threat model", "docs/threat-model.md", "restore"),
            ("R18", "docs/slsa.md", "restore"),
            ("R16 second version", "internal/provenance/checker.go", "skip later versions"),
        ]
        with tempfile.TemporaryDirectory(prefix="f107-coverage-") as temporary:
            checkout = Path(temporary)
            archive = subprocess.check_output(["git", "archive", "HEAD"], cwd=root)
            with tarfile.open(fileobj=io.BytesIO(archive)) as files:
                files.extractall(checkout, filter="data")
            command = ["go", "test", "-count=1", "-timeout", "2m", "-run", selection,
                       "./internal/provenance", "./internal/admit", "./cmd/bodega"]
            def run_tests():
                return subprocess.run(command, cwd=checkout, stdout=subprocess.PIPE,
                                      stderr=subprocess.STDOUT, text=True, timeout=180)
            baseline = run_tests()
            self.assertEqual(baseline.returncode, 0, "unmodified baseline failed:\n" + baseline.stdout)
            for requirement, name, mutation in cases:
                with self.subTest(requirement=requirement):
                    target = checkout / name
                    original = target.read_text()
                    if mutation == "skip later versions":
                        condition = "if ev.Outcome == audit.ProvenanceVerified || (ev.Outcome == audit.ProvenanceUnavailable && pm.Type == manifest.TypeNpm) {"
                        changed = original.replace(condition,
                            'if (pm.Type != manifest.TypePypi || ve.Version == "4.0.0") && (ev.Outcome == audit.ProvenanceVerified || (ev.Outcome == audit.ProvenanceUnavailable && pm.Type == manifest.TypeNpm)) {')
                    else:
                        changed = subprocess.check_output(["git", "show", "origin/main:" + name], cwd=root, text=True)
                    self.assertNotEqual(original, changed, "mutation was not applied")
                    target.write_text(changed)
                    try:
                        result = run_tests()
                        print(requirement + " mutated test output:\n" + result.stdout, flush=True)
                        self.assertTrue(result.returncode != 0 and "--- FAIL:" in result.stdout,
                                        requirement + " mutation survived: mapped tests passed with the requirement removed")
                    finally:
                        target.write_text(original)


if __name__ == "__main__":
    unittest.main()
