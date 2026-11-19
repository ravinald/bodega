import re
import sys
import unittest
from pathlib import Path

report = Path(sys.argv.pop(1)).read_text()
rows = dict(re.findall(r"^- ([1-5]): (.*)$", report, re.M))
functions = {
    name
    for path in Path("internal/server").glob("*_test.go")
    for name in re.findall(r"^func ((?:Test|Benchmark)\w+)\(", path.read_text(), re.M)
}


class E30RequirementMap(unittest.TestCase):
    def test_each_requirement_names_branch_evidence(self):
        for requirement in range(1, 6):
            with self.subTest(requirement=requirement):
                row = rows.get(str(requirement), "")
                kind = "Benchmark" if requirement == 4 else "Test"
                names = re.findall(r"`(" + kind + r"\w+)`", row)
                self.assertTrue(names, f"R{requirement} names no {kind} function: {row}")
                for name in names:
                    self.assertIn(name, functions)


if __name__ == "__main__":
    unittest.main()
