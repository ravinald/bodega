import re
import sys
import unittest
from pathlib import Path

report = Path(sys.argv.pop(1)).read_text()
rows = dict(re.findall(r"^- ([1-6]): (.*)$", report, re.M))
functions = {
    name
    for base in ("internal/config", "internal/manifest", "internal/server", "cmd/bodega")
    for path in Path(base).glob("*_test.go")
    for name in re.findall(r"^func (Test\w+)\(", path.read_text(), re.M)
}


class RequirementMap(unittest.TestCase):
    def test_each_requirement_names_existing_tests(self):
        for requirement in range(1, 7):
            with self.subTest(requirement=requirement):
                row = rows.get(str(requirement), "")
                names = re.findall(r"`(Test\w+)`", row)
                self.assertTrue(names, f"R{requirement} names no test function: {row}")
                for name in names:
                    self.assertIn(name, functions)


if __name__ == "__main__":
    unittest.main()
