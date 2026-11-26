import re
import sys
import unittest
from pathlib import Path

report = Path(sys.argv.pop(1)).read_text()
rows = dict(re.findall(r"^- ([1-5]): (.*)$", report, re.M))
functions = {
    name
    for path in Path("internal/server").glob("*_test.go")
    for name in re.findall(r"^func (Test\w+)\(", path.read_text(), re.M)
}


class B201RequirementMap(unittest.TestCase):
    def test_each_non_operator_requirement_names_existing_tests(self):
        for requirement in range(1, 5):
            with self.subTest(requirement=requirement):
                row = rows.get(str(requirement), "")
                names = re.findall(r"`(Test\w+)`", row)
                self.assertTrue(names, f"R{requirement} names no test function: {row}")
                for name in names:
                    self.assertIn(name, functions)


if __name__ == "__main__":
    unittest.main()
