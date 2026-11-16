import copy
import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('coverage_export', Path(__file__).with_name('coverage.py'))
coverage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(coverage)

FEED = {
    'schemaVersion': 1, 'revision': 'abc1234', 'evaluatedAt': '2026-01-01T00:00:00Z',
    'summary': '1 package types. Ready: apt.',
    'packages': [{
        'id': 'apt', 'verdict': 'Ready', 'reason': 'green on 2 test platforms, coverage 90%', 'coverage': '90%',
        'lastTested': '2026-01-01', 'checks': {'passed': 10, 'notPassing': 0},
        'features': [{'label': 'Proxy', 'description': 'Pulls through', 'value': 'yes', 'evidence': '', 'state': ''}],
        'runs': [{'text': 'Debian 13 · 10/10', 'title': 'Checked 2026-01-01 against build abc1234', 'class': 'run ok'}],
    }],
    'scoring': {'verdictRules': [{'verdict': 'Ready', 'rule': 'every suite green'}],
                'featureWeights': [{'weight': 3, 'features': ['Proxy']}],
                'featureValues': [{'value': 'yes', 'counts': 'full weight'}]},
}


class CoverageExportTests(unittest.TestCase):
    def export(self, change=None):
        feed = copy.deepcopy(FEED)
        if change:
            change(feed)
        return coverage.export(json.dumps(feed))

    def test_a_clean_feed_passes_through(self):
        out = self.export()
        self.assertEqual(out['packages'][0]['runs'], FEED['packages'][0]['runs'])
        self.assertEqual(out['packages'][0]['checks'], {'passed': 10, 'notPassing': 0})

    def test_fields_the_site_does_not_render_are_dropped(self):
        def change(feed):
            feed['packages'][0]['items'] = ['anything']
            feed['packages'][0]['features'][0]['evidence'] = 'a tooltip'
            feed['hosts'] = ['anything']
        out = self.export(change)
        self.assertNotIn('items', out['packages'][0])
        self.assertNotIn('hosts', out)
        self.assertEqual(out['packages'][0]['features'][0]['evidence'], '')

    def test_the_html_report_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'not JSON'):
            coverage.export('<!doctype html><html><table></table></html>')

    def test_text_that_reads_like_a_maintainer_note_is_refused(self):
        for note in ('tracked as B999', 'by design (PLAN_99)', 'see internal/server/example.go',
                     'example.go helper', 'ABC-P3-XYZ is expected to fail', 'suite 12-realworld-example',
                     'green on ci-example', 'runs on server.lab.example'):
            with self.subTest(note=note), self.assertRaisesRegex(ValueError, 'not published'):
                self.export(lambda feed, note=note: feed['packages'][0].update(reason=note))

    def test_a_feed_without_packages_or_revision_is_refused(self):
        with self.assertRaisesRegex(ValueError, 'no package rows'):
            self.export(lambda feed: feed.update(packages=[]))
        with self.assertRaisesRegex(ValueError, 'revision'):
            self.export(lambda feed: feed.update(revision='main'))


if __name__ == '__main__':
    unittest.main()
