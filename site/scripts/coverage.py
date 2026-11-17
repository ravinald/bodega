#!/usr/bin/env python3
"""Copy the public support feed into place, keeping only the fields the site renders.

The input is the JSON feed the status report writes for publication, never the
report's own HTML: that page carries maintainer notes in its tooltips (work-item
ids, source paths, test identifiers), and reading it put them on the public
site. This script recomputes nothing. It rebuilds the feed from a fixed list of
fields, so a field added upstream is not published until it is added here, and
it refuses a feed whose text still reads like one of those notes.
"""
import json
from pathlib import Path
import re
import sys

VERDICTS = {'Ready', 'Usable', 'Partial', 'Not yet', 'Unverified', 'Not served', 'Unrated'}
# What a maintainer note looks like. The feed is built from computed values, so
# a match means its producer changed and the feed needs reading before it ships.
PRIVATE = {
    'a work-item id': re.compile(r'\b[BEF]\d{2,3}\b|\bPLAN_\d+'),
    'a source path': re.compile(r'\b(internal|cmd|test|docs)/[\w./-]+|\.(go|sh|py|tsv|env)\b'),
    'a test identifier': re.compile(r'\b[A-Z]{2,6}(-[A-Z0-9]+)*-P?\d|\b\d\d-[a-z]+(-[a-z0-9]+)+\b'),
    'a host or host-group name': re.compile(r'\b[a-z0-9-]+\.[a-z0-9-]+\.[a-z]{2,}\b|\bci-[a-z0-9]+\b|\bk8s\b'),
}


def text(value, where):
    if not isinstance(value, str):
        raise ValueError(f'{where} is not a string')
    for kind, pattern in PRIVATE.items():
        found = pattern.search(value)
        if found:
            raise ValueError(f'{where} holds {kind} ({found.group(0)!r}); the feed is not published')
    return value


def count(value, where):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f'{where} is not a count')
    return value


def package(p, where):
    if p.get('verdict') not in VERDICTS:
        raise ValueError(f'{where}.verdict is not a known verdict')
    return {
        'id': text(p.get('id'), f'{where}.id'),
        'verdict': p['verdict'],
        'reason': text(p.get('reason'), f'{where}.reason'),
        'coverage': text(p.get('coverage'), f'{where}.coverage'),
        'lastTested': text(p.get('lastTested', ''), f'{where}.lastTested'),
        'checks': {k: count(v, f'{where}.checks.{k}') for k, v in (p.get('checks') or {}).items()
                   if k in ('passed', 'notPassing', 'knownIssues', 'skipped', 'runsWithoutResult')},
        # evidence and state stay empty: they were the report's tooltips.
        'features': [{'label': text(f.get('label'), f'{where}.features[{i}].label'),
                      'description': text(f.get('description'), f'{where}.features[{i}].description'),
                      'value': text(f.get('value'), f'{where}.features[{i}].value'),
                      'evidence': '', 'state': ''}
                     for i, f in enumerate(p.get('features') or [])],
        'runs': [{k: text(r.get(k, ''), f'{where}.runs[{i}].{k}') for k in ('text', 'title', 'class')}
                 for i, r in enumerate(p.get('runs') or [])],
    }


def scoring(s):
    return {
        'verdictRules': [{'verdict': text(r.get('verdict'), 'scoring.verdictRules.verdict'),
                          'rule': text(r.get('rule'), 'scoring.verdictRules.rule')}
                         for r in s.get('verdictRules') or []],
        'featureWeights': [{'weight': count(w.get('weight'), 'scoring.featureWeights.weight'),
                            'features': [text(f, 'scoring.featureWeights.features') for f in w.get('features') or []]}
                           for w in s.get('featureWeights') or []],
        'featureValues': [{'value': text(v.get('value'), 'scoring.featureValues.value'),
                           'counts': text(v.get('counts'), 'scoring.featureValues.counts')}
                          for v in s.get('featureValues') or []],
    }


def export(source):
    try:
        feed = json.loads(source)
    except ValueError:
        raise ValueError('coverage_report is not JSON. Point it at the public feed the status report writes, '
                         'not at the HTML report') from None
    if not isinstance(feed, dict) or feed.get('schemaVersion') != 1:
        raise ValueError('Feed schema changed: expected schemaVersion 1')
    if not re.fullmatch(r'[0-9a-f]{7,40}', str(feed.get('revision'))):
        raise ValueError('Feed is missing its revision')
    if not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', str(feed.get('evaluatedAt'))):
        raise ValueError('Feed is missing its evidence date')
    packages = [package(p, f'packages[{i}]') for i, p in enumerate(feed.get('packages') or [])]
    if not packages:
        raise ValueError('Feed has no package rows')
    return {'schemaVersion': 1, 'revision': feed['revision'], 'evaluatedAt': feed['evaluatedAt'],
            'summary': text(feed.get('summary'), 'summary'), 'packages': packages,
            'scoring': scoring(feed.get('scoring') or {})}


if __name__ == '__main__':
    try:
        feed = export(Path(sys.argv[1]).read_text())
    except ValueError as error:
        sys.exit(f'coverage.py: {error}')
    output = Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix('.tmp')
    temporary.write_text(json.dumps(feed, indent=2, ensure_ascii=False) + '\n')
    temporary.replace(output)
