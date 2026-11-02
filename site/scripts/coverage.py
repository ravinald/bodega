#!/usr/bin/env python3
"""Export the existing report's evaluated evidence without recomputing scores."""
import json
from html.parser import HTMLParser
from pathlib import Path
import re
import sys


class ReportParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.depth = 0
        self.cell = None
        self.row = []
        self.rows = []
        self.capture = None
        self.capture_depth = 0
        self.meta = {}
        self.chip = None
        self.chip_depth = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'table':
            self.depth += 1
        if tag == 'p' and attrs.get('class') in ('summary', 'sub'):
            self.capture = attrs['class']
            self.meta[self.capture] = ''
        if self.depth == 1 and tag == 'tr':
            self.row = []
        if self.depth == 1 and tag in ('td', 'th'):
            self.cell = {'text': '', 'title': attrs.get('title', ''), 'class': attrs.get('class', ''), 'chips': []}
        if self.cell is not None and tag == 'span' and ('run' in attrs.get('class', '').split() or 'v' in attrs.get('class', '').split()):
            self.chip = {'text': '', 'title': attrs.get('title', ''), 'class': attrs.get('class', '')}
        if self.chip is not None and tag == 'span':
            self.chip_depth += 1

    def handle_data(self, data):
        if self.capture:
            self.meta[self.capture] += data
        if self.cell is not None:
            self.cell['text'] += data
        if self.chip is not None:
            self.chip['text'] += data

    def handle_endtag(self, tag):
        if tag == 'p':
            self.capture = None
        if tag == 'span' and self.chip is not None:
            self.chip_depth -= 1
            if self.chip_depth == 0:
                self.chip['text'] = self.chip['text'].strip()
                self.cell['chips'].append(self.chip)
                self.chip = None
        if tag in ('td', 'th') and self.cell is not None:
            self.cell['text'] = self.cell['text'].strip()
            self.row.append(self.cell)
            self.cell = None
        if tag == 'tr' and self.depth == 1 and self.row:
            self.rows.append(self.row)
        if tag == 'table':
            self.depth -= 1

    def export(self):
        if not self.rows or len(self.rows[0]) != 15:
            raise ValueError('Report schema changed: expected 15 columns')
        stamp = re.search(r'rendered (\d{4}-\d\d-\d\d \d\d:\d\d) UTC', self.meta.get('sub', ''))
        revision = re.search(r'Build ([0-9a-f]+)', self.meta.get('sub', ''))
        if not stamp or not revision:
            raise ValueError('Report is missing its evidence date or revision')
        packages = []
        for row in self.rows[1:]:
            if len(row) != 15:
                continue
            verdict = row[1]['chips'][0] if row[1]['chips'] else {'text': row[1]['text'], 'title': ''}
            packages.append({
                'id': re.split(r'[×\s]', row[0]['text'])[0],
                'verdict': verdict['text'], 'reason': verdict['title'],
                'coverage': row[2]['text'],
                'features': [{'label': re.sub(r'×\d+', '', head['text']).strip(), 'description': head['title'],
                              'value': cell['text'], 'evidence': cell['title'], 'state': cell['class']}
                             for head, cell in zip(self.rows[0][3:13], row[3:13])],
                'runs': row[13]['chips'],
            })
        if not packages:
            raise ValueError('Report has no package rows')
        return {'schemaVersion': 1, 'revision': revision[1],
                'evaluatedAt': stamp[1].replace(' ', 'T') + ':00Z',
                'summary': self.meta.get('summary', ''), 'packages': packages}


if __name__ == '__main__':
    parser = ReportParser()
    parser.feed(Path(sys.argv[1]).read_text())
    output = Path(sys.argv[2])
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix('.tmp')
    temporary.write_text(json.dumps(parser.export(), indent=2) + '\n')
    temporary.replace(output)
