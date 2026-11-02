#!/usr/bin/env python3
"""Check the built site's local navigation, fragments, and asset references."""
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote, urlsplit
import sys


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.links = []
        self.ids = set()
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if attrs.get('id'):
            self.ids.add(attrs['id'])
        if tag in ('a', 'link') and attrs.get('href'):
            self.links.append(attrs['href'])
        if tag in ('img', 'script') and attrs.get('src'):
            self.links.append(attrs['src'])

    def failures(self, path, root, pages):
        for link in self.links:
            url = urlsplit(link)
            if url.scheme or url.netloc:
                continue
            pathname = unquote(url.path)
            target = root / pathname.lstrip('/') if pathname.startswith('/') else path.parent / pathname if pathname else path
            if target.is_dir():
                target /= 'index.html'
            if not target.exists():
                yield f'{path.relative_to(root)}: missing {link}'
            elif url.fragment and target in pages and unquote(url.fragment) not in pages[target].ids:
                yield f'{path.relative_to(root)}: missing fragment {link}'


if __name__ == '__main__':
    root = Path(__file__).resolve().parents[1] / 'dist'
    pages = {path: Page(path.read_text()) for path in root.rglob('*.html')}
    failures = [failure for path, page in pages.items() for failure in page.failures(path, root, pages)]
    if not pages:
        failures.append('No built pages; run npm run build first.')
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f'{len(pages)} pages checked; {len(failures)} broken links, fragments, or assets.')
    sys.exit(bool(failures))
