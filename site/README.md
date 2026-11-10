# Bodega website

`sitegen` (`main.go`) renders the project website from the repository: `README.md` becomes the front page, each document under [docs](../docs) becomes a page under `/docs/`, `docs/usage.md` splits into one page per `##` section, [`api/openapi.yaml`](../api/openapi.yaml) becomes the API reference under `/api/`, and the coverage feed becomes `/coverage.html`. nginx serves the static output. There is no JavaScript framework and no npm step.

| Path            | What it holds                                                                               |
| --------------- | ------------------------------------------------------------------------------------------- |
| `main.go`       | The generator: Markdown rendering, link rewriting, the contents column, the coverage tables |
| `api.go`        | The API reference: reads the OpenAPI document and writes the pages under `/api/`            |
| `layout.html`   | The page template every page shares                                                         |
| `site.css`      | The stylesheet, including the light, dark and color-vision palettes                         |
| `pages/`        | Pages with no Markdown source: the colophon and the 404 page                                |
| `static/fonts/` | Self-hosted Archivo and Source Serif 4 woff2 files and their SIL Open Font License texts    |
| `scripts/`      | Coverage export, deployment and their tests                                                 |

The generator is its own Go module (`site/go.mod`), so its Markdown dependency stays out of bodega's `go.mod` and out of `go list ./...`.

## Contents column

Every doc page lists the whole contents in the left column, numbered serially. An entry for a page with headings opens to that page's `h2`s and, under each, its `h3`s, read from the rendered page, so a split usage section lists its own `###` headings as its first level. The current page's entry starts open; the others start closed and open on a click on the number or the chevron, with no script. The narrow-screen contents lists pages only.

## API reference

`api.go` renders `api/openapi.yaml` with no viewer script: `/api/` lists every tag with its operations, `/api/<tag>.html` holds one tag's operations (method, path, description, parameters, request body and responses), and `/api/schemas.html` holds every schema under `components.schemas`. The pages sit in the contents column under their own group, placed by the `api` row of the `contents` table in `main.go`.

A doc that links `api/openapi.yaml` by its repository path lands on `/api/` here, and on the raw YAML when read on GitHub.

A `$ref` to a schema renders as a link into `/api/schemas.html`, so one that names a missing schema is a broken link and stops the build like any other. A `$ref` to a parameter or a response is resolved in place, and one that names nothing stops the build with the operation and the `$ref` in the message.

The renderer reads the OpenAPI keywords the document uses today. It does not render response headers, `example` values, links, callbacks or a `discriminator`; a document that starts using one builds, and the page omits it.

## Platform icons

`static/icons.svg` is a sprite of [Simple Icons](https://simpleicons.org) 16.36.0 marks (CC0). The generator draws one before a word naming an operating system or package ecosystem under these rules:

- Only the first plain-text mention of each mark in each section gets one, where a section is everything under one rendered `h2`, plus the intro above the first.
- Code spans, code blocks, headings and link text never get one: code is a literal a reader pastes.
- A table cell holding nothing but a term, plain or code, is a row label and always gets one. So do the coverage page's Type column and evidence entries.
- A match must be a whole word: `apt-get`, `npm/lodash`, `go.mod` and `GitHub` do not match.

The words and the mark each one draws are `iconTerms` in `main.go`. Words with an everyday meaning (`go`, `binary`, `ports`) are left out. Marks draw in brand colors, or in the text color under a color-vision palette or when the reader picks it under Icons. Black and low-contrast brands are mapped to the text color in `site.css`.

## Configuration

Deployment settings live in `docs-internal/site-deploy.json`, which is not committed. It holds exactly these four keys:

```json
{
  "site_url": "https://packages.example.com",
  "ssh_host": "web-production",
  "remote_root": "/srv/www/project",
  "coverage_report": "reports/packages.html"
}
```

These are example values. `coverage_report` resolves relative to the config file, or accepts an absolute or `~/` path. Configure SSH keys, ports and jump hosts in your SSH config. Pass `--config PATH` to the deployment commands, or set `BODEGA_SITE_CONFIG`; without either they read `docs-internal/site-deploy.json` in this checkout.

## Build locally

```sh
cd site
python3 scripts/coverage.py ~/path/to/report.html /tmp/coverage.json
go build -o /tmp/sitegen .
/tmp/sitegen -repo .. -tmpl . -out /tmp/bodega-site -base / \
  -coverage /tmp/coverage.json -version "$(git describe --tags --always)" -commit "$(git rev-parse HEAD)"
```

The generator checks every internal link and anchor it wrote and exits non-zero on a miss, naming the page and the target. A link to a repository path that is not a page goes to GitHub at the commit passed in `-commit`, so the footer, the source links and the text all name the same commit.

`docs/usage.md` sections are listed by heading in the `contents` table in `main.go`. Renaming or adding a `##` heading there needs the same change in that table, or the build stops with `docs/usage.md has no section "<heading>"`.

## Deploy

From the repository root:

```sh
sh site/scripts/deploy.sh --config docs-internal/site-deploy.json --dry-run
sh site/scripts/deploy.sh --config docs-internal/site-deploy.json
```

The dry run validates the config and prints the destination without building, connecting or writing. A deployment requires a clean working tree, including untracked files. It exports the coverage feed, builds and runs the generator, uploads an immutable timestamped release with a manifest of the source commit and file checksums, and activates it by replacing the `current` symlink with `mv -Tf`, all under a server-side lock. It then republishes the coverage feed and page, described next.

The workstation needs Go, Python 3.9 or newer, SSH and rsync. The server needs SSH, rsync, a POSIX shell and GNU `mv`. Provision nginx, HTTPS and the writable site directory separately; deployment does not use sudo or reload nginx.

## Coverage feed and page

```sh
sh site/scripts/sync-coverage.sh --config docs-internal/site-deploy.json
```

`scripts/coverage.py` extracts feature evidence and test results from the report into `coverage.json`. It does not import the report's layout, publish private backlog rows or recalculate readiness. Publication uploads the feed under a temporary name and renames it into `<remote_root>/data/coverage.json`.

It then renders `/coverage.html` again from the new feed. The page is built from the commit the active release names in its `deployment.json`, not from this checkout, so its layout and contents links match the pages around it; a checkout that lacks that commit refuses with a message to `git fetch`. The page lands in `<remote_root>/data/coverage.html`. A scheduler can run this command after each report; website releases and rollbacks do not touch either file.

nginx serves both files from the data directory with caching disabled:

```nginx
location = /data/coverage.json { alias <remote_root>/data/coverage.json; expires -1; }
location = /coverage.html      { alias <remote_root>/data/coverage.html; expires -1; }
```

## Roll back

Read `<remote_root>/previous-release` on the server, point a temporary symlink at that release, and replace `current` with `mv -Tf`, holding the same deployment lock. nginx needs no reload. Run the coverage publication afterwards so `/coverage.html` matches the restored release.

## Tests

```sh
make test
python3 -m unittest discover -s site/scripts -p 'test_*.py'
```

`make test` runs the generator's Go tests after bodega's own: they render a fixture OpenAPI document, and build the whole site from this checkout and fail on a broken link. The Python tests check the deployment safeguards without contacting a server: config validation, the clean-tree and changed-revision refusals, lock release on a failed upload, atomic activation, and that the coverage page renders from the deployed commit.
