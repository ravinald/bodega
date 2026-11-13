# Bodega website

`sitegen` (`main.go`) renders the project website from the repository: `README.md` becomes the front page, each document under [docs](../docs) becomes a page under `/docs/`, `docs/usage.md` splits into one page per `##` section, [Scalar](https://github.com/scalar/scalar) renders [`api/openapi.yaml`](../api/openapi.yaml) as the API reference at `/api/` from a vendored, checksummed bundle, and the coverage feed becomes `/coverage.html`. nginx serves the static output. No build step runs npm, and every script, stylesheet and font a page loads comes from the site's own origin.

| Path             | What it holds                                                                               |
| ---------------- | ------------------------------------------------------------------------------------------- |
| `main.go`        | The generator: Markdown rendering, link rewriting, the contents column, the coverage tables |
| `layout.html`    | The page template every page shares                                                         |
| `site.css`       | The stylesheet, including the light, dark and color-vision palettes                         |
| `pages/`         | Pages with no Markdown source: the colophon and the 404 page                                |
| `static/fonts/`  | Self-hosted Archivo and Source Serif 4 woff2 files and their SIL Open Font License texts    |
| `static/scalar/` | The vendored Scalar bundle and `scalar.json`, the record of its version and SHA-256         |
| `scripts/`       | Coverage export, deployment and their tests, and `update-scalar.sh`                         |

The generator is its own Go module (`site/go.mod`), so its dependencies stay out of bodega's `go.mod` and out of `go list ./...`: goldmark for the Markdown, and for the tests alone [`chromedp`](https://github.com/chromedp/chromedp) and a YAML parser.

## Contents column

Every doc page lists the whole contents in the left column, numbered serially. An entry for a page with headings opens to that page's `h2`s and, under each, its `h3`s, read from the rendered page, so a split usage section lists its own `###` headings as its first level. The current page's entry starts open; the others start closed and open on a click on the number or the chevron, with no script. The narrow-screen contents lists pages only.

## API reference

`/api/` is one page. It keeps the site's header and navigation, and under them [Scalar](https://github.com/scalar/scalar)'s standalone bundle renders `api/openapi.yaml` in the reader's browser, embedded the way Scalar's own HTML integration does it: a mount point, the bundle, and one `Scalar.createApiReference` call. The generator copies the document to `/api/openapi.yaml`, which is both what the page fetches and the download. The page sits in the contents column under its own group, placed by the `api` row of the `contents` table in `main.go`.

A doc that links `api/openapi.yaml` by its repository path lands on `/api/` here, and on the raw YAML when read on GitHub. A link that offers the file as a download carries the Markdown title `"Download the OpenAPI document"`, which keeps it on `/api/openapi.yaml`:

```md
[`api/openapi.yaml`](../api/openapi.yaml "Download the OpenAPI document")
```

This is the one page where the site runs a third-party script. The pages around it carry a few lines of their own for the display preferences and the coverage table's sorting, and nothing else. The configuration in `apiBody` (`main.go`) keeps Scalar on this origin:

| Option                                                 | Why                                                                                                  |
| ------------------------------------------------------ | ---------------------------------------------------------------------------------------------------- |
| `telemetry: false`                                     | Scalar reports usage to scalar.com otherwise                                                         |
| `withDefaultFonts: false`                              | Its default theme fetches Inter and a monospace face from fonts.scalar.com                           |
| `hideClientButton`, `hideTestRequestButton`            | A request from this site to a reader's own bodega server is cross-origin and would carry their token |
| `showDeveloperTools: "never"`                          | The toolbar links to Scalar's hosted products                                                        |
| `mcp: { disabled: true }`, `agent: { disabled: true }` | Both reach scalar.com, and the agent is on by default for a localhost URL                            |
| `layout: "modern"`                                     | Scalar's layout with its own sidebar and search                                                      |

The mount point's id is `reference`, not `api-reference`: the bundle mounts a second reference with its defaults on any element carrying that id, and the defaults fetch the hosted fonts.

### Updating Scalar

The bundle is one exact `@scalar/api-reference` release, committed under `static/scalar/`. To move to another:

```sh
sh site/scripts/update-scalar.sh 1.76.0
```

Give it a release published at least two weeks ago, so a bad publish has had time to be noticed and pulled. The script downloads the package tarball from `registry.npmjs.org`, refuses it unless its sha512 matches the `dist.integrity` the registry's metadata reports for that version, extracts `dist/browser/standalone.js`, and writes `scalar.json` with the version and the bundle's SHA-256. It needs `curl`, `openssl`, `tar` and `python3`, and runs no npm or other package client. The registry check catches a truncated or substituted download; the metadata and the tarball come from the same origin, so it is the committed SHA-256 that holds from then on. Commit the bundle and `scalar.json` together.

The generator refuses to build when the bundle's SHA-256 is not the one `scalar.json` records, and a test fails on the same mismatch, so an edit to the bundle that nobody recorded does not ship. A new release can add a default that reaches out, so after an update run `make test`: it loads `/api/` in headless Chrome with the new bundle and fails on any request that leaves the site's origin.

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

## Automatic deployment

```sh
sh site/scripts/sync-coverage.sh --config docs-internal/site-deploy.json
```

This runs `deploy.py sync`, which a scheduler calls every few minutes. It fetches `origin/main` and reads the commit the live release was built from (`sourceRevision` in `<remote_root>/current/deployment.json`). When the live commit is a strict ancestor of `main`, it deploys `main`. It builds from `git archive` of that commit rather than from the checkout, so the checkout's branch and working tree do not matter. It then republishes the coverage feed and page, described next. It leaves the live release in place in two cases, and says which in its output:

| Case                                    | Why                                                   |
| --------------------------------------- | ----------------------------------------------------- |
| The live commit is not on `main`        | Someone deployed a branch on purpose                  |
| `<remote_root>/auto-deploy-hold` exists | A rollback is in place and must outlive the next pass |

A failed build or upload changes nothing on the server, and the next pass tries again.

## Coverage feed and page

`scripts/coverage.py` extracts feature evidence and test results from the report into `coverage.json`. It does not import the report's layout, publish private backlog rows or recalculate readiness. Publication uploads the feed under a temporary name and renames it into `<remote_root>/data/coverage.json`.

It then renders `/coverage.html` again from the new feed. The page is built from the commit the active release names in its `deployment.json`, not from this checkout, so its layout and contents links match the pages around it; a checkout that lacks that commit refuses with a message to `git fetch`. The page lands in `<remote_root>/data/coverage.html`. A scheduler can run this command after each report; website releases and rollbacks do not touch either file.

nginx serves both files from the data directory with caching disabled:

```nginx
location = /data/coverage.json { alias <remote_root>/data/coverage.json; expires -1; }
location = /coverage.html      { alias <remote_root>/data/coverage.html; expires -1; }
```

## Roll back

Create `<remote_root>/auto-deploy-hold` first, or the next automatic pass deploys `main` over the rollback. Then read `<remote_root>/previous-release` on the server, point a temporary symlink at that release, and replace `current` with `mv -Tf`, holding the same deployment lock. nginx needs no reload. Run the coverage publication afterwards so `/coverage.html` matches the restored release. Remove the hold once `main` carries the fix.

## Tests

```sh
make test
python3 -m unittest discover -s site/scripts -p 'test_*.py'
```

`make test` runs the generator's Go tests after bodega's own: they build the whole site from this checkout and fail on a broken link, on a Scalar bundle whose SHA-256 is not the recorded one, on an `/api/` page that loads anything from another origin, and on a site URL in `api/openapi.yaml` or `docs/usage.md` that names no page. The `/api/` check reads the page four ways, because one reader cannot see every load:

| Reader                 | What it sees                                                                                                                           |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| The generated HTML     | A script, stylesheet, font, image or frame the page names                                                                              |
| The linked stylesheets | Every `url()` and `@import` in the site's CSS, including rules a browser would not apply on the day                                    |
| The OpenAPI document   | A Markdown image or an HTML tag in any string of `api/openapi.yaml`, including the tags, operations and schemas Scalar keeps collapsed |
| Headless Chrome        | Every request the page makes once Scalar has run and rendered the introduction                                                         |

The last one needs Chrome or Chromium on the host, under a name `chromedp` looks for, and the test fails with that instruction when it finds none. Chrome resolves no host name during the run, so a request the test reports was attempted and never sent. Nothing clicks through the reference: what Scalar fetches only after a reader opens a section is covered by the document reader for the document's own content, and by the pinned bundle and its configuration for the rest.

`test_reference_privacy.py` plants an image on another origin in a copy of the document's introduction and passes only when the Go check refuses that copy. `test_deploy.py` checks the deployment safeguards without contacting a server: config validation, the clean-tree and changed-revision refusals, lock release on a failed upload, atomic activation, that the coverage page renders from the deployed commit, and that `sync` deploys only a trunk ahead of the live release with no hold in place.
