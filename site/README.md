# Bodega website

Astro builds the showcase and coverage explorer. Starlight builds searchable operator documentation from the repository's Markdown. nginx serves the static output.

## Local configuration

Keep deployment settings in `docs-internal/site-deploy.json`, which belongs to the private attic overlay and is ignored by Git. The config contains exactly these four keys:

```json
{
  "site_url": "https://packages.example.com",
  "ssh_host": "web-production",
  "remote_root": "/srv/www/project",
  "coverage_report": "reports/packages.html"
}
```

These are example values. `coverage_report` resolves relative to the config file, or accepts an absolute path or `~/` path. Configure SSH keys, ports, and jump hosts in your SSH config. Keep actual nginx and scheduler configurations in the overlay too. Never force-add the overlay, generated site output, or private reports.

Pass `--config PATH` to deployment commands, or set `BODEGA_SITE_CONFIG`. Without either, they read `docs-internal/site-deploy.json` in this checkout. The build uses the same default config and accepts `BODEGA_SITE_URL` and `BODEGA_COVERAGE_REPORT` overrides. Without config, the build defaults to localhost and requires an explicit coverage report.

## Build and preview

```sh
cd site
npm ci
npm run build
npm run check
npm run preview
```

Use `npm run dev` during development. Dependencies are pinned in the lockfile. The build refuses coverage reports missing expected columns or evidence metadata.

`scripts/prepare.mjs` copies public assets, prepares documentation, and exports coverage data. Generated files under `public/assets`, `public/data`, and `src/content/docs` are ignored. Edit the original documents under [docs](../docs), including the [operations runbook](../docs/runbook.md). The build splits the operations reference into topics and retains the complete reference for cross-links.

## Deploy

From the repository root:

```sh
sh site/scripts/deploy.sh --config docs-internal/site-deploy.json --dry-run
sh site/scripts/deploy.sh --config docs-internal/site-deploy.json
```

The dry run validates config and prints the destination without building, connecting, or writing. An actual deployment requires a clean Git working tree, including untracked files. It installs locked dependencies, builds, checks local links, and uploads an immutable timestamped release. A manifest records the full source commit and artifact checksums. A server-side lock covers upload and activation; an atomic symlink replacement activates the release. Old releases remain available for rollback. Interrupted deployments can leave a lock: inspect its owner and confirm the deployment has stopped before removing it.

The workstation needs Node, npm, Python 3.9 or newer, SSH, and rsync. The server needs SSH, rsync, a POSIX shell, and GNU `mv` for atomic symlink replacement. Provision nginx, HTTPS, and the writable site directory separately. nginx should serve `<remote_root>/current`, with `/data/coverage.json` mapped to `<remote_root>/data/coverage.json` and caching disabled for that feed. Create the data directory before publishing coverage. The deployment account must own the release directory and symlink; deployment does not use sudo or reload nginx.

Build artifacts contain the public origin by design. They remain ignored locally and are uploaded to the web server, not committed to source control. Deployment config stays outside the artifact. Keep passwords and private keys in SSH facilities, not in this JSON file.

## Coverage feed

`scripts/coverage.py` extracts evaluated feature evidence and test results from the report. It does not import the report's layout, publish private backlog rows, or recalculate readiness. The explorer renders native HTML disclosure controls, with client-side filtering and a fetch of the current JSON feed. The bundled snapshot remains readable without JavaScript or when the feed fails.

```sh
sh site/scripts/sync-coverage.sh --config docs-internal/site-deploy.json --dry-run
sh site/scripts/sync-coverage.sh --config docs-internal/site-deploy.json
```

Coverage publication exports JSON, uploads a uniquely named temporary file, and renames it into place. It operates independently of website releases; deploying or rolling back the website does not overwrite this feed. Keep the JSON schema compatible across releases. A private scheduler can invoke this command after report generation. The existing report producer remains responsible for evaluating evidence. If publication stops, the public site retains the last snapshot and shows its age; the explorer warns once the snapshot is over 48 hours old.

The report producer's scoring rules are described on the coverage page. Update that explanation if the producer changes its scoring contract. The exporter checks structure; it does not establish the truth of report evidence itself. Review exported data before making a new report source public.

## Roll back and verify

Read `<remote_root>/previous-release` on the server and inspect that release directory. Point a temporary symlink at it, then replace `current` with `mv -Tf`. Coordinate rollback with deployments using the same deployment lock. nginx needs no reload for a release switch. Coverage remains independently updated.

Run `python3 -m unittest discover -s site/scripts -p 'test_*.py'` to check deployment safeguards without contacting a server. The production build indexes documentation with Pagefind. Check the homepage, client selector, coverage filters and evidence disclosures, documentation search, narrow layouts, HTTPS redirect, and a genuine 404 after deployment. Do not expose source trees, private reports, or backend package routes from this vhost.
