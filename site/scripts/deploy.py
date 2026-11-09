#!/usr/bin/env python3
"""Deploy static releases using an operator-owned JSON config and SSH identity."""
import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import uuid

SITE = Path(__file__).resolve().parents[1]
REPO = SITE.parent
DEFAULT_CONFIG = REPO / 'docs-internal/site-deploy.json'
# Every repository path the generator reads.
RENDERED = ('site', 'docs', 'assets', 'README.md', 'SECURITY.md', 'CONTRIBUTING.md')


@dataclass(frozen=True)
class DeploymentConfig:
    source: Path
    site_url: str
    ssh_host: str
    remote_root: str
    coverage_report: Path

    @classmethod
    def load(cls, source):
        source = Path(source).expanduser().resolve()
        data = json.loads(source.read_text())
        keys = {'site_url', 'ssh_host', 'remote_root', 'coverage_report'}
        if not isinstance(data, dict) or set(data) != keys:
            raise ValueError('Config must contain exactly: ' + ', '.join(sorted(keys)))
        if any(not isinstance(value, str) or not value for value in data.values()):
            raise ValueError('Config values must be nonempty strings')
        url = urlsplit(data['site_url'])
        if (url.scheme != 'https' or not url.hostname or url.username or url.password
                or url.path not in ('', '/') or url.query or url.fragment
                or any(c.isspace() for c in data['site_url'])):
            raise ValueError('site_url must be an HTTPS origin without credentials, a path, query, or fragment')
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*(?:@[A-Za-z0-9][A-Za-z0-9_.-]*)?', data['ssh_host']):
            raise ValueError('ssh_host must be an SSH alias or user@host; configure ports and keys in SSH config')
        remote = data['remote_root'].rstrip('/')
        if (not re.fullmatch(r'/[A-Za-z0-9_./-]+', remote)
                or any(p in ('.', '..') for p in remote.split('/'))
                or len(PurePosixPath(remote).parts) < 3):
            raise ValueError('remote_root must be an absolute site directory below a parent, without spaces or traversal')
        report = Path(data['coverage_report']).expanduser()
        if not report.is_absolute():
            report = source.parent / report
        report = report.resolve()
        if not report.is_file():
            raise ValueError('coverage_report does not exist')
        return cls(source, data['site_url'].rstrip('/'), data['ssh_host'], remote, report)



def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def git(*args):
    return run(['git', '-C', str(REPO), *args], capture_output=True, text=True).stdout.strip()


def clean_revision():
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Deployment requires a clean working tree, including untracked files. Commit reviewed source first.')
    return git('rev-parse', 'HEAD')


def remote(config, script, *args, capture=False):
    command = 'sh -s -- ' + shlex.join([config.remote_root, *args])
    return run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                '--', config.ssh_host, command], input=script, text=True, capture_output=capture)


def upload(config, source, destination):
    run(['rsync', '-az', '--timeout=60', '-e', 'ssh -o BatchMode=yes -o ConnectTimeout=10',
         '--', str(source), f'{config.ssh_host}:{destination}'])


def artifact_manifest(directory, revision):
    files = {}
    for file in sorted(directory.rglob('*')):
        if file.is_file():
            files[file.relative_to(directory).as_posix()] = hashlib.sha256(file.read_bytes()).hexdigest()
    manifest = {'sourceRevision': revision, 'builtAt': datetime.now(timezone.utc).isoformat(), 'sha256': files}
    (directory / 'deployment.json').write_text(json.dumps(manifest, indent=2) + '\n')


def export_coverage(config, output):
    run([sys.executable, '-I', str(SITE / 'scripts/coverage.py'), str(config.coverage_report), str(output)])
    json.loads(output.read_text())


def render(root, output, coverage, revision):
    """Build the generator from root/site and render root's README and docs into output.

    The generator checks every internal link and anchor and exits non-zero on a miss."""
    generator = output.parent / 'sitegen'
    run(['go', 'build', '-trimpath', '-o', str(generator), '.'], cwd=root / 'site')
    version = git('describe', '--tags', '--always', revision)
    run([str(generator), '-repo', str(root), '-tmpl', str(root / 'site'), '-out', str(output), '-base', '/',
         '-coverage', str(coverage), '-version', version, '-commit', revision])


def deploy(config):
    revision = clean_revision()
    release = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + revision[:12] + '-' + uuid.uuid4().hex[:8]
    with tempfile.TemporaryDirectory(prefix='bodega-site-') as temporary:
        staging = Path(temporary)
        coverage = staging / 'coverage.json'
        export_coverage(config, coverage)
        artifact = staging / 'artifact'
        render(REPO, artifact, coverage, revision)
        if clean_revision() != revision:
            raise ValueError('Source revision changed during the build; nothing uploaded')
        artifact_manifest(artifact, revision)
        # Hold the server-side lock through upload and activation, not just rename.
        remote(config, """set -eu
base=$1
release=$2
test -d "$base"
mkdir "$base/.deploy-lock" || { echo 'Another deployment holds the lock' >&2; exit 1; }
printf '%s\n' "$release" > "$base/.deploy-lock/owner"
""", release)
        try:
            remote(config, 'set -eu\nmkdir -p "$1/releases"\nmkdir "$1/releases/$2"\n', release)
            upload(config, str(artifact) + '/', f'{config.remote_root}/releases/{release}/')
            remote(config, """set -eu
base=$1
release=$2
test "$(cat "$base/.deploy-lock/owner")" = "$release"
test -s "$base/releases/$release/index.html"
test -s "$base/releases/$release/deployment.json"
if [ -e "$base/current" ] && [ ! -L "$base/current" ]; then
    echo 'current must be a symlink' >&2; exit 1
fi
if [ -L "$base/current" ]; then
    readlink "$base/current" > "$base/previous-release.next"
    mv -f "$base/previous-release.next" "$base/previous-release"
fi
ln -s "releases/$release" "$base/current.$release"
mv -Tf "$base/current.$release" "$base/current"
""", release)
        finally:
            remote(config, """set -eu
test "$(cat "$1/.deploy-lock/owner")" = "$2"
rm "$1/.deploy-lock/owner"
rmdir "$1/.deploy-lock"
""", release)
    print(f'Activated {release} at {config.site_url}.')


def deployed_revision(config):
    """The commit the active release was built from, read from its manifest on the server."""
    manifest = remote(config, 'set -eu\ncat "$1/current/deployment.json"\n', capture=True).stdout
    revision = json.loads(manifest).get('sourceRevision', '')
    if not re.fullmatch(r'[0-9a-f]{40}', revision):
        raise ValueError(f'{config.remote_root}/current/deployment.json names no full sourceRevision')
    if subprocess.run(['git', '-C', str(REPO), 'cat-file', '-e', revision + '^{commit}'], capture_output=True).returncode:
        raise ValueError(f'The active release was built from {revision}, which this checkout lacks; run git fetch')
    return revision


def publish_coverage(config):
    """Publish the feed, then re-render /coverage.html from it with the active release's own sources.

    The page is rendered from the deployed commit rather than this checkout, so its
    layout, stylesheet and contents links match the release nginx serves around it."""
    with tempfile.TemporaryDirectory(prefix='bodega-coverage-') as temporary:
        staging = Path(temporary)
        output = staging / 'coverage.json'
        export_coverage(config, output)
        name = 'coverage.' + uuid.uuid4().hex
        upload(config, output, f'{config.remote_root}/data/{name}.json')
        remote(config, 'set -eu\nmv -f "$1/data/$2.json" "$1/data/coverage.json"\n', name)
        print('Public coverage feed updated')

        revision = deployed_revision(config)
        source = staging / 'source'
        source.mkdir()
        archive = run(['git', '-C', str(REPO), 'archive', revision, *RENDERED], capture_output=True).stdout
        run(['tar', '-x', '-C', str(source)], input=archive)
        render(source, staging / 'site', output, revision)
        upload(config, staging / 'site/coverage.html', f'{config.remote_root}/data/{name}.html')
        remote(config, 'set -eu\nmv -f "$1/data/$2.html" "$1/data/coverage.html"\n', name)
    print(f'Public coverage page updated from release commit {revision[:12]}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['deploy', 'coverage'])
    parser.add_argument('--config', type=Path, default=os.environ.get('BODEGA_SITE_CONFIG', DEFAULT_CONFIG),
                        help='operator JSON config; defaults to docs-internal/site-deploy.json')
    parser.add_argument('--dry-run', action='store_true', help='validate config and print the plan; no build, SSH, or writes')
    args = parser.parse_args()
    try:
        config = DeploymentConfig.load(args.config)
        if args.dry_run:
            print(f'{args.command}: {config.site_url} via {config.ssh_host}, root {config.remote_root}')
            print('No commands executed. Deployment requires committed source and republishes the coverage feed and page.')
        elif args.command == 'deploy':
            deploy(config)
            # nginx serves /coverage.html from the data directory, so a new release
            # shows its own layout there only once the page is rendered again.
            publish_coverage(config)
        else:
            publish_coverage(config)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
