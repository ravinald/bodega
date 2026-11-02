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
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
import uuid

SITE = Path(__file__).resolve().parents[1]
REPO = SITE.parent
DEFAULT_CONFIG = REPO / 'docs-internal/site-deploy.json'


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

    def build_environment(self):
        return dict(os.environ, BODEGA_SITE_CONFIG=str(self.source),
                    BODEGA_SITE_URL=self.site_url, BODEGA_COVERAGE_REPORT=str(self.coverage_report))


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, **kwargs)


def git(*args):
    return run(['git', '-C', str(REPO), *args], capture_output=True, text=True).stdout.strip()


def clean_revision():
    if git('status', '--porcelain', '--untracked-files=all'):
        raise ValueError('Deployment requires a clean working tree, including untracked files. Commit reviewed source first.')
    return git('rev-parse', 'HEAD')


def remote(config, script, *args):
    command = 'sh -s -- ' + shlex.join([config.remote_root, *args])
    return run(['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10',
                '--', config.ssh_host, command], input=script, text=True)


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


def deploy(config):
    revision = clean_revision()
    release = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + revision[:12] + '-' + uuid.uuid4().hex[:8]
    with tempfile.TemporaryDirectory(prefix='bodega-site-') as temporary:
        staging = Path(temporary)
        report = staging / 'report.html'
        shutil.copyfile(config.coverage_report, report)
        env = dict(config.build_environment(), BODEGA_COVERAGE_REPORT=str(report))
        run(['npm', 'ci'], cwd=SITE, env=env)
        run(['npm', 'run', 'build'], cwd=SITE, env=env)
        run(['npm', 'run', 'check'], cwd=SITE, env=env)
        if clean_revision() != revision:
            raise ValueError('Source revision changed during the build; nothing uploaded')
        artifact = staging / 'artifact'
        shutil.copytree(SITE / 'dist', artifact)
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
    print(f'Activated {release} at {config.site_url}. Independent coverage feed unchanged.')


def publish_coverage(config):
    with tempfile.TemporaryDirectory(prefix='bodega-coverage-') as temporary:
        output = Path(temporary) / 'coverage.json'
        run([sys.executable, '-I', str(SITE / 'scripts/coverage.py'), str(config.coverage_report), str(output)])
        json.loads(output.read_text())
        name = 'coverage.' + uuid.uuid4().hex + '.json'
        upload(config, output, f'{config.remote_root}/data/{name}')
        remote(config, 'set -eu\nmv -f "$1/data/$2" "$1/data/coverage.json"\n', name)
    print('Public coverage updated')


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
            print('No commands executed. Deployment requires committed source; coverage publication is independent.')
        elif args.command == 'deploy':
            deploy(config)
        else:
            publish_coverage(config)
    except (OSError, ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
