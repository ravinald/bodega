import { mkdir, readFile, writeFile, cp, readdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { readBuildConfig } from './config.mjs';

const site = fileURLToPath(new URL('../', import.meta.url));
const root = path.resolve(site, '..');

export async function prepareDocs() {
  await mkdir(path.join(site, 'src/content/i18n'), { recursive: true });
  await writeFile(path.join(site, 'src/content/i18n/en.json'), '{}\n');
  const sources = ['docs/quickstart.md', 'docs/usage.md', 'docs/design.md', 'docs/threat-model.md',
    'docs/slsa.md', 'docs/runbook.md',
    'docs/quarantine/README.md', 'docs/quarantine/cli.md', 'docs/quarantine/api.md', 'docs/quarantine/tui.md',
    'SECURITY.md', 'CONTRIBUTING.md'];
  const destination = source => source.startsWith('docs/') ? source.replace('README.md', 'index.md') : `docs/${source.toLowerCase()}`;
  for (const source of sources) {
    const file = path.join(site, 'src/content/docs', destination(source));
    let text = await readFile(path.join(root, source), 'utf8');
    const title = text.match(/^# (.+)$/m)?.[1] || path.basename(source, '.md');
    text = text.replace(/^# .+\n/, '');
    text = text.replace(/^```zone$/gm, '```text');
    if (source === 'docs/usage.md') {
      const doctorHeading = text.match(/^### `(bodega doctor[^\n]*)`$/m)?.[1];
      if (doctorHeading) {
        const anchor = doctorHeading.toLowerCase().replace(/[\[\]`]/g, '').replace(/ /g, '-');
        text = text.replace(/\]\(#bodega-doctor[^)]+\)/g, `](#${anchor})`);
      }
    }
    text = text.replace(/(!?\[[^\]]*\])\(([^)\s]+)\)/g, (match, label, target) => {
      if (/^(https?:|#|mailto:)/.test(target)) return match;
      const [pathname, hash] = target.split('#');
      const resolved = path.posix.normalize(path.posix.join(path.posix.dirname(source), pathname));
      if (label.startsWith('!')) return `${label}(/assets/${path.posix.basename(pathname)})`;
      if (sources.includes(resolved)) return `${label}(/${destination(resolved).replace(/(?:index)?\.md$/, '')}/${hash ? '#' + hash : ''})`.replace(/\/\//g, '/');
      if (resolved === 'docs/quarantine/' || resolved === 'docs/quarantine') return `${label}(/docs/quarantine/)`;
      return `${label}(https://github.com/ravinald/bodega/blob/main/${resolved}${hash ? '#' + hash : ''})`;
    });
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, `---\ntitle: ${JSON.stringify(title)}\n---\n\n<!-- Codex-md-guard: allow verbatim-copy; source: ${source}. Links adapted for the website. -->\n${text}`);
    if (source === 'docs/usage.md') {
      const sections = text.split(/^## /m).slice(1);
      for (const section of sections) {
        const end = section.indexOf('\n');
        const heading = section.slice(0, end).trim();
        if (heading === 'Table of Contents') continue;
        const slug = heading.toLowerCase().replace(/[./]/g, '').replace(/ /g, '-');
        const body = section.slice(end + 1).replace(/\]\(#([^)]+)\)/g, '](/docs/usage/#$1)');
        const target = path.join(site, 'src/content/docs/docs/operator', `${slug}.md`);
        await mkdir(path.dirname(target), { recursive: true });
        await writeFile(target, `---\ntitle: ${JSON.stringify(heading)}\n---\n\n<!-- Codex-md-guard: allow verbatim-copy; source: docs/usage.md, ${heading} section. -->\n\n${body}`);
      }
    }
  }
  await writeFile(path.join(site, 'src/content/docs/404.md'), '---\ntitle: Not on this shelf\n---\n\nThis page does not exist. Open the [operator docs](/docs/) or return to [Bodega home](/).\n');
}

export async function prepareAssets() {
  const destination = path.join(site, 'public/assets');
  await mkdir(destination, { recursive: true });
  await cp(path.join(root, 'assets/emblem/emblem-512.png'), path.join(destination, 'depot.png'));
  await cp(path.join(root, 'assets/favicon.ico'), path.join(destination, 'favicon.ico'));
  for (const file of await readdir(path.join(root, 'docs/images'))) {
    await cp(path.join(root, 'docs/images', file), path.join(destination, file));
  }
}

export function prepareCoverage() {
  const { coverageReport } = readBuildConfig();
  if (!coverageReport) throw new Error('Set coverage_report in the local site config or BODEGA_COVERAGE_REPORT.');
  execFileSync('python3', [path.join(site, 'scripts/coverage.py'),
    coverageReport,
    path.join(site, 'public/data/coverage.json')], { stdio: 'inherit' });
}

await prepareDocs();
await prepareAssets();
prepareCoverage();
