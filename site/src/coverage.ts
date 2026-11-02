export interface Feature { label: string; description: string; value: string; evidence: string; state: string; }
export interface Run { text: string; title: string; class: string; }
export interface PackageEvidence { id: string; verdict: string; reason: string; coverage: string; features: Feature[]; runs: Run[]; }
export interface CoverageReport { schemaVersion: number; revision: string; evaluatedAt: string; summary: string; packages: PackageEvidence[]; }
export const labels: Record<string, [string, string]> = {
  apt: ['APT', 'Debian & Ubuntu'], git: ['Git', 'Repositories & bundles'], pypi: ['Python', 'pip / PyPI'],
  binary: ['Binaries', 'Direct downloads'], gomod: ['Go', 'Go modules'], helm: ['Helm', 'Kubernetes charts'],
  npm: ['npm', 'JavaScript packages'], cargo: ['Cargo', 'Rust crates'], freebsd: ['FreeBSD', 'pkg repositories'],
  distfiles: ['Distfiles', 'FreeBSD ports sources'], rubygems: ['RubyGems', 'Ruby packages'], maven: ['Maven', 'Maven & Gradle'],
  composer: ['Composer', 'PHP packages'], oci: ['OCI', 'Container images'], rpm: ['RPM', 'dnf / yum repositories'],
};
export const verdictClass = (verdict: string) => verdict.toLowerCase().replace(/\s+/g, '-');
export const coverageNumber = (coverage: string) => Math.min(100, Math.max(0, Number.parseInt(coverage) || 0));

export function createPackageRow(pkg: PackageEvidence): HTMLDetailsElement {
  const node = <K extends keyof HTMLElementTagNameMap>(tag: K, text = '', className = '') => {
    const element = document.createElement(tag); element.textContent = text; element.className = className; return element;
  };
  const row = node('details', '', 'package-row');
  row.dataset.manager = pkg.id; row.dataset.verdict = pkg.verdict;
  const summary = node('summary');
  const name = node('span', '', 'package-name');
  const label = labels[pkg.id] || [pkg.id, pkg.id];
  name.append(node('strong', label[0]), node('small', label[1]));
  const badge = node('span', pkg.verdict, `badge ${verdictClass(pkg.verdict)}`);
  const score = node('span', '', 'feature-score');
  score.append(node('span', pkg.coverage));
  const track = node('span', '', 'score-track'); track.setAttribute('aria-hidden', 'true');
  const bar = node('i'); bar.style.width = `${coverageNumber(pkg.coverage)}%`; track.append(bar); score.append(track);
  summary.append(name, badge, score);
  const detail = node('div', '', 'package-detail');
  detail.append(node('p', pkg.reason), node('h3', 'Feature support'));
  const grid = node('div', '', 'feature-grid');
  for (const feature of pkg.features) {
    const entry = node('details', '', 'feature-entry');
    const heading = node('summary'); heading.append(node('span', feature.label), node('strong', feature.value, `feature-${feature.value.replace(/[^a-z]/gi, '')}`));
    entry.append(heading, node('p', feature.description), node('p', feature.evidence || 'No additional evidence recorded.'));
    grid.append(entry);
  }
  detail.append(grid, node('h3', 'Real-client test evidence'));
  const runs = node('div', '', 'test-runs');
  if (!pkg.runs.length) runs.append(node('p', 'No primary suite results recorded. This is not a passing test result.'));
  for (const run of pkg.runs) {
    const entry = node('details', '', `test-run ${run.class}`);
    entry.append(node('summary', run.text + (run.class.includes('stale-run') ? ' · stale evidence' : '')), node('p', run.title));
    runs.append(entry);
  }
  detail.append(runs); row.append(summary, detail); return row;
}
