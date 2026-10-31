import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import { readBuildConfig } from './scripts/config.mjs';

export const siteURL = readBuildConfig().siteURL;
export const navigation = [
  { label: 'Bodega home', link: '/' },
  { label: 'Documentation home', link: '/docs/' },
  { label: 'Package support', link: '/coverage/' },
  { label: 'Install & deploy', items: [
    { label: 'Quick start', link: '/docs/quickstart/' },
    ...['Platforms', 'Configuration', 'Running under systemd', 'Running under rc.d', 'HTTP Server'].map(label => ({ label, link: `/docs/operator/${label.toLowerCase().replace(/\./g, '').replace(/ /g, '-')}/` })),
  ] },
  { label: 'Packages & storage', items: ['Manifest Structure', 'Pipeline', 'Proxy/Cache', 'Storage Layout', 'Checksum Verification', 'Manifest Integrity'].map(label => ({ label, link: `/docs/operator/${label.toLowerCase().replace(/\//g, '').replace(/ /g, '-')}/` })) },
  { label: 'Policy & identity', items: [
    ...['Authentication', 'Supply Chain Management', 'Attestations', 'Integrations'].map(label => ({ label, link: `/docs/operator/${label.toLowerCase().replace(/ /g, '-')}/` })),
    { label: 'Threat model', link: '/docs/threat-model/' },
    { label: 'SLSA', link: '/docs/slsa/' },
    { label: 'Security', link: '/docs/security/' },
  ] },
  { label: 'Daily operations', items: [
    { label: 'Operations runbook', link: '/docs/runbook/' },
    ...['Audit Trail', 'Inventory', 'TUI', 'Web Dashboard'].map(label => ({ label, link: `/docs/operator/${label.toLowerCase().replace(/ /g, '-')}/` })),
  ] },
  { label: 'Quarantine a release', items: [{ label: 'Overview', link: '/docs/quarantine/' }, { label: 'CLI workflow', link: '/docs/quarantine/cli/' }, { label: 'TUI workflow', link: '/docs/quarantine/tui/' }, { label: 'API workflow', link: '/docs/quarantine/api/' }] },
  { label: 'Reference', items: ['Commands', 'Global Flags', 'REST API'].map(label => ({ label, link: `/docs/operator/${label.toLowerCase().replace(/ /g, '-')}/` })) },
  { label: 'Project', items: [{ label: 'Architecture', link: '/docs/design/' }, { label: 'Contributing', link: '/docs/contributing/' }, { label: 'Development', link: '/docs/operator/development/' }, { label: 'Full operations reference', link: '/docs/usage/' }] },
];
export default defineConfig({
  site: siteURL,
  trailingSlash: 'always',
  integrations: [starlight({
    title: 'bodega',
    favicon: '/assets/favicon.ico',
    logo: { src: '../assets/emblem/emblem-256.png', replacesTitle: false },
    social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/ravinald/bodega' }],
    sidebar: navigation,
    customCss: ['./src/styles/docs.css'],
  })],
});
