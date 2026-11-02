import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import os from 'node:os';

export const defaultConfigPath = fileURLToPath(new URL('../../docs-internal/site-deploy.json', import.meta.url));

export function resolveConfigPath(value, directory) {
  if (value.startsWith('~/')) return path.join(os.homedir(), value.slice(2));
  return path.resolve(directory, value);
}

export function readBuildConfig() {
  const configPath = path.resolve(process.env.BODEGA_SITE_CONFIG || defaultConfigPath);
  if (process.env.BODEGA_SITE_CONFIG && !existsSync(configPath)) throw new Error('BODEGA_SITE_CONFIG does not exist.');
  const config = existsSync(configPath) ? JSON.parse(readFileSync(configPath, 'utf8')) : {};
  const siteURL = process.env.BODEGA_SITE_URL || config.site_url || 'http://localhost:4321';
  const url = new URL(siteURL);
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.pathname !== '/' || url.search || url.hash) {
    throw new Error('site_url must be an HTTP(S) origin without credentials, a path, query, or fragment.');
  }
  const report = process.env.BODEGA_COVERAGE_REPORT || config.coverage_report;
  return { siteURL: url.origin, coverageReport: report ? resolveConfigPath(report, path.dirname(configPath)) : undefined };
}
