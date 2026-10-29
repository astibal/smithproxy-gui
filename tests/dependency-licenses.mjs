import {createHash} from 'node:crypto';
import {readFileSync, writeFileSync} from 'node:fs';
import {spawnSync} from 'node:child_process';
import {pathToFileURL} from 'node:url';

export const allowedLicenses = new Set([
  'Apache-2.0',
  'BSD-3-Clause',
  'ISC',
  'MIT',
  'MPL-2.0',
]);

function packageUrl(name, version) {
  const encodedName = name.startsWith('@')
    ? `%40${name.slice(1).split('/').map(encodeURIComponent).join('/')}`
    : encodeURIComponent(name);
  return `pkg:npm/${encodedName}@${encodeURIComponent(version)}`;
}

export function normalizeLicenseInventory(report) {
  if (typeof report !== 'object' || report === null || Array.isArray(report)) {
    throw new Error('pnpm returned an invalid license inventory.');
  }
  const components = new Map();
  for (const [license, packages] of Object.entries(report)) {
    if (!allowedLicenses.has(license)) throw new Error(`Dependency license is not approved: ${license}`);
    if (!Array.isArray(packages)) throw new Error(`Invalid package list for license ${license}.`);
    for (const item of packages) {
      if (typeof item !== 'object' || item === null || typeof item.name !== 'string' ||
          item.name.length === 0 || !Array.isArray(item.versions) || item.versions.length === 0) {
        throw new Error(`Invalid dependency metadata for license ${license}.`);
      }
      for (const version of item.versions) {
        if (typeof version !== 'string' || version.length === 0) {
          throw new Error(`Invalid dependency version for ${item.name}.`);
        }
        const key = `${item.name}@${version}`;
        const existing = components.get(key);
        if (existing && existing.license !== license) {
          throw new Error(`Dependency ${key} reports conflicting licenses.`);
        }
        components.set(key, {name: item.name, version, license});
      }
    }
  }
  if (components.size === 0) throw new Error('Dependency license inventory is empty.');
  return [...components.values()].sort((left, right) =>
    left.name < right.name ? -1 : left.name > right.name ? 1 :
      left.version < right.version ? -1 : left.version > right.version ? 1 : 0);
}

function deterministicUuid(value) {
  const bytes = Buffer.from(createHash('sha256').update(value).digest().subarray(0, 16));
  bytes[6] = (bytes[6] & 0x0f) | 0x50;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function buildCycloneDxBom(components, application = {name: 'smithproxy-gui', version: '0.0.0'}) {
  const normalized = components.map(component => {
    const purl = packageUrl(component.name, component.version);
    return {
      type: 'library',
      'bom-ref': purl,
      name: component.name,
      version: component.version,
      licenses: [{license: {id: component.license}}],
      purl,
    };
  });
  const fingerprint = JSON.stringify({application, components: normalized});
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.5',
    serialNumber: `urn:uuid:${deterministicUuid(fingerprint)}`,
    version: 1,
    metadata: {
      component: {
        type: 'application',
        'bom-ref': application.name,
        name: application.name,
        version: application.version,
      },
    },
    components: normalized,
  };
}

function readPnpmInventory() {
  const result = spawnSync('pnpm', ['licenses', 'list', '--json'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
    timeout: 30_000,
  });
  if (result.error) throw result.error;
  if (result.status !== 0) throw new Error(result.stderr.trim() || 'pnpm license inventory failed.');
  return JSON.parse(result.stdout);
}

function outputPath(arguments_) {
  const index = arguments_.indexOf('--output');
  if (index < 0) {
    if (arguments_.length > 0) throw new Error('Usage: dependency-licenses.mjs [--output <path>]');
    return undefined;
  }
  if (index + 2 !== arguments_.length || arguments_[index + 1].length === 0) {
    throw new Error('Usage: dependency-licenses.mjs [--output <path>]');
  }
  return arguments_[index + 1];
}

function main() {
  const components = normalizeLicenseInventory(readPnpmInventory());
  const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
  if (manifest.name !== 'smithproxy-gui' || typeof manifest.version !== 'string' || manifest.version.length === 0) {
    throw new Error('package.json contains an invalid application identity.');
  }
  const bom = buildCycloneDxBom(components, {name: manifest.name, version: manifest.version});
  const target = outputPath(process.argv.slice(2));
  if (target) writeFileSync(target, `${JSON.stringify(bom, null, 2)}\n`, {encoding: 'utf8', mode: 0o644});
  process.stdout.write(`Verified ${components.length} dependency components across ${allowedLicenses.size} approved licenses.\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
