import {readdir, readFile} from 'node:fs/promises';

const output = new URL('../dist/', import.meta.url);
const files = await readdir(output, {recursive: true});
const sourceMaps = files.filter(file => file.endsWith('.map'));
if (sourceMaps.length > 0) {
  throw new Error(`Production source maps are forbidden: ${sourceMaps.join(', ')}`);
}

const assets = files.filter(file => /^assets\/.*\.(?:css|js)$/u.test(file));
if (assets.length === 0) {
  throw new Error('The production build contains no JavaScript or CSS assets.');
}
const unfingerprinted = assets.filter(file => !/-[A-Za-z0-9_-]{8,}\.(?:css|js)$/u.test(file));
if (unfingerprinted.length > 0) {
  throw new Error(`Production assets must be fingerprinted: ${unfingerprinted.join(', ')}`);
}

const entrypoint = await readFile(new URL('index.html', output), 'utf8');
for (const asset of assets) {
  if (!entrypoint.includes(`./${asset}`)) {
    throw new Error(`Production entry point does not reference ${asset}.`);
  }
}
