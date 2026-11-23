import {readdir, readFile} from 'node:fs/promises';
import {gzipSync} from 'node:zlib';

const maximumEntrypointGzipBytes = 200 * 1024;
const maximumTotalJavascriptGzipBytes = 300 * 1024;

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
const entryAssets = assets.filter(asset => entrypoint.includes(`./${asset}`));
const reachable = new Set(entryAssets);
let discovered = true;
while (discovered) {
  discovered = false;
  for (const parent of [...reachable].filter(asset => asset.endsWith('.js'))) {
    const source = await readFile(new URL(parent, output), 'utf8');
    for (const asset of assets) {
      const filename = asset.slice('assets/'.length);
      if (!reachable.has(asset) &&
          (source.includes(`./${filename}`) || source.includes(`./${asset}`))) {
        reachable.add(asset);
        discovered = true;
      }
    }
  }
}
const orphaned = assets.filter(asset => !reachable.has(asset));
if (orphaned.length > 0) {
  throw new Error(`Production assets are not reachable from the entry point: ${orphaned.join(', ')}`);
}

const javascriptAssets = assets.filter(asset => asset.endsWith('.js'));
const compressedSizes = new Map(await Promise.all(javascriptAssets.map(async asset => [
  asset,
  gzipSync(await readFile(new URL(asset, output))).byteLength,
])));
const entryJavascriptGzipBytes = entryAssets
  .filter(asset => asset.endsWith('.js'))
  .reduce((total, asset) => total + (compressedSizes.get(asset) ?? 0), 0);
const totalJavascriptGzipBytes = [...compressedSizes.values()]
  .reduce((total, size) => total + size, 0);
if (entryJavascriptGzipBytes > maximumEntrypointGzipBytes) {
  throw new Error(
    `Production entry JavaScript exceeds the ${maximumEntrypointGzipBytes}-byte gzip budget: ` +
    `${entryJavascriptGzipBytes} bytes.`,
  );
}
if (totalJavascriptGzipBytes > maximumTotalJavascriptGzipBytes) {
  throw new Error(
    `Production JavaScript exceeds the ${maximumTotalJavascriptGzipBytes}-byte gzip budget: ` +
    `${totalJavascriptGzipBytes} bytes.`,
  );
}
process.stdout.write(
  `Verified ${assets.length} fingerprinted assets; entry JavaScript ${entryJavascriptGzipBytes} bytes gzip, ` +
  `all JavaScript ${totalJavascriptGzipBytes} bytes gzip.\n`,
);
