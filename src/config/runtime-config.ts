export type ApplicationMode = 'standalone' | 'embedded';

export interface RuntimeConfig {
  apiBase: string;
  basePath: string;
  mode: ApplicationMode;
}
function metaContent(name: string): string | undefined {
  return document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`)?.content || undefined;
}

export function runtimePathsFromBaseUri(baseUri: string): Pick<RuntimeConfig, 'apiBase' | 'basePath'> {
  const directory = new URL('.', baseUri).pathname;
  const basePath = directory === '/' ? '/' : directory.replace(/\/+$/u, '');
  return {
    basePath,
    apiBase: basePath === '/' ? '/api/v1' : `${basePath}/api/v1`,
  };
}

export function readRuntimeConfig(host: HTMLElement): RuntimeConfig {
  const mode = host.getAttribute('mode') === 'embedded' ? 'embedded' : 'standalone';
  const inferred = runtimePathsFromBaseUri(document.baseURI);
  const basePath = host.getAttribute('base-path') || metaContent('smithproxy-base-path') || inferred.basePath;
  return {
    mode,
    apiBase: host.getAttribute('api-base') || metaContent('smithproxy-api-base') ||
      (basePath === '/' ? '/api/v1' : `${basePath.replace(/\/+$/u, '')}/api/v1`),
    basePath,
  };
}
