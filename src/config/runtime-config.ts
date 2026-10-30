import {normalizeSameOriginPath, requireApiBelowMount} from '../security/deployment-path';

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
  const basePath = normalizeSameOriginPath(directory, 'Base path');
  return {
    basePath,
    apiBase: basePath === '/' ? '/api/v1' : `${basePath}/api/v1`,
  };
}

export function readRuntimeConfig(host: HTMLElement): RuntimeConfig {
  const mode = host.getAttribute('mode') === 'embedded' ? 'embedded' : 'standalone';
  const inferred = runtimePathsFromBaseUri(document.baseURI);
  const basePath = normalizeSameOriginPath(
    host.getAttribute('base-path') || metaContent('smithproxy-base-path') || inferred.basePath,
    'Base path',
  );
  const apiBase = normalizeSameOriginPath(
    host.getAttribute('api-base') || metaContent('smithproxy-api-base') ||
      (basePath === '/' ? '/api/v1' : `${basePath}/api/v1`),
    'API base',
  );
  requireApiBelowMount(apiBase, basePath);
  return {
    mode,
    apiBase,
    basePath,
  };
}
