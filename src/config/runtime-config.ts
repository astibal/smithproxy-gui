export type ApplicationMode = 'standalone' | 'embedded';

export interface RuntimeConfig {
  apiBase: string;
  basePath: string;
  mode: ApplicationMode;
}
function metaContent(name: string): string | undefined {
  return document.querySelector<HTMLMetaElement>(`meta[name="${name}"]`)?.content || undefined;
}

export function readRuntimeConfig(host: HTMLElement): RuntimeConfig {
  const mode = host.getAttribute('mode') === 'embedded' ? 'embedded' : 'standalone';
  return {
    mode,
    apiBase: host.getAttribute('api-base') || metaContent('smithproxy-api-base') || '/api/v1',
    basePath: host.getAttribute('base-path') || metaContent('smithproxy-base-path') || '/',
  };
}
