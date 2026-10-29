import {afterEach, describe, expect, it, vi} from 'vitest';
import {readRuntimeConfig, runtimePathsFromBaseUri} from './runtime-config';

function host(attributes: Readonly<Record<string, string>> = {}): HTMLElement {
  return {
    getAttribute: (name: string) => attributes[name] ?? null,
  } as HTMLElement;
}

function stubDocument(baseURI: string, meta: Readonly<Record<string, string>> = {}): void {
  vi.stubGlobal('document', {
    baseURI,
    querySelector: (selector: string) => {
      const match = /^meta\[name="([^"]+)"\]$/u.exec(selector);
      const content = match ? meta[match[1]!] : undefined;
      return content === undefined ? null : {content};
    },
  });
}

afterEach(() => vi.unstubAllGlobals());

describe('runtime deployment paths', () => {
  it('keeps standalone development at the origin root', () => {
    expect(runtimePathsFromBaseUri('http://127.0.0.1:4173/')).toEqual({
      basePath: '/',
      apiBase: '/api/v1',
    });
  });

  it('derives the API below a workspace mount', () => {
    expect(runtimePathsFromBaseUri('https://saslik.example/ws001/smithproxy-gui/')).toEqual({
      basePath: '/ws001/smithproxy-gui',
      apiBase: '/ws001/smithproxy-gui/api/v1',
    });
  });

  it('reads an inferred standalone runtime configuration', () => {
    stubDocument('http://127.0.0.1:4173/');

    expect(readRuntimeConfig(host())).toEqual({
      mode: 'standalone',
      basePath: '/',
      apiBase: '/api/v1',
    });
  });

  it('uses deployment metadata below a workspace prefix', () => {
    stubDocument('https://saslik.example/fallback/', {
      'smithproxy-base-path': '/ws001/smithproxy-gui/',
      'smithproxy-api-base': '/ws001/smithproxy-gui/internal/api/v1',
    });

    expect(readRuntimeConfig(host({mode: 'embedded'}))).toEqual({
      mode: 'embedded',
      basePath: '/ws001/smithproxy-gui/',
      apiBase: '/ws001/smithproxy-gui/internal/api/v1',
    });
  });

  it('gives explicit host attributes precedence over metadata', () => {
    stubDocument('https://saslik.example/fallback/', {
      'smithproxy-base-path': '/metadata',
      'smithproxy-api-base': '/metadata/api/v1',
    });

    expect(readRuntimeConfig(host({
      mode: 'embedded',
      'base-path': '/tools/smithproxy/',
      'api-base': '/tools/smithproxy/control/v1',
    }))).toEqual({
      mode: 'embedded',
      basePath: '/tools/smithproxy/',
      apiBase: '/tools/smithproxy/control/v1',
    });
  });

  it('derives an API path from an explicit base path when no override exists', () => {
    stubDocument('https://saslik.example/fallback/');

    expect(readRuntimeConfig(host({'base-path': '/ws002/smithproxy-gui/'}))).toEqual({
      mode: 'standalone',
      basePath: '/ws002/smithproxy-gui/',
      apiBase: '/ws002/smithproxy-gui/api/v1',
    });
  });
});
