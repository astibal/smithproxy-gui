import {describe, expect, it} from 'vitest';
import {runtimePathsFromBaseUri} from './runtime-config';

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
});
