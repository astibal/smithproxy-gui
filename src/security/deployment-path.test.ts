import {describe, expect, it} from 'vitest';
import {normalizeSameOriginPath, requireApiBelowMount} from './deployment-path';

describe('deployment path confinement', () => {
  it('canonicalizes trusted same-origin paths', () => {
    expect(normalizeSameOriginPath('/ws001//smithproxy-gui/', 'Base path'))
      .toBe('/ws001/smithproxy-gui');
  });

  it.each([
    'https://attacker.invalid/api',
    '//attacker.invalid/api',
    '/ws001/../admin',
    '/ws001/%2e%2e/admin',
    '/ws001/%2Fadmin',
    '/ws001/%5cadmin',
    '/ws001/%252e%252e/admin',
    '/ws001/api?redirect=/admin',
    '/ws001/api#admin',
    '/ws001/unsafe path',
  ])('rejects a path that could escape or change routing: %s', path => {
    expect(() => normalizeSameOriginPath(path, 'API base')).toThrow();
  });

  it('requires the API to remain below a non-root mount', () => {
    expect(() => requireApiBelowMount(
      '/ws001/smithproxy-gui/api/v1', '/ws001/smithproxy-gui',
    )).not.toThrow();
    expect(() => requireApiBelowMount('/ws001/admin/api/v1', '/ws001/smithproxy-gui'))
      .toThrow('below the application mount');
  });

  it('allows a non-root API below the origin root mount', () => {
    expect(() => requireApiBelowMount('/api/v1', '/')).not.toThrow();
    expect(() => requireApiBelowMount('/', '/')).toThrow('below the application mount');
  });
});
