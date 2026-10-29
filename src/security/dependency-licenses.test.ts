import {describe, expect, it} from 'vitest';
import {buildCycloneDxBom, normalizeLicenseInventory} from '../../tests/dependency-licenses.mjs';

describe('dependency license policy', () => {
  it('normalizes approved packages and emits a deterministic CycloneDX inventory', () => {
    const report = {
      MIT: [{name: 'example', versions: ['2.0.0', '1.0.0']}],
      'Apache-2.0': [{name: '@scope/tool', versions: ['3.0.0']}],
    };
    const components = normalizeLicenseInventory(report);
    const application = {name: 'test-application', version: '1.2.3'};
    const first = buildCycloneDxBom(components, application);
    const second = buildCycloneDxBom(components, application);
    const nextVersion = buildCycloneDxBom(components, {...application, version: '1.2.4'});

    expect(first).toEqual(second);
    expect(nextVersion.serialNumber).not.toBe(first.serialNumber);
    expect(first.metadata).toEqual({
      component: expect.objectContaining({name: 'test-application', version: '1.2.3'}),
    });
    expect(first.serialNumber).toMatch(/^urn:uuid:[0-9a-f-]{36}$/u);
    expect(first.components).toEqual([
      expect.objectContaining({name: '@scope/tool', purl: 'pkg:npm/%40scope/tool@3.0.0'}),
      expect.objectContaining({name: 'example', version: '1.0.0'}),
      expect.objectContaining({name: 'example', version: '2.0.0'}),
    ]);
  });

  it('rejects unapproved, conflicting, empty, and malformed inventories', () => {
    expect(() => normalizeLicenseInventory({GPL: [{name: 'bad', versions: ['1']}]}))
      .toThrow('Dependency license is not approved');
    expect(() => normalizeLicenseInventory({MIT: [{name: 'same', versions: ['1']}], ISC: [{name: 'same', versions: ['1']}]}))
      .toThrow('reports conflicting licenses');
    expect(() => normalizeLicenseInventory({})).toThrow('inventory is empty');
    expect(() => normalizeLicenseInventory({MIT: [{name: '', versions: []}]}))
      .toThrow('Invalid dependency metadata');
  });
});
