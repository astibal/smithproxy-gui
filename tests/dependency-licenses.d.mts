export interface LicenseComponent {
  name: string;
  version: string;
  license: string;
}

export const allowedLicenses: ReadonlySet<string>;
export function normalizeLicenseInventory(report: unknown): LicenseComponent[];
export function buildCycloneDxBom(
  components: ReadonlyArray<LicenseComponent>,
  application?: {name: string; version: string},
): {
  bomFormat: 'CycloneDX';
  specVersion: '1.5';
  serialNumber: string;
  version: 1;
  metadata: object;
  components: object[];
};
