const CONFIG_REVISION = /^(?:[0-9a-f]{32}|sha256:[0-9a-f]{64})$/u;

export function isConfigRevision(value: unknown): value is string {
  return typeof value === 'string' && CONFIG_REVISION.test(value);
}

export function isConfigRevisionOrNull(value: unknown): value is string | null {
  return value === null || isConfigRevision(value);
}
