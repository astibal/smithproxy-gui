const CANONICAL_REVISION = /^sha256:[0-9a-f]{64}$/u;

export function isCanonicalRevision(value: unknown): value is string {
  return typeof value === 'string' && CANONICAL_REVISION.test(value);
}

export function isCanonicalRevisionOrNull(value: unknown): value is string | null {
  return value === null || isCanonicalRevision(value);
}
