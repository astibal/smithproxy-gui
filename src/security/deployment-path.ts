const SAFE_PATH_SEGMENT = /^[A-Za-z0-9._~!$&'()*+,;=:@-]+$/u;

export function normalizeSameOriginPath(value: string, label: string): string {
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\') || /[?#]/u.test(value)) {
    throw new Error(`${label} must be a same-origin absolute path.`);
  }

  const segments = value.split('/').filter(Boolean);
  if (segments.some(segment => segment === '.' || segment === '..')) {
    throw new Error(`${label} cannot contain relative path segments.`);
  }
  if (segments.some(segment => !SAFE_PATH_SEGMENT.test(segment))) {
    throw new Error(`${label} contains unsafe path characters.`);
  }

  return segments.length === 0 ? '/' : `/${segments.join('/')}`;
}

export function requireApiBelowMount(apiBase: string, basePath: string): void {
  const isBelowMount = basePath === '/'
    ? apiBase !== '/' && apiBase.startsWith('/')
    : apiBase.startsWith(`${basePath}/`);
  if (!isBelowMount) {
    throw new Error('API base must be below the application mount.');
  }
}
