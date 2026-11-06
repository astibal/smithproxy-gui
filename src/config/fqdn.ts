export interface FqdnInfo {
  normalized: string;
  labels: number;
  absolute: boolean;
}

function isIpv4Literal(value: string): boolean {
  const pieces = value.split('.');
  return pieces.length === 4 && pieces.every(piece => {
    if (!/^\d{1,3}$/u.test(piece)) return false;
    const number = Number(piece);
    return number <= 255 && String(number) === piece;
  });
}

export function parseFqdn(value: string): FqdnInfo | undefined {
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > 254) return undefined;
  const absolute = trimmed.endsWith('.');
  const normalized = (absolute ? trimmed.slice(0, -1) : trimmed).toLowerCase();
  if (normalized.length === 0 || normalized.length > 253 || isIpv4Literal(normalized)) {
    return undefined;
  }
  const labels = normalized.split('.');
  if (labels.some(label => label.length === 0 || label.length > 63 ||
      !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/u.test(label))) {
    return undefined;
  }
  return {normalized, labels: labels.length, absolute};
}

export function describeFqdn(value: string): string | undefined {
  const info = parseFqdn(value);
  if (!info) return undefined;
  const labelWord = info.labels === 1 ? 'label' : 'labels';
  const form = info.absolute ? 'absolute name' : 'host name';
  return `Valid DNS ${form} · ${info.labels} ${labelWord} · ${info.normalized}`;
}
