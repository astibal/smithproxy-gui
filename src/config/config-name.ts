export function isConfigGroupName(value: string): boolean {
  return /^[A-Za-z_][A-Za-z0-9_-]{0,127}$/u.test(value);
}
