/**
 * Keeps short reference lists directly readable while bounding dense table rows.
 * Two or three related objects are useful information, not overflow.
 */
export function referenceNameSummary(names: ReadonlyArray<string>): string {
  if (names.length === 0) return 'None';
  if (names.length <= 3) return names.join(', ');
  return `${names.slice(0, 2).join(', ')} +${names.length - 2}`;
}
