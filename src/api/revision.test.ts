import {describe, expect, it} from 'vitest';
import {isConfigRevision, isConfigRevisionOrNull} from './revision';

describe('configuration revision validation', () => {
  it('accepts current random revision identifiers', () => {
    expect(isConfigRevision('89afe0b0ccaad050ce7fca8f78661c35')).toBe(true);
  });

  it('retains compatibility with legacy content-addressed revisions', () => {
    expect(isConfigRevision(`sha256:${'a'.repeat(64)}`)).toBe(true);
  });

  it.each([
    '',
    '89afe0b0ccaad050ce7fca8f78661c3',
    '89afe0b0ccaad050ce7fca8f78661c350',
    '89AFE0B0CCAAD050CE7FCA8F78661C35',
    `sha256:${'a'.repeat(63)}`,
    `sha256:${'A'.repeat(64)}`,
  ])('rejects malformed revision %j', (revision) => {
    expect(isConfigRevision(revision)).toBe(false);
  });

  it('accepts null only through the nullable validator', () => {
    expect(isConfigRevision(null)).toBe(false);
    expect(isConfigRevisionOrNull(null)).toBe(true);
  });
});
