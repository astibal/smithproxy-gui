import {describe, expect, it} from 'vitest';
import {httpStatusError} from './http-error';

describe('httpStatusError', () => {
  it('includes a validated server request reference', () => {
    const response = new Response('', {
      status: 503,
      headers: {'X-Request-ID': 'a1b2c3-42'},
    });
    expect(httpStatusError(response, 'System API').message)
      .toBe('System API returned HTTP 503. Request a1b2c3-42.');
  });

  it('does not reflect malformed request references', () => {
    const response = new Response('', {
      status: 401,
      headers: {'X-Request-ID': 'unsafe request value'},
    });
    expect(httpStatusError(response, 'Draft API').message).toBe('Draft API returned HTTP 401.');
  });
});
