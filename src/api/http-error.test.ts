import {describe, expect, it} from 'vitest';
import {HttpStatusError, httpStatusError, isHttpStatusError} from './http-error';

describe('httpStatusError', () => {
  it('includes a validated server request reference', () => {
    const response = new Response('', {
      status: 503,
      headers: {'X-Request-ID': 'a1b2c3-42'},
    });
    const error = httpStatusError(response, 'System API');
    expect(error).toBeInstanceOf(HttpStatusError);
    expect(error.message).toBe('System API returned HTTP 503. Request a1b2c3-42.');
    expect(error.status).toBe(503);
    expect(error.requestId).toBe('a1b2c3-42');
    expect(isHttpStatusError(error, 503)).toBe(true);
    expect(isHttpStatusError(error, 409)).toBe(false);
  });

  it('does not reflect malformed request references', () => {
    const response = new Response('', {
      status: 401,
      headers: {'X-Request-ID': 'unsafe request value'},
    });
    const error = httpStatusError(response, 'Draft API');
    expect(error.message).toBe('Draft API returned HTTP 401.');
    expect(error.requestId).toBeUndefined();
  });
});
