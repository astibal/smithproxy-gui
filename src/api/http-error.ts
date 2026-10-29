const REQUEST_ID = /^[0-9a-f]{1,32}-[1-9][0-9]{0,19}$/u;

export function httpStatusError(response: Response, service: string): Error {
  const supplied = response.headers.get('X-Request-ID');
  const reference = supplied && REQUEST_ID.test(supplied) ? ` Request ${supplied}.` : '';
  return new Error(`${service} returned HTTP ${response.status}.${reference}`);
}
