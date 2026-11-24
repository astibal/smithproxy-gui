const REQUEST_ID = /^[0-9a-f]{1,32}-[1-9][0-9]{0,19}$/u;

export class HttpStatusError extends Error {
  readonly status: number;
  readonly requestId: string | undefined;

  constructor(service: string, status: number, requestId?: string) {
    super(`${service} returned HTTP ${status}.${requestId ? ` Request ${requestId}.` : ''}`);
    this.name = 'HttpStatusError';
    this.status = status;
    this.requestId = requestId;
  }
}

export function httpStatusError(response: Response, service: string): HttpStatusError {
  const supplied = response.headers.get('X-Request-ID');
  const requestId = supplied && REQUEST_ID.test(supplied) ? supplied : undefined;
  return new HttpStatusError(service, response.status, requestId);
}

export function isHttpStatusError(error: unknown, status: number): error is HttpStatusError {
  return error instanceof HttpStatusError && error.status === status;
}
