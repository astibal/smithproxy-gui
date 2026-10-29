export async function boundedJson(
  response: Response,
  maximumBytes: number,
  responseName: string,
): Promise<unknown> {
  const declaredLength = response.headers.get('Content-Length');
  if (declaredLength !== null &&
      (!/^\d+$/u.test(declaredLength) || Number(declaredLength) > maximumBytes)) {
    throw new Error(`${responseName} response exceeded the size limit.`);
  }
  if (!response.body) {
    try {
      return JSON.parse(await response.text()) as unknown;
    } catch {
      throw new Error(`${responseName} API returned invalid JSON.`);
    }
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', {fatal: true});
  let size = 0;
  let payload = '';
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maximumBytes) {
        try {
          await reader.cancel();
        } catch {
          // Preserve the authoritative size-limit failure if transport cancellation also fails.
        }
        throw new Error(`${responseName} response exceeded the size limit.`);
      }
      payload += decoder.decode(value, {stream: true});
    }
    payload += decoder.decode();
    return JSON.parse(payload) as unknown;
  } catch (error) {
    if (error instanceof Error && error.message.includes('size limit')) throw error;
    throw new Error(`${responseName} API returned invalid JSON.`);
  } finally {
    reader.releaseLock();
  }
}
