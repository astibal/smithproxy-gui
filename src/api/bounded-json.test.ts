import {describe, expect, it} from 'vitest';
import {boundedJson} from './bounded-json';

describe('boundedJson', () => {
  it('parses UTF-8 split across streamed chunks', async () => {
    const encoded = new TextEncoder().encode('{"value":"ž"}');
    const split = encoded.indexOf(0xc5) + 1;
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoded.slice(0, split));
        controller.enqueue(encoded.slice(split));
        controller.close();
      },
    });

    await expect(boundedJson(new Response(body), 64, 'Test'))
      .resolves.toEqual({value: 'ž'});
  });

  it('handles responses without an exposed body stream', async () => {
    const response = (payload: string) => ({
      headers: new Headers(), body: null, text: async () => payload,
    }) as Response;

    await expect(boundedJson(response('{"fallback":true}'), 64, 'Test'))
      .resolves.toEqual({fallback: true});
    await expect(boundedJson(response('{invalid'), 64, 'Test'))
      .rejects.toThrow('invalid JSON');
  });

  it('cancels a chunked response as soon as the byte limit is crossed', async () => {
    const chunks = [new Uint8Array([1, 2, 3]), new Uint8Array([4, 5, 6])];
    let nextChunk = 0;
    let cancelled = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        const chunk = chunks[nextChunk++];
        if (chunk) controller.enqueue(chunk);
      },
      cancel() { cancelled = true; },
    });

    await expect(boundedJson(new Response(body), 4, 'Test'))
      .rejects.toThrow('size limit');
    expect(cancelled).toBe(true);
  });

  it('preserves the size-limit result when stream cancellation fails', async () => {
    let emitted = false;
    const body = new ReadableStream<Uint8Array>({
      pull(controller) {
        if (!emitted) {
          emitted = true;
          controller.enqueue(new Uint8Array([1, 2, 3]));
        }
      },
      cancel() { throw new Error('transport cancellation failed'); },
    });

    await expect(boundedJson(new Response(body), 2, 'Test'))
      .rejects.toThrow('size limit');
  });

  it('rejects invalid declared lengths, UTF-8, and JSON', async () => {
    await expect(boundedJson(new Response('{}', {
      headers: {'Content-Length': 'unknown'},
    }), 64, 'Test')).rejects.toThrow('size limit');
    await expect(boundedJson(new Response(new Uint8Array([0xff])), 64, 'Test'))
      .rejects.toThrow('invalid JSON');
    await expect(boundedJson(new Response('{invalid'), 64, 'Test'))
      .rejects.toThrow('invalid JSON');
  });
});
