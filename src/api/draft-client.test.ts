import {describe, expect, it, vi} from 'vitest';
import {DraftClient} from './draft-client';

function response(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {status, headers: {'Content-Type': 'application/json'}});
}

describe('DraftClient', () => {
  it('loads and updates a versioned workspace draft', async () => {
    const fetcher = vi.fn()
      .mockResolvedValueOnce(response({id: 'workspace-draft', base_revision: null, version: 0, changes: []}))
      .mockResolvedValueOnce(response({
        id: 'workspace-draft', base_revision: null, version: 1,
        changes: [{path: 'policy.[0].action', value: 'accept'}],
      }));
    const client = new DraftClient('/ws001/smithproxy-gui/api/v1/', fetcher);

    await expect(client.load()).resolves.toMatchObject({version: 0, changes: []});
    await expect(client.upsert(0, 'policy.[0].action', 'accept')).resolves.toMatchObject({
      version: 1, changes: [{path: 'policy.[0].action', value: 'accept'}],
    });
    expect(fetcher).toHaveBeenLastCalledWith(
      '/ws001/smithproxy-gui/api/v1/config/draft/changes',
      expect.objectContaining({
        method: 'POST', credentials: 'same-origin',
        headers: expect.objectContaining({'X-Smithproxy-GUI-CSRF': '1'}),
      }),
    );
    const request = fetcher.mock.calls.at(-1)?.[1] as RequestInit;
    expect(JSON.parse(String(request.body))).toEqual({
      expected_version: 0,
      changes: [{path: 'policy.[0].action', value: 'accept'}],
    });
  });

  it('validates and sends atomic batches including string arrays', async () => {
    const fetcher = vi.fn().mockResolvedValue(response({
      id: 'workspace-draft', base_revision: null, version: 1,
      changes: [
        {path: 'policy.[0].name', value: 'office'},
        {path: 'policy.[0].dst', value: ['internet', 'backup']},
      ],
    }));
    const client = new DraftClient('/api/v1', fetcher);
    await expect(client.upsertMany(0, [
      {path: 'policy.[0].name', value: 'office'},
      {path: 'policy.[0].dst', value: ['internet', 'backup']},
    ])).resolves.toMatchObject({version: 1});
    await expect(client.upsertMany(1, [])).rejects.toThrow('Invalid draft changes');
    await expect(client.upsertMany(1, [
      {path: 'policy.[0].name', value: 'one'},
      {path: 'policy.[0].name', value: 'two'},
    ])).rejects.toThrow('Invalid draft path');
  });

  it('clears a draft with optimistic concurrency headers', async () => {
    const fetcher = vi.fn().mockResolvedValue(response({
      id: 'workspace-draft', base_revision: null, version: 4, changes: [],
    }));
    const client = new DraftClient('/api/v1', fetcher);
    await expect(client.clear(3)).resolves.toMatchObject({version: 4, changes: []});
    expect(fetcher).toHaveBeenCalledWith('/api/v1/config/draft/clear', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({expected_version: 3}),
      headers: expect.objectContaining({'X-Smithproxy-GUI-CSRF': '1'}),
    }));
  });

  it('rejects oversized draft responses before parsing', async () => {
    const client = new DraftClient('/api/v1', async () => new Response('{}', {
      headers: {'Content-Length': String(8 * 1024 * 1024 + 1)},
    }));
    await expect(client.load()).rejects.toThrow('size limit');
  });

  it('rejects malformed drafts and stale server responses', async () => {
    const malformed = new DraftClient('/api/v1', async () => response({
      id: 'workspace-draft', base_revision: null, version: 0,
      changes: [{path: '../unsafe', value: true}],
    }));
    await expect(malformed.load()).rejects.toThrow('Invalid draft change');

    const conflict = new DraftClient('/api/v1', async () => response({}, 409));
    await expect(conflict.upsert(2, 'settings.enabled', true)).rejects.toThrow('HTTP 409');
  });

  it('rejects unsafe endpoint configuration', () => {
    expect(() => new DraftClient('https://other.example/api')).toThrow('same-origin');
    expect(() => new DraftClient('/api/../secret')).toThrow('relative path');
  });
});
