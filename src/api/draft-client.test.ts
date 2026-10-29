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

  it('validates and sends atomic batches including typed arrays', async () => {
    const fetcher = vi.fn().mockResolvedValue(response({
      id: 'workspace-draft', base_revision: null, version: 1,
      changes: [
        {path: 'policy.[0].name', value: 'office'},
        {path: 'policy.[0].dst', value: ['internet', 'backup']},
        {path: 'tls_profiles.[0].redirect_warning_ports', value: [443, 44443]},
      ],
    }));
    const client = new DraftClient('/api/v1', fetcher);
    await expect(client.upsertMany(0, [
      {path: 'policy.[0].name', value: 'office'},
      {path: 'policy.[0].dst', value: ['internet', 'backup']},
      {path: 'tls_profiles.[0].redirect_warning_ports', value: [443, 44443]},
    ])).resolves.toMatchObject({version: 1});
    await expect(client.upsertMany(1, [])).rejects.toThrow('Invalid draft changes');
    await expect(client.upsertMany(1, [
      {path: 'policy.[0].name', value: 'one'},
      {path: 'policy.[0].name', value: 'two'},
    ])).rejects.toThrow('Invalid draft path');
    await expect(client.upsertMany(1, [
      {path: 'tls_profiles.[0].redirect_warning_ports', value: [443, '8443'] as never},
    ])).rejects.toThrow('Invalid draft scalar');
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

  it('removes one path from a draft with optimistic concurrency headers', async () => {
    const fetcher = vi.fn().mockResolvedValue(response({
      id: 'workspace-draft', base_revision: null, version: 4, changes: [],
    }));
    const client = new DraftClient('/api/v1', fetcher);
    await expect(client.remove(3, 'policy.[0].action')).resolves.toMatchObject({version: 4, changes: []});
    expect(fetcher).toHaveBeenCalledWith('/api/v1/config/draft/changes/remove', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({expected_version: 3, path: 'policy.[0].action'}),
      headers: expect.objectContaining({'X-Smithproxy-GUI-CSRF': '1'}),
    }));
    await expect(client.remove(4, '../unsafe')).rejects.toThrow('Invalid draft path');
  });

  it('removes a bounded unique path group atomically', async () => {
    const fetcher = vi.fn().mockResolvedValue(response({
      id: 'workspace-draft', base_revision: null, version: 5, changes: [],
    }));
    const client = new DraftClient('/api/v1', fetcher);
    const paths = ['policy.[0].name', 'policy.[0].action'];
    await expect(client.removeMany(4, paths)).resolves.toMatchObject({version: 5, changes: []});
    expect(fetcher).toHaveBeenCalledWith('/api/v1/config/draft/changes/remove', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({expected_version: 4, paths}),
      headers: expect.objectContaining({'X-Smithproxy-GUI-CSRF': '1'}),
    }));
    await expect(client.removeMany(5, [])).rejects.toThrow('Invalid draft paths');
    await expect(client.removeMany(5, [paths[0]!, paths[0]!])).rejects.toThrow('Invalid draft path');
  });

  it('loads a bounded redacted preflight impact summary', async () => {
    const fetcher = vi.fn().mockResolvedValue(response({
      source: 'gui-core', draft_id: 'workspace-draft', draft_version: 7,
      base_revision: null, change_count: 3, sensitive_change_count: 1,
      schema_validation: 'valid', upstream_validation: 'unavailable',
      validation_available: false, commit_available: false,
      sections: [
        {name: 'policy', change_count: 2, sensitive_change_count: 0},
        {name: 'settings', change_count: 1, sensitive_change_count: 1},
      ],
      blockers: [{
        code: 'upstream.schema_review_required',
        message: 'Smithproxy transaction schemas are not reviewed by this GUI core.',
      }],
    }));
    const client = new DraftClient('/api/v1', fetcher);
    await expect(client.preflight()).resolves.toMatchObject({
      draftVersion: 7, changeCount: 3, sensitiveChangeCount: 1,
      schemaValidation: 'valid', upstreamValidation: 'unavailable',
      validationAvailable: false, commitAvailable: false,
      sections: [{name: 'policy', changeCount: 2}, {name: 'settings', changeCount: 1}],
    });
    expect(fetcher).toHaveBeenCalledWith('/api/v1/config/draft/preflight', expect.objectContaining({
      method: 'GET', credentials: 'same-origin', redirect: 'error',
    }));
  });

  it('requests and validates upstream draft validation without sending draft values', async () => {
    const revision = `sha256:${'1'.repeat(64)}`;
    const fetcher = vi.fn().mockResolvedValue(response({
      source: 'gui-core', draft_id: 'workspace-draft', draft_version: 7,
      base_revision: revision, upstream_validation: 'valid', validated_operations: 3,
      warning_count: 1, restart: 'not-required',
    }));
    const client = new DraftClient('/api/v1', fetcher);
    await expect(client.validate(7)).resolves.toEqual({
      source: 'gui-core', draftId: 'workspace-draft', draftVersion: 7,
      baseRevision: revision, upstreamValidation: 'valid', validatedOperations: 3,
      warningCount: 1, restart: 'not-required',
    });
    expect(fetcher).toHaveBeenCalledWith('/api/v1/config/draft/validate', expect.objectContaining({
      method: 'POST', body: '{"expected_version":7}',
      headers: expect.objectContaining({'X-Smithproxy-GUI-CSRF': '1'}),
    }));
  });

  it('commits only an optimistic draft version and validates the commit receipt', async () => {
    const previousRevision = `sha256:${'1'.repeat(64)}`;
    const revision = `sha256:${'2'.repeat(64)}`;
    const fetcher = vi.fn().mockResolvedValue(response({
      source: 'gui-core', draft_id: 'workspace-draft', committed_draft_version: 7,
      draft_version: 8, previous_revision: previousRevision, revision,
      committed_operations: 3, warning_count: 1, restart: 'required',
      refresh_job_id: 'job-01234567-89ab-4def-8123-456789abcdef',
    }));
    const client = new DraftClient('/api/v1', fetcher);
    await expect(client.commit(7)).resolves.toEqual({
      source: 'gui-core', draftId: 'workspace-draft', committedDraftVersion: 7,
      draftVersion: 8, previousRevision, revision, committedOperations: 3,
      warningCount: 1, restart: 'required',
      refreshJobId: 'job-01234567-89ab-4def-8123-456789abcdef',
    });
    expect(fetcher).toHaveBeenCalledWith('/api/v1/config/draft/commit', expect.objectContaining({
      method: 'POST', body: '{"expected_version":7}',
      headers: expect.objectContaining({'X-Smithproxy-GUI-CSRF': '1'}),
    }));
  });

  it('accepts a commit-ready preflight without blockers', async () => {
    const client = new DraftClient('/api/v1', async () => response({
      source: 'gui-core', draft_id: 'workspace-draft', draft_version: 3,
      base_revision: `sha256:${'1'.repeat(64)}`, change_count: 1, sensitive_change_count: 0,
      schema_validation: 'valid', upstream_validation: 'unavailable',
      validation_available: true, commit_available: true,
      sections: [{name: 'policy', change_count: 1, sensitive_change_count: 0}],
      blockers: [],
    }));
    await expect(client.preflight()).resolves.toMatchObject({
      validationAvailable: true, commitAvailable: true, blockers: [],
    });
  });

  it('rejects malformed upstream validation metadata', async () => {
    const client = new DraftClient('/api/v1', async () => response({
      source: 'gui-core', draft_id: 'workspace-draft', draft_version: 1,
      base_revision: `sha256:${'1'.repeat(64)}`, upstream_validation: 'valid',
      validated_operations: 1, warning_count: 0, restart: 'unknown',
    }));
    await expect(client.validate(1)).rejects.toThrow('Invalid draft validation response');
  });

  it('rejects an unbound or internally inconsistent commit receipt', async () => {
    const revision = `sha256:${'2'.repeat(64)}`;
    const client = new DraftClient('/api/v1', async () => response({
      source: 'gui-core', draft_id: 'workspace-draft', committed_draft_version: 7,
      draft_version: 9, previous_revision: revision, revision,
      committed_operations: 1, warning_count: 0, restart: 'not-required',
      refresh_job_id: null,
    }));
    await expect(client.commit(7)).rejects.toThrow('Invalid draft commit response');
  });

  it.each([
    ['upstream.transaction_unavailable', null],
    ['upstream.transaction_incompatible', null],
    ['draft.base_revision_unavailable', null],
    ['gui.commit_transport_unavailable', `sha256:${'1'.repeat(64)}`],
  ])('accepts the stable %s preflight blocker', async (code, baseRevision) => {
    const client = new DraftClient('/api/v1', async () => response({
      source: 'gui-core', draft_id: 'workspace-draft', draft_version: 1,
      base_revision: baseRevision, change_count: 1, sensitive_change_count: 0,
      schema_validation: 'valid', upstream_validation: 'unavailable',
      validation_available: code === 'gui.commit_transport_unavailable', commit_available: false,
      sections: [{name: 'policy', change_count: 1, sensitive_change_count: 0}],
      blockers: [{code, message: 'Fixed core diagnostic.'}],
    }));
    await expect(client.preflight()).resolves.toMatchObject({
      blockers: [{code}], baseRevision,
    });
  });

  it('rejects an available validation transport without a canonical base revision', async () => {
    const client = new DraftClient('/api/v1', async () => response({
      source: 'gui-core', draft_id: 'workspace-draft', draft_version: 1,
      base_revision: null, change_count: 1, sensitive_change_count: 0,
      schema_validation: 'valid', upstream_validation: 'unavailable',
      validation_available: true, commit_available: false,
      sections: [{name: 'policy', change_count: 1, sensitive_change_count: 0}],
      blockers: [{code: 'gui.commit_transport_unavailable', message: 'Blocked.'}],
    }));
    await expect(client.preflight()).rejects.toThrow('Inconsistent draft preflight');
  });

  it('rejects inconsistent or unbounded preflight summaries', async () => {
    const client = new DraftClient('/api/v1', async () => response({
      source: 'gui-core', draft_id: 'workspace-draft', draft_version: 1,
      base_revision: null, change_count: 2, sensitive_change_count: 0,
      schema_validation: 'valid', upstream_validation: 'unavailable',
      validation_available: false, commit_available: false,
      sections: [{name: 'policy', change_count: 1, sensitive_change_count: 0}],
      blockers: [{code: 'upstream.transaction_unavailable', message: 'Blocked.'}],
    }));
    await expect(client.preflight()).rejects.toThrow('Inconsistent draft preflight');
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

    const malformedRevision = new DraftClient('/api/v1', async () => response({
      id: 'workspace-draft', base_revision: 'revision-7', version: 0, changes: [],
    }));
    await expect(malformedRevision.load()).rejects.toThrow('Invalid draft response');

    const conflict = new DraftClient('/api/v1', async () => response({}, 409));
    await expect(conflict.upsert(2, 'settings.enabled', true)).rejects.toThrow('HTTP 409');
  });

  it('rejects unsafe endpoint configuration', () => {
    expect(() => new DraftClient('https://other.example/api')).toThrow('same-origin');
    expect(() => new DraftClient('/api/../secret')).toThrow('relative path');
  });

  it('cancels all in-flight draft requests', async () => {
    const signals: AbortSignal[] = [];
    const fetcher = vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
      const signal = init?.signal;
      if (signal) signals.push(signal);
      return new Promise<Response>((_resolve, reject) => {
        signal?.addEventListener('abort', () => reject(new Error('request cancelled')), {once: true});
      });
    });
    const client = new DraftClient('/api/v1', fetcher);
    const load = client.load();
    const preflight = client.preflight();

    client.cancelPendingRequests();

    expect(signals).toHaveLength(2);
    expect(signals.every(signal => signal.aborted)).toBe(true);
    await expect(load).rejects.toThrow('request cancelled');
    await expect(preflight).rejects.toThrow('request cancelled');
  });
});
