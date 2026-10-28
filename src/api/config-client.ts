import type {
  AddressObject,
  ConfigClient,
  ConfigReference,
  ConfigSnapshot,
  ConfigUsage,
  PolicySummary,
  PortObject,
  ProfileObject,
  ProtocolObject,
} from './models';

type JsonObject = Record<string, unknown>;
type Usage = ConfigUsage;
type MutableAddress = Omit<AddressObject, 'usedBy'> & {usedBy: Usage[]};
type MutablePort = Omit<PortObject, 'usedBy'> & {usedBy: Usage[]};
type MutableProtocol = Omit<ProtocolObject, 'usedBy'> & {usedBy: Usage[]};
type MutableProfile = Omit<ProfileObject, 'usedBy'> & {usedBy: Usage[]};

const MAX_POLICIES = 4096;
const MAX_OBJECTS = 4096;
const MAX_REFERENCES = 256;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

function isObject(value: unknown): value is JsonObject {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function safeString(value: unknown, label: string, maximum = 1024): string {
  if (typeof value !== 'string' || value.length === 0 || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  return value;
}

function optionalString(value: unknown, label: string, maximum = 128): string {
  if (typeof value !== 'string' || value.length > maximum || /[\u0000-\u001f\u007f]/u.test(value)) {
    throw new Error(`Invalid ${label}.`);
  }
  return value;
}

function safeInteger(value: unknown, label: string, maximum: number): number {
  if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0 || value > maximum) {
    throw new Error(`Invalid ${label}.`);
  }
  return value;
}

function safeBoolean(value: unknown, label: string): boolean {
  if (typeof value !== 'boolean') throw new Error(`Invalid ${label}.`);
  return value;
}

function nullableInteger(value: unknown, label: string): number | null {
  return value === null ? null : safeInteger(value, label, Number.MAX_SAFE_INTEGER);
}

function boundedArray(value: unknown, label: string, maximum: number): unknown[] {
  if (!Array.isArray(value) || value.length > maximum) throw new Error(`Invalid ${label}.`);
  return value;
}

function stringArray(value: unknown, label: string): string[] {
  return boundedArray(value, label, MAX_REFERENCES).map(item => safeString(item, label, 128));
}

function normalizedPath(value: string): string {
  if (!value.startsWith('/') || value.startsWith('//') || value.includes('\\') || /[?#]/u.test(value)) {
    throw new Error('API base must be a same-origin absolute path.');
  }
  const segments = value.split('/').filter(Boolean);
  if (segments.some(segment => segment === '.' || segment === '..')) {
    throw new Error('API base cannot contain relative path segments.');
  }
  return segments.length === 0 ? '/' : `/${segments.join('/')}`;
}

async function boundedJson(response: Response): Promise<unknown> {
  const declaredLength = response.headers.get('Content-Length');
  if (declaredLength !== null && (!/^\d+$/u.test(declaredLength) || Number(declaredLength) > MAX_RESPONSE_BYTES)) {
    throw new Error('Configuration response exceeded the size limit.');
  }
  if (!response.body) return JSON.parse(await response.text()) as unknown;

  const reader = response.body.getReader();
  const decoder = new TextDecoder('utf-8', {fatal: true});
  let size = 0;
  let text = '';
  try {
    while (true) {
      const {done, value} = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error('Configuration response exceeded the size limit.');
      }
      text += decoder.decode(value, {stream: true});
    }
    text += decoder.decode();
    return JSON.parse(text) as unknown;
  } catch (error) {
    if (error instanceof Error && error.message.includes('size limit')) throw error;
    throw new Error('Configuration API returned invalid JSON.');
  } finally {
    reader.releaseLock();
  }
}

function parseAddress(value: unknown): MutableAddress {
  if (!isObject(value)) throw new Error('Invalid address object.');
  const type = safeString(value.type, 'address type', 16);
  if (type !== 'cidr' && type !== 'fqdn') throw new Error('Invalid address type.');
  return {
    id: safeString(value.id, 'address ID', 128),
    name: safeString(value.name, 'address name', 128),
    type,
    value: safeString(value.value, 'address value'),
    usedBy: [],
  };
}

function references(values: string[], addresses: ReadonlyMap<string, AddressObject>): ConfigReference[] {
  return values.map(name => ({id: addresses.get(name)?.id ?? null, name}));
}

export function parseConfigSnapshot(value: unknown): ConfigSnapshot {
  if (!isObject(value) || typeof value.state !== 'string' ||
      !['ready', 'starting', 'unavailable', 'unconfigured'].includes(value.state) ||
      typeof value.detail !== 'string' || value.detail.length > 1024 ||
      /[\u0000-\u001f\u007f]/u.test(value.detail) || value.view !== 'runtime' ||
      !(value.revision === null || (typeof value.revision === 'string' && value.revision.length <= 128))) {
    throw new Error('Invalid configuration snapshot.');
  }

  const addressValues = boundedArray(value.addresses, 'address collection', MAX_OBJECTS);
  const addresses = addressValues.map(parseAddress);
  const addressNames = new Map<string, MutableAddress>();
  const addressesById = new Map<string, MutableAddress>();
  const addressIds = new Set<string>();
  for (const address of addresses) {
    if (addressNames.has(address.name) || addressIds.has(address.id)) throw new Error('Duplicate address object.');
    addressNames.set(address.name, address);
    addressIds.add(address.id);
    addressesById.set(address.id, address);
  }

  const policies = boundedArray(value.policies, 'policy collection', MAX_POLICIES).map((item): PolicySummary => {
    if (!isObject(item)) throw new Error('Invalid policy.');
    return {
      id: safeString(item.id, 'policy ID', 128),
      name: safeString(item.name, 'policy name', 128),
      protocol: safeString(item.protocol, 'policy protocol', 128),
      sources: references(stringArray(item.sources, 'policy sources'), addressNames),
      sourcePorts: stringArray(item.source_ports, 'policy source ports'),
      destinations: references(stringArray(item.destinations, 'policy destinations'), addressNames),
      destinationPorts: stringArray(item.destination_ports, 'policy destination ports'),
      features: stringArray(item.features, 'policy features'),
      action: safeString(item.action, 'policy action', 32),
      nat: optionalString(item.nat, 'policy NAT'),
      routing: optionalString(item.routing, 'policy routing'),
      tlsProfile: optionalString(item.tls_profile, 'policy TLS profile'),
      sshProfile: optionalString(item.ssh_profile, 'policy SSH profile'),
      detectionProfile: optionalString(item.detection_profile, 'policy detection profile'),
      contentProfile: optionalString(item.content_profile, 'policy content profile'),
      authProfile: optionalString(item.auth_profile, 'policy authentication profile'),
      dnsProfile: optionalString(item.dns_profile, 'policy DNS profile'),
      scriptProfile: optionalString(item.script_profile, 'policy script profile'),
      enabled: safeBoolean(item.enabled, 'policy enabled state'),
    };
  });

  const policyIds = new Set<string>();
  for (const policy of policies) {
    if (policyIds.has(policy.id)) throw new Error('Duplicate policy ID.');
    policyIds.add(policy.id);
    for (const reference of [...policy.sources, ...policy.destinations]) {
      if (reference.id === null) continue;
      const address = addressesById.get(reference.id);
      if (address && !address.usedBy.some(item => item.id === policy.id)) {
        address.usedBy.push({id: policy.id, kind: 'policy', name: policy.name});
      }
    }
  }

  const ports = boundedArray(value.ports, 'port collection', MAX_OBJECTS).map((item): MutablePort => {
    if (!isObject(item)) throw new Error('Invalid port object.');
    const start = safeInteger(item.start, 'port start', 65535);
    const end = safeInteger(item.end, 'port end', 65535);
    if (start > end) throw new Error('Invalid port range.');
    return {
      id: safeString(item.id, 'port ID', 128),
      name: safeString(item.name, 'port name', 128),
      start,
      end,
      usedBy: [],
    };
  });
  const protocols = boundedArray(value.protocols, 'protocol collection', MAX_OBJECTS).map((item): MutableProtocol => {
    if (!isObject(item)) throw new Error('Invalid protocol object.');
    return {
      id: safeString(item.id, 'protocol ID', 128),
      name: safeString(item.name, 'protocol name', 128),
      number: safeInteger(item.number, 'protocol number', 255),
      usedBy: [],
    };
  });
  const profiles = boundedArray(value.profiles, 'profile collection', MAX_OBJECTS).map((item): MutableProfile => {
    if (!isObject(item)) throw new Error('Invalid profile.');
    const type = safeString(item.type, 'profile type', 32);
    let routing: ProfileObject['routing'] = null;
    if (type === 'routing') {
      if (!isObject(item.routing)) throw new Error('Invalid routing profile.');
      const loadBalancingMethod = safeString(item.routing.load_balancing_method, 'routing load-balancing method', 32);
      if (!['round-robin', 'sticky-l3', 'sticky-l4'].includes(loadBalancingMethod)) {
        throw new Error('Invalid routing load-balancing method.');
      }
      const rewriteSni = optionalString(item.routing.rewrite_sni, 'routing source SNI', 1024);
      const rewriteSniTo = optionalString(item.routing.rewrite_sni_to, 'routing destination SNI', 1024);
      if ((rewriteSni.length === 0) !== (rewriteSniTo.length === 0)) throw new Error('Invalid routing SNI rewrite.');
      routing = {
        destinationAddresses: stringArray(item.routing.destination_addresses, 'routing destination addresses'),
        destinationPorts: stringArray(item.routing.destination_ports, 'routing destination ports'),
        loadBalancingMethod: loadBalancingMethod as 'round-robin' | 'sticky-l3' | 'sticky-l4',
        rewriteSni,
        rewriteSniTo,
      };
    } else if (item.routing !== null) {
      throw new Error('Invalid non-routing profile details.');
    }
    return {
      id: safeString(item.id, 'profile ID', 128),
      name: safeString(item.name, 'profile name', 128),
      type,
      routing,
      usedBy: [],
    };
  });
  for (const collection of [ports, protocols, profiles]) {
    const ids = new Set<string>();
    const names = new Set<string>();
    for (const item of collection) {
      if (ids.has(item.id) || names.has(item.name)) throw new Error('Duplicate configuration object.');
      ids.add(item.id);
      names.add(item.name);
    }
  }
  const portsByName = new Map(ports.map(item => [item.name, item]));
  const protocolsByName = new Map(protocols.map(item => [item.name, item]));
  const profilesByIdentity = new Map(profiles.map(item => [`${item.type}:${item.name}`, item]));
  for (const policy of policies) {
    const usage: Usage = {id: policy.id, kind: 'policy', name: policy.name};
    protocolsByName.get(policy.protocol)?.usedBy.push(usage);
    profilesByIdentity.get(`tls:${policy.tlsProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`routing:${policy.routing}`)?.usedBy.push(usage);
    profilesByIdentity.get(`ssh:${policy.sshProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`detection:${policy.detectionProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`content:${policy.contentProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`authentication:${policy.authProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`dns:${policy.dnsProfile}`)?.usedBy.push(usage);
    profilesByIdentity.get(`script:${policy.scriptProfile}`)?.usedBy.push(usage);
    for (const name of new Set([...policy.sourcePorts, ...policy.destinationPorts])) {
      portsByName.get(name)?.usedBy.push(usage);
    }
  }
  for (const profile of profiles) {
    if (!profile.routing) continue;
    const usage: Usage = {id: profile.id, kind: 'routing-profile', name: profile.name};
    for (const name of new Set(profile.routing.destinationAddresses)) {
      const address = addressNames.get(name);
      if (address && !address.usedBy.some(item => item.id === profile.id)) address.usedBy.push(usage);
    }
    for (const name of new Set(profile.routing.destinationPorts)) {
      const port = portsByName.get(name);
      if (port && !port.usedBy.some(item => item.id === profile.id)) port.usedBy.push(usage);
    }
  }

  return {
    source: 'live',
    state: value.state as ConfigSnapshot['state'],
    detail: value.detail,
    checkedAtUnixMs: nullableInteger(value.checked_at_unix_ms, 'configuration check time'),
    lastSuccessAtUnixMs: nullableInteger(value.last_success_at_unix_ms, 'configuration success time'),
    revision: value.revision as string | null,
    policies,
    addresses,
    ports,
    protocols,
    profiles,
  };
}

export class ApiConfigClient implements ConfigClient {
  readonly #endpoint: string;
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(apiBase: string, fetchImplementation: typeof fetch = (input, init) => fetch(input, init), timeoutMs = 5000) {
    const base = normalizedPath(apiBase);
    this.#endpoint = base === '/' ? '/config/snapshot' : `${base}/config/snapshot`;
    this.#fetch = fetchImplementation;
    this.#timeoutMs = timeoutMs;
  }

  async loadSnapshot(): Promise<ConfigSnapshot> {
    const controller = new AbortController();
    const timeout = globalThis.setTimeout(() => controller.abort(), this.#timeoutMs);
    try {
      const response = await this.#fetch(this.#endpoint, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {Accept: 'application/json'},
        redirect: 'error',
        signal: controller.signal,
      });
      if (!response.ok) throw new Error(`Configuration API returned HTTP ${response.status}.`);
      return parseConfigSnapshot(await boundedJson(response));
    } finally {
      globalThis.clearTimeout(timeout);
    }
  }
}
