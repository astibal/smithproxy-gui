export interface CidrInfo {
  family: 'IPv4' | 'IPv6';
  prefix: number;
  network: string;
  last: string;
  addressCount: bigint;
}

function parsePrefix(value: string, maximum: number): number | undefined {
  if (!/^\d{1,3}$/u.test(value)) return undefined;
  const prefix = Number(value);
  return prefix <= maximum ? prefix : undefined;
}

function parseIpv4(value: string): bigint | undefined {
  const octets = value.split('.');
  if (octets.length !== 4) return undefined;
  let result = 0n;
  for (const octet of octets) {
    if (!/^\d{1,3}$/u.test(octet)) return undefined;
    const number = Number(octet);
    if (number > 255 || String(number) !== octet) return undefined;
    result = (result << 8n) | BigInt(number);
  }
  return result;
}

function formatIpv4(value: bigint): string {
  return [24n, 16n, 8n, 0n].map(shift => Number((value >> shift) & 255n)).join('.');
}

function parseIpv6(value: string): bigint | undefined {
  if (value.length === 0 || value.includes('%') || value.split('::').length > 2) return undefined;
  let normalized = value.toLowerCase();
  const ipv4Separator = normalized.lastIndexOf(':');
  const ipv4Tail = normalized.slice(ipv4Separator + 1);
  if (ipv4Tail.includes('.')) {
    const ipv4 = parseIpv4(ipv4Tail);
    if (ipv4 === undefined) return undefined;
    normalized = `${normalized.slice(0, ipv4Separator + 1)}${(ipv4 >> 16n).toString(16)}:${
      (ipv4 & 0xffffn).toString(16)}`;
  }

  const compressed = normalized.includes('::');
  const [headText = '', tailText = ''] = normalized.split('::');
  const head = headText.length > 0 ? headText.split(':') : [];
  const tail = tailText.length > 0 ? tailText.split(':') : [];
  if ((!compressed && head.length !== 8) || (compressed && head.length + tail.length >= 8)) return undefined;
  const groups = compressed
    ? [...head, ...Array<string>(8 - head.length - tail.length).fill('0'), ...tail]
    : head;
  if (groups.length !== 8 || groups.some(group => !/^[0-9a-f]{1,4}$/u.test(group))) return undefined;
  return groups.reduce((result, group) => (result << 16n) | BigInt(`0x${group}`), 0n);
}

function formatIpv6(value: bigint): string {
  const groups = Array.from({length: 8}, (_, index) =>
    Number((value >> BigInt((7 - index) * 16)) & 0xffffn).toString(16));
  let bestStart = -1;
  let bestLength = 0;
  for (let index = 0; index < groups.length;) {
    if (groups[index] !== '0') {
      index += 1;
      continue;
    }
    let end = index;
    while (end < groups.length && groups[end] === '0') end += 1;
    if (end - index > bestLength && end - index >= 2) {
      bestStart = index;
      bestLength = end - index;
    }
    index = end;
  }
  if (bestStart < 0) return groups.join(':');
  const left = groups.slice(0, bestStart).join(':');
  const right = groups.slice(bestStart + bestLength).join(':');
  return `${left}::${right}`;
}

export function parseCidr(value: string): CidrInfo | undefined {
  const pieces = value.trim().split('/');
  if (pieces.length < 1 || pieces.length > 2) return undefined;
  const [address = '', suppliedPrefix] = pieces;
  const family = address.includes(':') ? 'IPv6' : 'IPv4';
  const bits = family === 'IPv6' ? 128 : 32;
  const rawPrefix = suppliedPrefix ?? String(bits);
  const parsedAddress = family === 'IPv6' ? parseIpv6(address) : parseIpv4(address);
  const prefix = parsePrefix(rawPrefix, bits);
  if (parsedAddress === undefined || prefix === undefined) return undefined;
  const hostBits = bits - prefix;
  const hostMask = hostBits === 0 ? 0n : (1n << BigInt(hostBits)) - 1n;
  const network = parsedAddress & ~hostMask;
  const last = network | hostMask;
  const format = family === 'IPv6' ? formatIpv6 : formatIpv4;
  return {family, prefix, network: format(network), last: format(last), addressCount: 1n << BigInt(hostBits)};
}

export function normalizeCidr(value: string): string | undefined {
  const trimmed = value.trim();
  const info = parseCidr(trimmed);
  if (!info) return undefined;
  return trimmed.includes('/') ? trimmed : `${info.network}/${info.prefix}`;
}

export function describeCidr(value: string): string | undefined {
  const info = parseCidr(value);
  if (!info) return undefined;
  const bits = info.family === 'IPv6' ? 128 : 32;
  const hostBits = bits - info.prefix;
  let size: string;
  if (info.prefix === 0) {
    size = `all ${info.family} addresses`;
  } else if (hostBits === 0) {
    size = 'single address';
  } else if (info.addressCount <= 4_294_967_296n) {
    size = `${info.addressCount.toLocaleString('en-US')} addresses`;
  } else {
    size = `2^${hostBits} addresses`;
  }
  const range = info.network === info.last ? info.network : `${info.network} – ${info.last}`;
  return `${info.family} /${info.prefix} · ${size} · ${range}`;
}
