/**
 * IPv4 / CIDR 纯函数工具集。
 * 全部以 32 位无符号整数为中间表示，不碰 DOM、不碰网络，方便单测。
 */

const OCTET = /^(0|[1-9]\d{0,2})$/;

/** 把 "10.1.2.3" 解析为无符号 32 位整数；非法输入抛错。 */
export function parseIp(text) {
  if (typeof text !== 'string') throw new TypeError('IP 必须是字符串');
  const parts = text.trim().split('.');
  if (parts.length !== 4) throw new Error(`IP 段数不对: ${text}`);
  let value = 0;
  for (const part of parts) {
    if (!OCTET.test(part)) throw new Error(`非法 IP 段 "${part}": ${text}`);
    const n = Number(part);
    if (n > 255) throw new Error(`IP 段越界 "${part}": ${text}`);
    value = value * 256 + n;
  }
  return value >>> 0;
}

/** 把 32 位整数还原成 "10.1.2.3"。 */
export function formatIp(value) {
  if (!Number.isInteger(value) || value < 0 || value > 0xffffffff) {
    throw new Error(`不是合法的 32 位地址: ${value}`);
  }
  return [
    (value >>> 24) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 8) & 0xff,
    value & 0xff,
  ].join('.');
}

/** 前缀长度对应的掩码整数，例如 24 -> 0xffffff00。 */
export function prefixToMask(prefix) {
  assertPrefix(prefix);
  if (prefix === 0) return 0;
  return (0xffffffff << (32 - prefix)) >>> 0;
}

/** 掩码整数反推前缀长度；非连续掩码抛错。 */
export function maskToPrefix(mask) {
  mask = mask >>> 0;
  let prefix = 0;
  let m = mask;
  while ((m & 0x80000000) >>> 0) {
    prefix += 1;
    m = (m << 1) >>> 0;
  }
  if (m !== 0) throw new Error('掩码不连续');
  return prefix;
}

/** 解析 "10.0.0.0/22" 或纯 IP（视为 /32）。 */
export function parseCidr(text) {
  if (typeof text !== 'string') throw new TypeError('CIDR 必须是字符串');
  const trimmed = text.trim();
  const slash = trimmed.indexOf('/');
  const ipText = slash === -1 ? trimmed : trimmed.slice(0, slash);
  const prefix = slash === -1 ? 32 : Number(trimmed.slice(slash + 1));
  if (slash !== -1 && !/^\d{1,2}$/.test(trimmed.slice(slash + 1))) {
    throw new Error(`前缀长度不合法: ${text}`);
  }
  assertPrefix(prefix);
  const ip = parseIp(ipText);
  const mask = prefixToMask(prefix);
  const network = (ip & mask) >>> 0;
  const broadcast = (network | (~mask >>> 0)) >>> 0;
  const size = broadcast - network + 1;
  return { ip, prefix, mask, network, broadcast, size };
}

/** 网段的可用主机数：/31 按 RFC 3021 两端都可用，/32 只有自己。 */
export function hostCount(prefix) {
  assertPrefix(prefix);
  if (prefix === 32) return 1;
  if (prefix === 31) return 2;
  return 2 ** (32 - prefix) - 2;
}

/** 网段可用地址区间；/31、/32 没有"首尾各留一个"的概念。 */
export function usableRange(cidr) {
  const { network, broadcast, prefix } = cidr;
  if (prefix === 31) return { first: network, last: broadcast };
  if (prefix === 32) return { first: network, last: network };
  return { first: network + 1, last: broadcast - 1 };
}

/** 判断某个 IP 是否落在 CIDR 里。 */
export function contains(cidrText, ipText) {
  const { network, mask } = parseCidr(cidrText);
  const ip = parseIp(ipText);
  return ((ip & mask) >>> 0) === network;
}

/** 按更长的前缀切分网段，返回切分后的每一块。 */
export function split(cidrText, newPrefix, limit = 1 << 16) {
  const cidr = parseCidr(cidrText);
  assertPrefix(newPrefix);
  if (newPrefix <= cidr.prefix) {
    throw new Error(`子网前缀 ${newPrefix} 必须大于 ${cidr.prefix}`);
  }
  const count = 2 ** (newPrefix - cidr.prefix);
  if (count > limit) {
    throw new Error(`切出 ${count} 块超出上限 ${limit}，请提高新前缀或显式放宽 limit`);
  }
  const step = 2 ** (32 - newPrefix);
  const out = [];
  for (let i = 0; i < count; i++) {
    const start = cidr.network + i * step;
    out.push({
      cidr: `${formatIp(start)}/${newPrefix}`,
      network: start >>> 0,
      broadcast: (start + step - 1) >>> 0,
      size: step,
    });
  }
  return out;
}

/** 汇总一个网段对外展示需要的字段。 */
export function describe(cidrText) {
  const cidr = parseCidr(cidrText);
  const { network, broadcast, prefix, mask } = cidr;
  const range = usableRange(cidr);
  return {
    cidr: `${formatIp(network)}/${prefix}`,
    network: formatIp(network),
    broadcast: formatIp(broadcast),
    mask: formatIp(mask),
    prefix,
    size: cidr.size,
    hosts: hostCount(prefix),
    first: formatIp(range.first),
    last: formatIp(range.last),
    private: isPrivate(network),
  };
}

/** 是否是 RFC 1918 私有地址（按网络地址判断）。 */
export function isPrivate(value) {
  const a = (value >>> 24) & 0xff;
  const b = (value >>> 16) & 0xff;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 127) return true;
  return false;
}

function assertPrefix(prefix) {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
    throw new Error(`前缀长度必须在 0..32 之间: ${prefix}`);
  }
}
