import test from 'node:test';
import assert from 'node:assert/strict';
import {
  parseIp,
  formatIp,
  prefixToMask,
  maskToPrefix,
  parseCidr,
  hostCount,
  usableRange,
  contains,
  split,
  describe,
  isPrivate,
} from '../src/ipv4.js';

test('parseIp / formatIp 往返', () => {
  for (const text of ['0.0.0.0', '1.2.3.4', '10.0.0.0', '192.168.1.1', '255.255.255.255']) {
    assert.equal(formatIp(parseIp(text)), text);
  }
  assert.equal(parseIp('255.255.255.255'), 0xffffffff);
  assert.equal(parseIp('0.0.0.0'), 0);
});

test('parseIp 拒绝非法输入', () => {
  assert.throws(() => parseIp('1.2.3'), /段数不对/);
  assert.throws(() => parseIp('1.2.3.4.5'), /段数不对/);
  assert.throws(() => parseIp('1.2.3.256'), /越界/);
  assert.throws(() => parseIp('1.2.3.-1'), /非法 IP 段/);
  assert.throws(() => parseIp('1.2.3.01'), /非法 IP 段/);
  assert.throws(() => parseIp('1.2.3.a'), /非法 IP 段/);
  assert.throws(() => parseIp(42), /必须是字符串/);
});

test('formatIp 拒绝越界整数', () => {
  assert.throws(() => formatIp(-1), /不是合法的 32 位地址/);
  assert.throws(() => formatIp(2 ** 32), /不是合法的 32 位地址/);
  assert.throws(() => formatIp(1.5), /不是合法的 32 位地址/);
});

test('prefixToMask 常见前缀', () => {
  assert.equal(formatIp(prefixToMask(0)), '0.0.0.0');
  assert.equal(formatIp(prefixToMask(8)), '255.0.0.0');
  assert.equal(formatIp(prefixToMask(24)), '255.255.255.0');
  assert.equal(formatIp(prefixToMask(30)), '255.255.255.252');
  assert.equal(formatIp(prefixToMask(32)), '255.255.255.255');
});

test('maskToPrefix 与 prefixToMask 互逆', () => {
  for (let p = 0; p <= 32; p++) {
    assert.equal(maskToPrefix(prefixToMask(p)), p);
  }
  assert.throws(() => maskToPrefix(0xff00ff00 >>> 0), /掩码不连续/);
});

test('parseCidr 计算网络号与广播地址', () => {
  const c = parseCidr('10.1.2.3/22');
  assert.equal(formatIp(c.network), '10.1.0.0');
  assert.equal(formatIp(c.broadcast), '10.1.3.255');
  assert.equal(c.size, 1024);
  assert.equal(c.prefix, 22);
});

test('parseCidr 不带前缀时按 /32 处理', () => {
  const c = parseCidr('8.8.8.8');
  assert.equal(c.prefix, 32);
  assert.equal(formatIp(c.network), '8.8.8.8');
  assert.equal(formatIp(c.broadcast), '8.8.8.8');
});

test('parseCidr 拒绝越界前缀与坏格式', () => {
  assert.throws(() => parseCidr('10.0.0.0/33'), /0\.\.32/);
  assert.throws(() => parseCidr('10.0.0.0/-1'), /前缀长度不合法/);
  assert.throws(() => parseCidr('10.0.0.0/2a'), /前缀长度不合法/);
  assert.throws(() => parseCidr('10.0.0.0/'), /前缀长度不合法/);
});

test('hostCount 覆盖 /30 /31 /32 与 /0', () => {
  assert.equal(hostCount(0), 2 ** 32 - 2);
  assert.equal(hostCount(24), 254);
  assert.equal(hostCount(30), 2);
  assert.equal(hostCount(31), 2); // RFC 3021 点对点链路
  assert.equal(hostCount(32), 1);
});

test('usableRange 首尾各留一个（/31 与 /32 例外）', () => {
  assert.deepEqual(usableRange(parseCidr('192.168.1.0/24')), {
    first: parseIp('192.168.1.1'),
    last: parseIp('192.168.1.254'),
  });
  assert.deepEqual(usableRange(parseCidr('10.0.0.0/31')), {
    first: parseIp('10.0.0.0'),
    last: parseIp('10.0.0.1'),
  });
  assert.deepEqual(usableRange(parseCidr('10.0.0.5/32')), {
    first: parseIp('10.0.0.5'),
    last: parseIp('10.0.0.5'),
  });
});

test('contains 判断归属（含边界地址）', () => {
  assert.equal(contains('10.0.0.0/8', '10.255.255.255'), true);
  assert.equal(contains('10.0.0.0/8', '11.0.0.1'), false);
  assert.equal(contains('192.168.1.0/24', '192.168.1.255'), true);
  assert.equal(contains('192.168.1.0/24', '192.168.2.0'), false);
  assert.equal(contains('0.0.0.0/0', '203.0.113.9'), true);
});

test('split 切分明细正确', () => {
  const blocks = split('192.168.0.0/24', 26);
  assert.equal(blocks.length, 4);
  assert.deepEqual(blocks.map(b => b.cidr), [
    '192.168.0.0/26',
    '192.168.0.64/26',
    '192.168.0.128/26',
    '192.168.0.192/26',
  ]);
  assert.ok(blocks.every(b => b.size === 64));
  assert.deepEqual(blocks[3], {
    cidr: '192.168.0.192/26',
    network: parseIp('192.168.0.192'),
    broadcast: parseIp('192.168.0.255'),
    size: 64,
  });
});

test('split 生成的首尾地址连续无重叠', () => {
  const blocks = split('10.0.0.0/16', 20);
  assert.equal(blocks.length, 16);
  for (let i = 1; i < blocks.length; i++) {
    assert.equal(blocks[i].network, blocks[i - 1].broadcast + 1);
  }
  assert.equal(blocks[0].network, parseIp('10.0.0.0'));
  assert.equal(blocks.at(-1).broadcast, parseIp('10.0.255.255'));
});

test('split 拒绝非法前缀与超大切分', () => {
  assert.throws(() => split('10.0.0.0/24', 24), /必须大于/);
  assert.throws(() => split('10.0.0.0/24', 20), /必须大于/);
  assert.throws(() => split('10.0.0.0/8', 20, 1024), /超出上限/);
});

test('describe 汇总字段', () => {
  const d = describe('172.16.5.9/20');
  assert.equal(d.cidr, '172.16.0.0/20');
  assert.equal(d.network, '172.16.0.0');
  assert.equal(d.broadcast, '172.16.15.255');
  assert.equal(d.mask, '255.255.240.0');
  assert.equal(d.size, 4096);
  assert.equal(d.hosts, 4094);
  assert.equal(d.first, '172.16.0.1');
  assert.equal(d.last, '172.16.15.254');
  assert.equal(d.private, true);
});

test('isPrivate 识别私有与回环段', () => {
  assert.equal(isPrivate(parseIp('10.1.2.3')), true);
  assert.equal(isPrivate(parseIp('172.16.0.1')), true);
  assert.equal(isPrivate(parseIp('172.31.255.255')), true);
  assert.equal(isPrivate(parseIp('172.32.0.0')), false);
  assert.equal(isPrivate(parseIp('192.168.0.1')), true);
  assert.equal(isPrivate(parseIp('127.0.0.1')), true);
  assert.equal(isPrivate(parseIp('8.8.8.8')), false);
});
