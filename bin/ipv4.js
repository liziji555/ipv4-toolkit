#!/usr/bin/env node
import { describe, split, contains, parseCidr, formatIp } from '../src/ipv4.js';

const HELP = `ipv4 — 零依赖的 IPv4 / CIDR 工具

用法:
  ipv4 info <cidr>              网段信息（网络号、广播、掩码、可用区间）
  ipv4 split <cidr> <前缀>      按更长前缀切分，列出子网
  ipv4 contains <cidr> <ip>     判断 IP 是否属于该网段

示例:
  ipv4 info 10.0.0.0/22
  ipv4 split 192.168.0.0/24 26
  ipv4 contains 10.0.0.0/8 10.1.2.3
`;

// 中日韩字符在终端占两列，按显示宽度补空格才能对齐
function displayWidth(text) {
  let width = 0;
  for (const ch of text) {
    width += ch.codePointAt(0) > 0x2e80 ? 2 : 1;
  }
  return width;
}

function pad(label, value, width = 16) {
  const gap = Math.max(1, width - displayWidth(label));
  return `${label}${' '.repeat(gap)}${value}`;
}

function cmdInfo(arg) {
  if (!arg) throw new Error('info 需要一个 CIDR 参数');
  const d = describe(arg);
  const lines = [
    pad('CIDR', d.cidr),
    pad('网络地址', d.network),
    pad('广播地址', d.broadcast),
    pad('子网掩码', `${d.mask} (/${d.prefix})`),
    pad('地址总数', d.size),
    pad('可用主机', d.hosts),
    pad('可用区间', d.hosts === 0 ? '—' : `${d.first} ~ ${d.last}`),
    pad('私有地址', d.private ? '是' : '否'),
  ];
  process.stdout.write(lines.join('\n') + '\n');
}

function cmdSplit(cidrText, prefixText) {
  if (!cidrText || !prefixText) throw new Error('split 需要 <cidr> <前缀> 两个参数');
  const prefix = Number(prefixText);
  if (!Number.isInteger(prefix)) throw new Error(`前缀不是整数: ${prefixText}`);
  const blocks = split(cidrText, prefix);
  const base = parseCidr(cidrText);
  process.stdout.write(
    `${formatIp(base.network)}/${base.prefix} 切分为 ${blocks.length} 个 /${prefix}：\n`
  );
  for (const b of blocks) {
    process.stdout.write(`  ${b.cidr.padEnd(20, ' ')}${b.size} 个地址\n`);
  }
}

function cmdContains(cidrText, ipText) {
  if (!cidrText || !ipText) throw new Error('contains 需要 <cidr> <ip> 两个参数');
  const hit = contains(cidrText, ipText);
  process.stdout.write(hit ? `${ipText} 属于 ${cidrText}\n` : `${ipText} 不属于 ${cidrText}\n`);
  process.exitCode = hit ? 0 : 1;
}

function main(argv) {
  const [cmd, ...rest] = argv;
  if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') {
    process.stdout.write(HELP);
    return;
  }
  try {
    if (cmd === 'info') return cmdInfo(rest[0]);
    if (cmd === 'split') return cmdSplit(rest[0], rest[1]);
    if (cmd === 'contains') return cmdContains(rest[0], rest[1]);
    throw new Error(`未知子命令: ${cmd}`);
  } catch (err) {
    process.stderr.write(`错误: ${err.message}\n`);
    process.exitCode = 2;
  }
}

main(process.argv.slice(2));
