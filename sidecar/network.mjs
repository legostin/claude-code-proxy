// Which of this machine's addresses a phone on the same network should use
// as its proxy server. A Mac often has several: Wi-Fi, a VPN tunnel, bridges
// for virtual machines and containers, link-local leftovers. The right one is
// on the interface that carries the default route, unless that is a VPN.

import { execFile } from 'node:child_process'
import os from 'node:os'

const VPN = /^(utun|ipsec|ppp|tun|tap|wg|zt|tailscale)/
const VIRTUAL = /^(bridge|vmnet|vboxnet|docker|br-|veth|virbr|awdl|llw|anpi|ap\d)/

function run(argv) {
  return new Promise(resolve => {
    execFile(argv[0], argv.slice(1), { timeout: 3000 }, (error, stdout) => resolve(error ? '' : String(stdout)))
  })
}

/** The interface the default route leaves by: `en0`, or undefined. */
async function defaultInterface() {
  if (process.platform === 'darwin') {
    return /interface:\s*(\S+)/.exec(await run(['route', '-n', 'get', 'default']))?.[1]
  }
  if (process.platform === 'linux') {
    return /\bdev\s+(\S+)/.exec(await run(['ip', 'route', 'show', 'default']))?.[1]
  }
  return undefined
}

/** macOS names its devices: en0 → "Wi-Fi", en7 → "iPhone USB". */
async function hardwarePorts() {
  if (process.platform !== 'darwin') return {}
  const out = await run(['networksetup', '-listallhardwareports'])
  const ports = {}
  for (const block of out.split(/\n\s*\n/)) {
    const name = /Hardware Port:\s*(.+)/.exec(block)?.[1]?.trim()
    const device = /Device:\s*(\S+)/.exec(block)?.[1]
    if (name && device) ports[device] = name
  }
  return ports
}

/**
 * Ranks the IPv4 addresses: the one to give a phone first.
 *
 * @param interfaces what os.networkInterfaces() answers
 * @param routed the default route's interface, if known
 * @param ports device → hardware port name, if known
 * @returns `{ address, iface, label, kind, isPrimary }`, best first; kind is
 *   `lan`, `vpn` or `virtual`; link-local and loopback addresses are left out
 */
export function rankAddresses(interfaces, routed, ports = {}) {
  const found = []
  for (const [iface, entries] of Object.entries(interfaces)) {
    for (const entry of entries ?? []) {
      if (entry.family !== 'IPv4' && entry.family !== 4) continue
      if (entry.internal || entry.address.startsWith('169.254.')) continue
      const kind = VPN.test(iface) ? 'vpn' : VIRTUAL.test(iface) && !ports[iface] ? 'virtual' : 'lan'
      const port = ports[iface]
      found.push({ address: entry.address, iface, label: port ? `${port} (${iface})` : iface, kind, isPrimary: false })
    }
  }
  const score = item =>
    (item.kind === 'lan' ? 0 : item.kind === 'vpn' ? 20 : 10) +
    (item.iface === routed ? 0 : 2) +
    (/wi-?fi|ethernet|lan/i.test(ports[item.iface] ?? '') ? 0 : 1)
  found.sort((a, b) => score(a) - score(b))
  if (found[0] && found[0].kind === 'lan') found[0].isPrimary = true
  return found
}

export async function networkAddresses() {
  const [routed, ports] = await Promise.all([defaultInterface(), hardwarePorts()])
  return rankAddresses(os.networkInterfaces(), routed, ports)
}
