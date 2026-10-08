import { describe, expect, test } from 'claude-code/testing'

import { buildTree, flattenTree, treeIds, treeLeafLabel } from '../hooks/flows'
import { newestNodeFirst, nodeMajor, phoneAddress, proxyTargets, type SetupFacts } from '../hooks/setup'
import type { ProxyAddress, ProxyFlow } from '../types'

function flow(id: number, path: string, extra: Partial<ProxyFlow> = {}): ProxyFlow {
  return {
    id,
    ts: 0,
    kind: 'http',
    method: 'GET',
    scheme: 'https',
    host: 'api.example.com',
    port: 443,
    path,
    status: 200,
    reqSize: 0,
    resSize: 10,
    durationMs: 5,
    contentType: 'application/json',
    state: 'done',
    error: null,
    errorCode: null,
    client: null,
    ...extra,
  }
}

const FLOWS = [
  flow(1, '/v1/items?page=1'),
  flow(2, '/v1/items?page=2'),
  flow(3, '/v1/login', { method: 'POST', status: 401 }),
  flow(4, '/'),
  flow(5, '/static/js/app.js', { host: 'cdn.example.com', contentType: 'text/javascript' }),
  flow(6, '', { kind: 'tunnel', method: 'CONNECT', host: 'gateway.icloud.com', status: null, state: 'error', errorCode: 'client-rejected-cert' }),
  flow(7, '/v1/items/42', { scheme: 'http', port: 8080, host: 'localhost' }),
]

describe('the tree view', () => {
  test('groups by origin, then path segment, and folds single-child chains', () => {
    const tree = buildTree(FLOWS)
    expect(tree.map(node => [node.label, node.count, node.errors])).toEqual([
      ['gateway.icloud.com:443', 1, 1],
      ['http://localhost:8080', 1, 0],
      ['https://api.example.com', 4, 1],
      ['https://cdn.example.com', 1, 0],
    ])
    const api = tree[2]!
    // "/" lands on the origin itself; /v1 keeps two children so it is not folded
    expect(api.flows.map(f => f.id)).toEqual([4])
    expect(api.children.map(child => child.label)).toEqual(['/v1'])
    expect(api.children[0]!.children.map(child => [child.label, child.count])).toEqual([
      ['/items', 2],
      ['/login', 1],
    ])
    // requests to one path, newest first
    expect(api.children[0]!.children[0]!.flows.map(f => f.id)).toEqual([2, 1])
    // a chain with no requests of its own folds into one node
    expect(tree[3]!.children.map(child => child.label)).toEqual(['/static/js/app.js'])
    expect(tree[1]!.children.map(child => child.label)).toEqual(['/v1/items/42'])
  })

  test('shows only what is open, child nodes before requests', () => {
    const tree = buildTree(FLOWS)
    expect(flattenTree(tree, new Set()).map(row => row.kind)).toEqual(['node', 'node', 'node', 'node'])
    const open = new Set(['o:https://api.example.com', 'p:https://api.example.com/v1', 'p:https://api.example.com/v1/items'])
    const rows = flattenTree(tree, open).map(row =>
      row.kind === 'node' ? `${'  '.repeat(row.depth)}${row.isOpen ? '▾' : '▸'} ${row.node.label}` : `${'  '.repeat(row.depth)}#${row.flow.id}`,
    )
    expect(rows).toEqual([
      '▸ gateway.icloud.com:443',
      '▸ http://localhost:8080',
      '▾ https://api.example.com',
      '  ▾ /v1',
      '    ▾ /items',
      '      #2',
      '      #1',
      '    ▸ /login',
      '  #4',
      '▸ https://cdn.example.com',
    ])
    expect(treeIds(tree)).toContain('p:https://cdn.example.com/static/js/app.js')
  })

  test('a request row names its id and query', () => {
    expect(treeLeafLabel(flow(1, '/v1/items?page=1&q=a?b'))).toBe('#1 ?page=1&q=a?b')
    expect(treeLeafLabel(flow(3, '/v1/login'))).toBe('#3')
  })
})

describe('the address to enter', () => {
  const lan: ProxyAddress[] = [
    { address: '10.7.9.5', iface: 'en0', label: 'Wi-Fi (en0)', kind: 'lan', isPrimary: true },
    { address: '192.168.139.3', iface: 'bridge100', label: 'bridge100', kind: 'virtual', isPrimary: false },
    { address: '10.20.133.214', iface: 'utun8', label: 'utun8', kind: 'vpn', isPrimary: false },
  ]
  const facts = (extra: Partial<SetupFacts['status']> = {}, listen: 'local' | 'lan' = 'local'): SetupFacts => ({
    status: {
      phase: 'running',
      host: '127.0.0.1',
      port: 8899,
      addresses: ['127.0.0.1'],
      lan,
      runDir: null,
      pid: 1,
      ca: null,
      error: null,
      ...extra,
    },
    dataDir: '/tmp/proxy-mod',
    listen,
  })

  test('a phone gets the Wi-Fi address, never the VPN or a VM bridge', () => {
    expect(phoneAddress(facts())?.address).toBe('10.7.9.5')
    const ios = proxyTargets(facts(), 'ios')
    expect(ios.map(t => [t.client, t.host, t.port, t.isRemote])).toEqual([
      ['iOS Simulator', '127.0.0.1', 8899, false],
      ['iPhone / iPad', '10.7.9.5', 8899, true],
    ])
  })

  test('each Android client gets its own address', () => {
    expect(proxyTargets(facts(), 'android').map(t => [t.client, t.host])).toEqual([
      ['Android emulator', '10.0.2.2'],
      ['Android on USB', '127.0.0.1'],
      ['Android on Wi-Fi', '10.7.9.5'],
    ])
  })

  test('no reachable address means no host to enter', () => {
    const bare = facts({ lan: [lan[2]!] })
    expect(phoneAddress(bare)).toBeNull()
    expect(proxyTargets(bare, 'ios')[1]!.host).toBeNull()
  })
})

describe('finding Node', () => {
  test('the major version comes from node --version', () => {
    expect(nodeMajor('v22.11.0\n')).toBe(22)
    expect(nodeMajor('v9.11.2')).toBe(9)
    expect(nodeMajor('')).toBe(0)
    expect(nodeMajor('zsh: command not found: node')).toBe(0)
  })

  test("a version manager's folders, the newest first", () => {
    expect(newestNodeFirst(['v18.20.4', 'v9.11.2', '.DS_Store', 'v22.11.0', 'v22.2.0'])).toEqual(['v22.11.0', 'v22.2.0', 'v18.20.4', 'v9.11.2'])
  })
})
