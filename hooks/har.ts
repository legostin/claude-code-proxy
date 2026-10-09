// Captured exchanges as HAR 1.2, the format browsers' DevTools, Charles,
// Proxyman and HTTP Toolkit read.

import type { Exchange } from './diff'
import type { WsRecord } from './flows'

const OPCODES: Record<string, number> = { text: 1, binary: 2, close: 8, ping: 9, pong: 10 }

function version(httpVersion: string | undefined): string {
  return httpVersion === '2' ? 'HTTP/2' : `HTTP/${httpVersion ?? '1.1'}`
}

function queryOf(url: URL): { name: string; value: string }[] {
  const out: { name: string; value: string }[] = []
  url.searchParams.forEach((value, name) => out.push({ name, value }))
  return out
}

function headers(list: readonly [string, string][]) {
  return list.map(([name, value]) => ({ name, value }))
}

function header(list: readonly [string, string][], name: string): string | undefined {
  return list.find(([key]) => key.toLowerCase() === name)?.[1]
}

export function toHar(exchanges: readonly (Exchange & { messages?: WsRecord[] })[], wirepaneVersion: string) {
  return {
    log: {
      version: '1.2',
      creator: { name: 'Wirepane', version: wirepaneVersion },
      entries: exchanges.map(({ detail, reqText, resText, messages }) => {
        const url = new URL(detail.url)
        const time = detail.durationMs ?? 0
        return {
          startedDateTime: new Date(detail.ts).toISOString(),
          time,
          request: {
            method: detail.method,
            url: detail.url,
            httpVersion: version(detail.httpVersion),
            cookies: [],
            headers: headers(detail.reqHeaders),
            queryString: queryOf(url),
            ...(reqText !== null ? { postData: { mimeType: header(detail.reqHeaders, 'content-type') ?? 'application/octet-stream', text: reqText } } : {}),
            headersSize: -1,
            bodySize: detail.reqSize,
          },
          response: {
            status: detail.status ?? 0,
            statusText: detail.statusMessage ?? '',
            httpVersion: version(detail.upstreamHttpVersion ?? detail.httpVersion),
            cookies: [],
            headers: headers(detail.resHeaders),
            content: { size: detail.resSize, mimeType: detail.contentType ?? 'x-unknown', ...(resText !== null ? { text: resText } : {}) },
            redirectURL: header(detail.resHeaders, 'location') ?? '',
            headersSize: -1,
            bodySize: detail.resSize,
          },
          cache: {},
          timings: { send: 0, wait: time, receive: 0 },
          _wirepane: { id: detail.id, client: detail.client, rules: detail.rules ?? [], error: detail.error },
          ...(messages
            ? {
                _resourceType: 'websocket',
                _webSocketMessages: messages.map(m => ({
                  type: m.dir === 'out' ? 'send' : 'receive',
                  time: (detail.ts + m.t) / 1000,
                  opcode: OPCODES[m.op] ?? 0,
                  data: m.text ?? m.b64 ?? '',
                })),
              }
            : {}),
        }
      }),
    },
  }
}
