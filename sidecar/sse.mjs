// Server-sent events (text/event-stream), read as they stream: what the
// WHATWG event-stream format says an event is, from bytes in any pieces.

export class EventStreamReader {
  constructor(onEvent) {
    this.onEvent = onEvent
    this.decoder = new TextDecoder('utf-8')
    this.rest = ''
    this.reset()
  }

  reset() {
    this.data = []
    this.event = undefined
    this.id = undefined
    this.retry = undefined
  }

  push(chunk) {
    let text = this.rest + this.decoder.decode(chunk, { stream: true })
    // a \r at the end may be the first half of a \r\n: it waits for the next piece
    const held = text.endsWith('\r') ? '\r' : ''
    if (held) text = text.slice(0, -1)
    const lines = text.split(/\r\n|\n|\r/)
    this.rest = (lines.pop() ?? '') + held
    for (const line of lines) this.line(line)
  }

  line(line) {
    if (line === '') {
      if (this.data.length || this.event !== undefined || this.id !== undefined) {
        this.onEvent({ event: this.event, id: this.id, data: this.data.join('\n'), retry: this.retry })
      }
      return this.reset()
    }
    if (line.startsWith(':')) return
    const at = line.indexOf(':')
    const field = at < 0 ? line : line.slice(0, at)
    let value = at < 0 ? '' : line.slice(at + 1)
    if (value.startsWith(' ')) value = value.slice(1)
    if (field === 'data') this.data.push(value)
    else if (field === 'event') this.event = value
    else if (field === 'id') this.id = value
    else if (field === 'retry' && /^\d+$/.test(value)) this.retry = Number(value)
  }
}
