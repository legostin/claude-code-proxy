// The server name a TLS client asks for, read from its ClientHello. Some
// clients CONNECT to an address rather than a name (the Android emulator's
// -http-proxy resolves names itself): the name they mean is still in the
// handshake, and the tracked domains are names.

/** Whether `buffer` holds a whole first TLS record, or enough to tell it is not one. */
export function isClientHelloComplete(buffer) {
  if (buffer.length >= 1 && buffer[0] !== 0x16) return true
  return buffer.length >= 5 && buffer.length >= 5 + buffer.readUInt16BE(3)
}

/** The SNI host name in a ClientHello record, lower-cased; null when there is none. */
export function serverNameOf(buffer) {
  try {
    if (buffer[0] !== 0x16 || buffer[5] !== 0x01) return null
    // record header (5), handshake type and length (4), version (2), random (32)
    let at = 5 + 4 + 2 + 32
    at += 1 + buffer[at] // session id
    at += 2 + buffer.readUInt16BE(at) // cipher suites
    at += 1 + buffer[at] // compression methods
    const end = Math.min(buffer.length, at + 2 + buffer.readUInt16BE(at))
    at += 2
    while (at + 4 <= end) {
      const type = buffer.readUInt16BE(at)
      const size = buffer.readUInt16BE(at + 2)
      at += 4
      if (type === 0) {
        // server_name: list length (2), name type (1, 0 = host name), name length (2), name
        if (buffer[at + 2] !== 0) return null
        const name = buffer.toString('latin1', at + 5, at + 5 + buffer.readUInt16BE(at + 3))
        return /^[a-z0-9-]+(\.[a-z0-9-]+)*$/i.test(name) ? name.toLowerCase() : null
      }
      at += size
    }
  } catch {
    // a short or malformed record: no name
  }
  return null
}

/**
 * Reads a paused socket's first record without consuming it: resolves to its
 * SNI name, or null when it sends something else, nothing within `waitMs`,
 * or no name. The bytes are put back and the socket left paused.
 */
export function peekServerName(socket, waitMs = 3000) {
  return new Promise(resolve => {
    const chunks = []
    let finished = false
    const finish = isGone => {
      if (finished) return
      finished = true
      clearTimeout(timer)
      socket.off('data', onData)
      socket.off('end', gone)
      socket.off('close', gone)
      socket.pause()
      const buffer = Buffer.concat(chunks)
      // a stream takes nothing back once it has ended
      if (buffer.length && !isGone) socket.unshift(buffer)
      resolve(buffer.length ? serverNameOf(buffer) : null)
    }
    const gone = () => finish(true)
    const onData = chunk => {
      chunks.push(chunk)
      const buffer = Buffer.concat(chunks)
      if (isClientHelloComplete(buffer) || buffer.length >= 16 * 1024 + 5) finish(false)
    }
    const timer = setTimeout(() => finish(false), waitMs)
    socket.on('data', onData)
    socket.once('end', gone)
    socket.once('close', gone)
    socket.resume()
  })
}
