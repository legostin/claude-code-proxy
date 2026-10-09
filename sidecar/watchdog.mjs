#!/usr/bin/env node
// Puts the Mac's system proxy back when the proxy that turned it on dies
// without a word (a kill -9, a crash): a process of its own, started beside
// the proxy, that outlives it. A proxy that answers on the port again (a
// restart, another session's) keeps the settings; nothing else does.
//
//   node watchdog.mjs <proxy pid> <backup file> <port>
//
// WIREPANE_WATCHDOG_DRY=<file> writes the commands there instead of running them.

import { execFileSync } from 'node:child_process'
import { appendFileSync, readFileSync, writeFileSync } from 'node:fs'
import net from 'node:net'

import { restoreCommands } from '../shared/systemproxy.mjs'

const [pid, backupFile, port] = process.argv.slice(2)
const dry = process.env.WIREPANE_WATCHDOG_DRY

function isAlive(id) {
  try {
    process.kill(Number(id), 0)
    return true
  } catch (error) {
    return error.code === 'EPERM'
  }
}

function answers(at) {
  return new Promise(resolve => {
    const socket = net.connect({ host: '127.0.0.1', port: Number(at) })
    socket.setTimeout(1000, () => {
      socket.destroy()
      resolve(false)
    })
    socket.once('connect', () => {
      socket.destroy()
      resolve(true)
    })
    socket.once('error', () => resolve(false))
  })
}

function restore() {
  let backup
  try {
    const text = readFileSync(backupFile, 'utf8')
    if (!text.trim()) return
    backup = JSON.parse(text)
  } catch {
    return
  }
  for (const argv of restoreCommands(backup)) {
    try {
      if (dry) appendFileSync(dry, `${argv.join(' ')}\n`)
      else execFileSync(argv[0], argv.slice(1), { timeout: 5000, stdio: 'ignore' })
    } catch {}
  }
  writeFileSync(backupFile, '')
}

async function watch() {
  if (isAlive(pid)) return setTimeout(watch, 1500)
  // a restart takes a moment to listen again
  await new Promise(resolve => setTimeout(resolve, 3000))
  if (!(await answers(port))) restore()
  process.exit(0)
}

if (!pid || !backupFile || !port) {
  process.stderr.write('usage: watchdog.mjs <pid> <backup file> <port>\n')
  process.exit(2)
}
watch()
