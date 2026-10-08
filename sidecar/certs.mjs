// Certificate authority and per-host leaf certificates, made with the openssl
// CLI (LibreSSL on macOS is enough). One CA per machine, one shared leaf key,
// one leaf certificate per host, all cached on disk under <data>/ca and
// <data>/certs.

import { spawn } from 'node:child_process'
import { createHash, createPublicKey, randomBytes, X509Certificate } from 'node:crypto'
import { existsSync } from 'node:fs'
import { chmod, mkdir, readFile, writeFile } from 'node:fs/promises'
import { hostname } from 'node:os'
import { isIP } from 'node:net'
import { join } from 'node:path'
import { createSecureContext } from 'node:tls'

const CA_DAYS = 825
const LEAF_DAYS = 365

function run(argv, input) {
  return new Promise((resolve, reject) => {
    const child = spawn(argv[0], argv.slice(1), { stdio: ['pipe', 'pipe', 'pipe'] })
    const out = []
    const err = []
    child.stdout.on('data', chunk => out.push(chunk))
    child.stderr.on('data', chunk => err.push(chunk))
    child.on('error', error =>
      reject(error.code === 'ENOENT' ? new Error(`${argv[0]} not found on PATH`) : error),
    )
    child.on('close', code => {
      if (code === 0) resolve(Buffer.concat(out))
      else reject(new Error(`${argv.slice(0, 2).join(' ')} failed: ${Buffer.concat(err).toString().trim()}`))
    })
    child.stdin.end(input ?? '')
  })
}

function spkiOf(pem) {
  const der = createPublicKey(pem).export({ type: 'spki', format: 'der' })
  return createHash('sha256').update(der).digest('base64')
}

// Host names come from the network: keep them to what a file name and an
// openssl config line can hold.
export function safeHost(host) {
  const lower = String(host).toLowerCase().replace(/^\[|\]$/g, '')
  if (isIP(lower)) return lower
  if (lower.length > 253 || !/^[a-z0-9_-]+(\.[a-z0-9_-]+)*\.?$/.test(lower)) {
    throw new Error(`refusing to issue a certificate for ${JSON.stringify(host)}`)
  }
  return lower.replace(/\.$/, '')
}

// X.509 holds a common name to 64 characters; a machine's name can be longer.
export function caCommonName(machine) {
  const short = String(machine).split('.')[0].replace(/[^\w-]/g, '') || 'local'
  const prefix = 'Wirepane CA ('
  return `${prefix}${short.slice(0, 64 - prefix.length - 1)})`
}

export async function ensureCA(dataDir) {
  const caDir = join(dataDir, 'ca')
  const caKeyPath = join(caDir, 'ca.key')
  const caCertPath = join(caDir, 'ca.pem')
  const leafKeyPath = join(caDir, 'leaf.key')
  await mkdir(caDir, { recursive: true, mode: 0o700 })

  if (!existsSync(caKeyPath) || !existsSync(caCertPath)) {
    const name = caCommonName(hostname())
    const config = join(caDir, 'ca.cnf')
    await writeFile(
      config,
      [
        '[req]',
        'distinguished_name=dn',
        'prompt=no',
        '[dn]',
        `CN=${name}`,
        'O=Wirepane',
        '[v3_ca]',
        'basicConstraints=critical,CA:TRUE',
        'keyUsage=critical,keyCertSign,cRLSign',
        'subjectKeyIdentifier=hash',
        '',
      ].join('\n'),
    )
    await run(['openssl', 'genrsa', '-out', caKeyPath, '2048'])
    await chmod(caKeyPath, 0o600)
    await run([
      'openssl', 'req', '-x509', '-new', '-key', caKeyPath, '-sha256',
      '-days', String(CA_DAYS), '-config', config, '-extensions', 'v3_ca',
      '-out', caCertPath,
    ])
  }
  if (!existsSync(leafKeyPath)) {
    await run(['openssl', 'genrsa', '-out', leafKeyPath, '2048'])
    await chmod(leafKeyPath, 0o600)
  }

  const caPem = await readFile(caCertPath, 'utf8')
  const leafKeyPem = await readFile(leafKeyPath, 'utf8')
  const x509 = new X509Certificate(caPem)
  return {
    dataDir,
    caKeyPath,
    caCertPath,
    leafKeyPath,
    caPem,
    leafKeyPem,
    caDer: x509.raw,
    subject: x509.subject.replace(/\n/g, ', '),
    fingerprint256: x509.fingerprint256,
    validTo: x509.validTo,
    // What Chrome's --ignore-certificate-errors-spki-list takes: every leaf
    // shares one key, so its hash covers every host; the CA's rides along.
    spki: [spkiOf(leafKeyPem), spkiOf(caPem)],
  }
}

export function createLeafFactory(ca) {
  const certsDir = join(ca.dataDir, 'certs')
  const contexts = new Map()

  async function issue(host) {
    await mkdir(certsDir, { recursive: true, mode: 0o700 })
    const file = join(certsDir, `${host.replace(/:/g, '_')}.pem`)
    if (existsSync(file)) {
      const pem = await readFile(file, 'utf8')
      const cert = new X509Certificate(pem)
      const isFresh = Date.parse(cert.validTo) - Date.now() > 7 * 24 * 3600 * 1000
      if (isFresh && cert.checkIssued(new X509Certificate(ca.caPem))) return pem
    }
    const san = isIP(host) ? `IP:${host}` : `DNS:${host}`
    const extFile = join(certsDir, `${host.replace(/:/g, '_')}.cnf`)
    await writeFile(
      extFile,
      [
        '[v3_leaf]',
        'basicConstraints=CA:FALSE',
        'keyUsage=critical,digitalSignature,keyEncipherment',
        'extendedKeyUsage=serverAuth',
        `subjectAltName=${san}`,
        'authorityKeyIdentifier=keyid',
        '',
      ].join('\n'),
    )
    const cn = host.length <= 64 ? host : 'proxied-host'
    const csr = await run(['openssl', 'req', '-new', '-key', ca.leafKeyPath, '-subj', `/CN=${cn}`])
    const pem = (
      await run(
        [
          'openssl', 'x509', '-req', '-CA', ca.caCertPath, '-CAkey', ca.caKeyPath,
          '-set_serial', `0x${randomBytes(12).toString('hex')}`, '-days', String(LEAF_DAYS),
          '-sha256', '-extfile', extFile, '-extensions', 'v3_leaf',
        ],
        csr,
      )
    ).toString()
    await writeFile(file, pem)
    return pem
  }

  return {
    // A TLS context for `host`, the leaf followed by the CA; one issue per
    // host however many connections ask at once.
    get(rawHost) {
      const host = safeHost(rawHost)
      let pending = contexts.get(host)
      if (!pending) {
        pending = issue(host).then(pem =>
          createSecureContext({ key: ca.leafKeyPem, cert: pem + ca.caPem }),
        )
        pending.catch(() => contexts.delete(host))
        contexts.set(host, pending)
      }
      return pending
    },
  }
}

// An unsigned iOS configuration profile carrying the CA as a trusted root.
export function mobileConfig(ca) {
  const uuid = () => {
    const b = randomBytes(16).toString('hex').toUpperCase()
    return `${b.slice(0, 8)}-${b.slice(8, 12)}-${b.slice(12, 16)}-${b.slice(16, 20)}-${b.slice(20)}`
  }
  const escape = s => s.replace(/&/g, '&amp;').replace(/</g, '&lt;')
  const name = escape(ca.subject.match(/CN=([^,]+)/)?.[1] ?? 'Wirepane CA')
  return `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <array>
    <dict>
      <key>PayloadCertificateFileName</key><string>wirepane-ca.cer</string>
      <key>PayloadContent</key><data>${ca.caDer.toString('base64')}</data>
      <key>PayloadDescription</key><string>Adds the Wirepane root CA</string>
      <key>PayloadDisplayName</key><string>${name}</string>
      <key>PayloadIdentifier</key><string>io.github.legostin.wirepane.ca.cert</string>
      <key>PayloadType</key><string>com.apple.security.root</string>
      <key>PayloadUUID</key><string>${uuid()}</string>
      <key>PayloadVersion</key><integer>1</integer>
    </dict>
  </array>
  <key>PayloadDisplayName</key><string>${name}</string>
  <key>PayloadIdentifier</key><string>io.github.legostin.wirepane.ca</string>
  <key>PayloadRemovalDisallowed</key><false/>
  <key>PayloadType</key><string>Configuration</string>
  <key>PayloadUUID</key><string>${uuid()}</string>
  <key>PayloadVersion</key><integer>1</integer>
</dict>
</plist>
`
}
