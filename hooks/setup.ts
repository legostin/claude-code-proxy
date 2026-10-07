// What the setup tabs say and the commands they copy or run.

import type { ProxySetupTab, ProxyStatus } from '../types'

export const MAGIC_HOST = 'claude.proxy'

export const SETUP_TABS: { tab: ProxySetupTab; label: string; hotkey: string }[] = [
  { tab: 'browser', label: 'Browser', hotkey: '1' },
  { tab: 'ios', label: 'iOS', hotkey: '2' },
  { tab: 'android', label: 'Android', hotkey: '3' },
  { tab: 'cli', label: 'macOS / CLI', hotkey: '4' },
]

export type Browser = { name: string; app: string; slug: string }

/** Chromium browsers that honour --proxy-server and the SPKI allow-list. */
export const BROWSER_CANDIDATES: Browser[] = [
  { name: 'Google Chrome', app: 'Google Chrome.app', slug: 'chrome' },
  { name: 'Chrome Canary', app: 'Google Chrome Canary.app', slug: 'chrome-canary' },
  { name: 'Chromium', app: 'Chromium.app', slug: 'chromium' },
  { name: 'Microsoft Edge', app: 'Microsoft Edge.app', slug: 'edge' },
  { name: 'Brave', app: 'Brave Browser.app', slug: 'brave' },
]

export type SetupFacts = {
  status: ProxyStatus
  dataDir: string
  listen: 'local' | 'lan'
}

function proxyAddress(status: ProxyStatus): string {
  return `127.0.0.1:${status.port}`
}

function lanAddress(facts: SetupFacts): string | null {
  const ip = facts.status.addresses.find(a => a !== '127.0.0.1')
  return ip ? `${ip}:${facts.status.port}` : null
}

export function browserArgs(facts: SetupFacts, browser: Browser): string[] {
  const spki = facts.status.ca?.spki ?? []
  return [
    `--user-data-dir=${facts.dataDir}/browser/${browser.slug}`,
    `--proxy-server=http://${proxyAddress(facts.status)}`,
    // Chrome skips the proxy for localhost unless told otherwise.
    '--proxy-bypass-list=<-loopback>',
    `--ignore-certificate-errors-spki-list=${spki.join(',')}`,
    '--no-first-run',
    '--no-default-browser-check',
    `http://${MAGIC_HOST}/`,
  ]
}

export function shellQuote(text: string): string {
  return /^[\w@%+=:,./-]+$/.test(text) ? text : `'${text.replace(/'/g, `'\\''`)}'`
}

export function browserCommand(facts: SetupFacts, browser: Browser, appPath: string): string {
  return ['open', '-na', appPath, '--args', ...browserArgs(facts, browser)].map(shellQuote).join(' ')
}

export function systemProxyCommands(port: number, service = 'Wi-Fi'): { on: string; off: string } {
  const s = shellQuote(service)
  return {
    on: `networksetup -setwebproxy ${s} 127.0.0.1 ${port} && networksetup -setsecurewebproxy ${s} 127.0.0.1 ${port}`,
    off: `networksetup -setwebproxystate ${s} off && networksetup -setsecurewebproxystate ${s} off`,
  }
}

export function trustCommand(caPath: string): string {
  return `security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db ${shellQuote(caPath)}`
}

export function untrustCommand(caPath: string): string {
  return `security remove-trusted-cert ${shellQuote(caPath)}`
}

export const ANDROID_NETWORK_CONFIG = `<!-- res/xml/network_security_config.xml -->
<network-security-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>

<!-- AndroidManifest.xml, on <application> -->
android:networkSecurityConfig="@xml/network_security_config"`

/** The copyable commands each tab offers, by key. */
export function setupCommands(facts: SetupFacts): Record<string, string> {
  const port = facts.status.port
  const ca = facts.status.ca?.path ?? `${facts.dataDir}/ca/ca.pem`
  const proxy = systemProxyCommands(port)
  return {
    'sys-on': proxy.on,
    'sys-off': proxy.off,
    trust: trustCommand(ca),
    untrust: untrustCommand(ca),
    'sim-ca': `xcrun simctl keychain booted add-root-cert ${shellQuote(ca)}`,
    'adb-on': `adb shell settings put global http_proxy 10.0.2.2:${port}`,
    'adb-off': 'adb shell settings put global http_proxy :0',
    'android-config': ANDROID_NETWORK_CONFIG,
    curl: `curl -x http://${proxyAddress(facts.status)} --cacert ${shellQuote(ca)} https://example.com/`,
    env: [
      `export HTTPS_PROXY=http://${proxyAddress(facts.status)} HTTP_PROXY=http://${proxyAddress(facts.status)}`,
      `export NODE_EXTRA_CA_CERTS=${shellQuote(ca)} SSL_CERT_FILE=${shellQuote(ca)} REQUESTS_CA_BUNDLE=${shellQuote(ca)}`,
    ].join('\n'),
  }
}

export function browserGuide(facts: SetupFacts, found: readonly Browser[]): string {
  const browsers = found.length > 0 ? found.map(b => b.name).join(', ') : 'none (looked for Chrome, Chromium, Edge, Brave)'
  return `### A separate browser whose traffic all goes through the proxy

The button below starts a **new instance** of a Chromium browser with a profile of its own
(\`${facts.dataDir}/browser/…\`) that:

- goes through the proxy \`${proxyAddress(facts.status)}\`, **localhost included** (\`--proxy-bypass-list=<-loopback>\`);
- trusts the proxy's certificates by the SPKI hash of their key, so **nothing goes into the keychain**;
- leaves your everyday profile alone: logins, extensions and tabs stay apart, and the profile is kept between runs.

Found: ${browsers}.

It opens on \`http://${MAGIC_HOST}/\`: if that page shows, the browser is going through the proxy.
A yellow "unsupported command-line flag" bar is expected; it is how Chrome flags the trust switch.

**Firefox** (by hand): a separate profile (\`firefox -P\`), then Settings → Network Settings → Manual proxy
configuration, \`127.0.0.1\` port \`${facts.status.port}\` for HTTP and HTTPS. In \`about:config\` set
\`network.proxy.allow_hijacking_localhost = true\`. Import the CA under Settings → Privacy & Security → Certificates →
View Certificates → Authorities → Import (\`${facts.status.ca?.path ?? 'ca.pem'}\`) and tick "Trust this CA to identify websites".`
}

export function iosGuide(facts: SetupFacts): string {
  const lan = lanAddress(facts)
  const device =
    facts.listen === 'lan' && lan
      ? `1. On the iPhone: **Settings → Wi-Fi → (i) next to the network → Configure Proxy → Manual**:
   server \`${lan.split(':')[0]}\`, port \`${facts.status.port}\`. The Mac and the iPhone must be on the same network.
2. In **Safari** open \`http://${MAGIC_HOST}/\` (or \`http://${lan}/\`) → "iOS: download profile" → Allow.
3. **Settings → Profile Downloaded → Install** (the profile is unsigned; that is expected).
4. **Settings → General → About → Certificate Trust Settings** → turn on "${caName(facts)}".
5. Done. Rows marked **CERT** in the list mean step 4 is missing or the app pins its certificates;
   such hosts can go into the "Hosts not to decrypt" option.

When you are done, set **Configure Proxy → Off** again, or the iPhone loses its network once the proxy stops.`
      : `An iPhone needs the proxy to listen on the network: open \`/config\`, set the mod's **Listen on** option to **lan**, and restart the proxy.
It listens on this Mac only now (\`${proxyAddress(facts.status)}\`).`
  return `### iOS Simulator

1. **"CA → simulators"** below adds the root certificate to every **booted** simulator
   (\`xcrun simctl keychain <udid> add-root-cert\`). Once per simulator is enough.
2. The simulator has no proxy settings of its own: it uses the **macOS system proxy**. Turn it on with
   "system proxy on" and turn it off ("off") when you are done. All of this Mac's traffic goes through
   the proxy meanwhile, so keep it on only while you debug.

### iPhone / iPad

${device}`
}

export function androidGuide(facts: SetupFacts): string {
  const lan = lanAddress(facts)
  const device =
    facts.listen === 'lan' && lan
      ? `1. **Settings → Wi-Fi → long-press the network → Modify → Advanced → Proxy: Manual**:
   host \`${lan.split(':')[0]}\`, port \`${facts.status.port}\`.
2. In Chrome on the phone open \`http://${MAGIC_HOST}/\` → "Android: download certificate".
3. **Settings → Security → Encryption & credentials → Install a certificate → CA certificate** → pick the downloaded file.
4. When you are done, set **Proxy: None** again.`
      : `A phone over Wi-Fi needs the proxy to listen on the network: \`/config\` → the mod's **Listen on** option → **lan**, then restart the proxy.
A phone on USB does not: "Android → proxy" reaches it through \`adb reverse\`.`
  return `### Android emulator and USB devices

1. **"Android → proxy"** points every device \`adb devices\` lists at the proxy: an emulator at
   \`10.0.2.2:${facts.status.port}\` (an emulator's name for this Mac's localhost), a USB device at
   \`127.0.0.1:${facts.status.port}\` through \`adb reverse\`. The \`local\` mode is enough for both.
   **"Revert"** sets \`:0\` again; the mod also reverts by itself when the proxy stops and when the session ends.
2. **"Open CA page"** opens \`http://${MAGIC_HOST}/\` in the device's browser. Download "Android: download certificate",
   then **Settings → Security → Encryption & credentials → Install a certificate → CA certificate**.

### Android over Wi-Fi

${device}

### Apps and user CAs

Since Android 7, apps **do not trust** certificates the user installed. Chrome does; your app will show
**CERT** rows. Give its debug build a \`network_security_config\` ("config snippet"):

\`\`\`xml
${ANDROID_NETWORK_CONFIG}
\`\`\``
}

export function cliGuide(facts: SetupFacts): string {
  const ca = facts.status.ca?.path ?? 'ca.pem'
  return `### Trusting the CA on this Mac

Needed only when traffic does not come from the separate browser, for example from Safari or through the system proxy:

\`\`\`sh
${trustCommand(ca)}
\`\`\`

To undo: \`${untrustCommand(ca)}\`.

### The macOS system proxy (Safari, the simulator, native apps)

\`\`\`sh
${systemProxyCommands(facts.status.port).on}
# turn it off:
${systemProxyCommands(facts.status.port).off}
\`\`\`

\`networksetup -listallnetworkservices\` lists the service names (\`Wi-Fi\` here). If the proxy stops while
the system proxy is on, the Mac has no network until it is turned off.

### curl and scripts

\`\`\`sh
${setupCommands(facts).curl}
${setupCommands(facts).env}
\`\`\``
}

export function caName(facts: SetupFacts): string {
  return facts.status.ca?.subject.match(/CN=([^,]+)/)?.[1] ?? 'Claude Code Proxy CA'
}
