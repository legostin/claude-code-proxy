---
name: wirepane-troubleshooting
description: Use when Wirepane (the /proxy mod) shows nothing, shows CERT rows, an app breaks or loses its internet behind the proxy, a phone cannot connect, gRPC or WebSockets fail, a dev server's certificate is refused, or the Mac has no internet after a proxy crash. Symptom, check, fix - including the fix in the person's own app code (Android network_security_config, OkHttp/iOS pinning, Flutter HttpOverrides, Node/Go/Python proxy settings).
---

# Wirepane troubleshooting

Start with the `diagnose` tool (or `/proxy doctor`). It checks the proxy process, the system proxy, a VPN, other proxy apps, the Mac's trust in the CA, refusals per client and host, upstream failures, the tracked domains and the Android devices. The Health view in the pane has a button for each fix Wirepane can do itself. Below is what to do with each finding, and with what it cannot see.

## Nothing shows up

| Check | Fix |
| --- | --- |
| The proxy is stopped or failed | `/proxy start`. "Port taken" names the holder; quit it, or change the port in `/plugin` → Wirepane. After an update from 0.7, the holder is often the old proxy of a session still open: **Stop it and start** in Health. |
| The client is not pointed at the proxy | Browser: the one Wirepane opens (Setup → Browser). iOS Simulator and Mac apps: the system proxy (Setup → iOS / macOS). Android emulator: Setup → Android. Phone: Wi-Fi → proxy → the Mac's address and port (Setup shows it, with a QR code). |
| Tracked domains are on and exclude the app | The Domains view lists what passed through. Add the app's real hosts. |
| The app ignores the system proxy | See "Apps that ignore the proxy" below. |

## CERT rows: the client refuses the Wirepane CA

`diagnose` tells the two cases apart:

- **Every host refused from one client:** the client lacks the CA.
  - iOS Simulator: Setup → iOS installs it in one press.
  - iPhone: install the profile from `http://claude.proxy/`. Then **Settings → General → About → Certificate Trust Settings → turn on Wirepane CA**. People forget this step.
  - Android: a user CA is trusted by Chrome, not by apps. For your own app, add the config below. On an emulator with a Google APIs image, the Health view's **Trust in all apps** makes it a system CA until the next reboot. A Google Play image refuses root, so use a Google APIs one.
  - Mac apps and Safari: Setup → macOS → Trust on this Mac.
  - Firefox: its own store (Settings → Certificates → Import `~/.claude/proxy-mod/ca/ca.pem`).
  - CLI tools: `NODE_EXTRA_CA_CERTS=~/.claude/proxy-mod/ca/ca.pem`, `REQUESTS_CA_BUNDLE=…`, `SSL_CERT_FILE=…`, `curl --cacert …`. For Java: `keytool -importcert -cacerts -file …`.
- **One host refused while others work:** the app pins that certificate. After two refusals Wirepane passes that host through untouched, so the app keeps working, unrecorded. In your own app, switch pinning off in debug builds only:

Android `res/xml/network_security_config.xml`, referenced from `<application android:networkSecurityConfig="@xml/network_security_config">`:

```xml
<network-security-config>
  <debug-overrides>
    <trust-anchors>
      <certificates src="user" />
      <certificates src="system" />
    </trust-anchors>
  </debug-overrides>
</network-security-config>
```

OkHttp: `if (!BuildConfig.DEBUG) builder.certificatePinner(pinner)`. An OkHttp pin mismatch shows as a handshake that closes at once. Wirepane counts that too.

iOS (URLSession delegate, Alamofire `ServerTrustManager`, TrustKit): evaluate pins only `#if !DEBUG`.

Flutter (debug only):

```dart
class ProxyOverrides extends HttpOverrides {
  @override
  HttpClient createHttpClient(SecurityContext? context) => super.createHttpClient(context)
    ..findProxy = ((uri) => 'PROXY 10.0.2.2:8899;') // emulator; the Mac's LAN address on a phone
    ..badCertificateCallback = ((cert, host, port) => kDebugMode);
}
// main(): if (kDebugMode) HttpOverrides.global = ProxyOverrides();
```

Someone else's app that pins stays encrypted. Leave it passed through, or "Never decrypt it" in Health.

## Apps that ignore the proxy

- **Flutter/Dart:** ignores the OS proxy and the network security config. Use the `HttpOverrides` above.
- **Node:** `HTTPS_PROXY=http://127.0.0.1:8899 NODE_USE_ENV_PROXY=1 NODE_EXTRA_CA_CERTS=…` (Node 24.5+). Older versions need undici's `ProxyAgent` or `global-agent`.
- **Go:** reads `HTTPS_PROXY` and `HTTP_PROXY` from the environment only. Set `SSL_CERT_FILE` for the CA.
- **Python requests:** honours `HTTPS_PROXY` and `REQUESTS_CA_BUNDLE`.
- **Java:** `-Dhttps.proxyHost=127.0.0.1 -Dhttps.proxyPort=8899` plus the CA in a truststore.
- **Docker:** `HTTPS_PROXY=http://host.docker.internal:8899`. Also listen on the LAN, or publish the port.
- **Unity:** `UnityWebRequest` on Android ignores the system proxy. Point the emulator with `-http-proxy` (Setup → Android starts it so).
- **Electron:** `--proxy-server=http://127.0.0.1:8899`.
- **Apps on QUIC/HTTP/3:** UDP never meets an HTTP proxy. Chrome drops to HTTP/2 behind a proxy; Cronet apps may not. Turn QUIC off in the app's debug build.

## A phone cannot connect

1. Turn on Listen on → LAN (Setup). The Mac and the phone must be on the same network.
2. Guest or office Wi-Fi often isolates clients. Use a home or hotspot network.
3. The macOS firewall can block it: allow incoming connections for `node`.
4. A VPN on the Mac (`diagnose` names it) can route the phone's packets away. Try with it off.
5. Android over USB needs no Wi-Fi: Setup → Android points a USB device at `127.0.0.1` through `adb reverse`.

## Requests fail upstream

- **`ENOTFOUND`:** the name does not resolve on this Mac (VPN-only, `.local`, a container name). Connect the VPN, or map it with a `mapRemote` rule.
- **Self-signed dev server:** the Health view's "Accept its certificate" adds the host to the plugin's `insecureHosts` setting. Only that host goes unchecked.
- **`ECONNREFUSED` to `localhost`:** the dev server is not running on that port.
  - An emulator reaches the Mac as `10.0.2.2`.
  - A phone's request for `localhost` is refused by design: the network may not reach the Mac's loopback. Use the Mac's address, or a rule.
- **Office network, corporate proxy or Zscaler:** servers may be reachable only through the network's proxy. `diagnose` names the proxy the network service had before Wirepane, and **Use it upstream** sets the plugin's `upstreamProxy` option. It takes `http://[user:password@]host:port`, `socks5://[user:password@]host:port`, or a PAC file as `pac+http://wpad/proxy.pac`. Add `user:password@` if the proxy asks (a 407). `upstreamBypass` lists the hosts to reach directly. NTLM and Kerberos sign-in are not supported. If the network service has automatic proxy configuration (PAC) on, apps may follow it instead of Wirepane's system proxy: turn it off while debugging.

## Protocols

- **gRPC:** needs HTTP/2, which Wirepane speaks both ways over TLS. Plain-text h2c with prior knowledge is not supported; gRPC-Web is.
- **WebSockets:** Wirepane takes permessage-deflate out of the client's offer so messages stay readable. A server that insists on compression may refuse; a message that arrives compressed anyway passes on as it came.
- **HTTP/2:** clients that offer h2 get it. When the server speaks only HTTP/1.1, Wirepane talks HTTP/1.1 to it.

## The Mac has no internet after a crash

A proxy killed with `kill -9` cannot clean up after itself, so a watchdog puts the system proxy back within seconds. The next session also repairs it at start. By hand:

```sh
networksetup -setwebproxystate Wi-Fi off && networksetup -setsecurewebproxystate Wi-Fi off
```

## Several sessions

One proxy serves every Claude Code session on the Mac. The Health view shows its process: pid, uptime, memory, disk, and the sessions attached.

- Each project's rules apply while its session is attached.
- The tracked domains are shared.
- `/proxy stop` stops it for everyone. A session that ends only lets go. The last one out stops it.
- A proxy of another version or other settings is replaced once nobody uses it, or at once with `/proxy restart`.
