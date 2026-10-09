// The Android emulator's system CA store, for an image that allows `adb root`
// (Google APIs and AOSP images; not Google Play ones): the CA joins the system
// certificates on a tmpfs laid over the store, and on Android 14 and later the
// store in the Conscrypt APEX is replaced too, in zygote's namespace and in
// every running app's. It lasts until the emulator reboots.

/** Where adb push puts the CA on the device. */
export const DEVICE_CA = '/data/local/tmp/wirepane-ca.pem'

/** The shell script, run as root on the device, that puts the CA (named `<hash>.0`) among the system CAs. */
export function systemCaScript(hash: string): string {
  return [
    'set -e',
    'STAGE=/data/local/tmp/wirepane-cacerts',
    'rm -rf "$STAGE" && mkdir -p -m 700 "$STAGE"',
    // the certificates the system has now, from the APEX where there is one
    'if [ -d /apex/com.android.conscrypt/cacerts ]; then cp /apex/com.android.conscrypt/cacerts/* "$STAGE"/; else cp /system/etc/security/cacerts/* "$STAGE"/; fi',
    'mount -t tmpfs tmpfs /system/etc/security/cacerts',
    'mv "$STAGE"/* /system/etc/security/cacerts/',
    `cp ${DEVICE_CA} /system/etc/security/cacerts/${hash}.0`,
    'chown root:root /system/etc/security/cacerts/*',
    'chmod 644 /system/etc/security/cacerts/*',
    'chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*',
    'if [ -d /apex/com.android.conscrypt/cacerts ]; then',
    '  for Z in $(pidof zygote zygote64); do nsenter --mount=/proc/$Z/ns/mnt -- /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts; done',
    '  for P in $(for Z in $(pidof zygote zygote64); do ps -o PID -P $Z | grep -v PID; done); do nsenter --mount=/proc/$P/ns/mnt -- /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts || true; done',
    'fi',
    'rm -rf "$STAGE"',
    'echo "wirepane: system CA in place"',
  ].join('\n')
}

/** Whether the device holds the CA among its system CAs now. */
export function hasSystemCaCommand(hash: string): string {
  return `[ -f /system/etc/security/cacerts/${hash}.0 ] && echo yes || echo no`
}

/** `adb root` answers this on an image that does not allow it. */
export function isRootRefused(output: string): boolean {
  return /cannot run as root|production builds|not allowed/i.test(output)
}
