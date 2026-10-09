import { describe, expect, test } from 'claude-code/testing'

import { DEVICE_CA, hasSystemCaCommand, isRootRefused, systemCaScript } from '../hooks/android'

describe('the Android system CA', () => {
  test('the script lays a tmpfs over the store, adds the CA and binds it into the APEX of zygote and the apps', () => {
    const script = systemCaScript('da32c98d')
    expect(script).toContain('mount -t tmpfs tmpfs /system/etc/security/cacerts')
    expect(script).toContain(`cp ${DEVICE_CA} /system/etc/security/cacerts/da32c98d.0`)
    expect(script).toContain('chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*')
    expect(script).toContain('nsenter --mount=/proc/$Z/ns/mnt -- /bin/mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts')
    expect(script.split('\n')[0]).toBe('set -e')
    expect(script.trim().endsWith('echo "wirepane: system CA in place"')).toBe(true)
  })

  test('tells a Google Play image, which refuses root', () => {
    expect(isRootRefused('adbd cannot run as root in production builds\n')).toBe(true)
    expect(isRootRefused('restarting adbd as root\n')).toBe(false)
    expect(hasSystemCaCommand('ab12')).toBe('[ -f /system/etc/security/cacerts/ab12.0 ] && echo yes || echo no')
  })
})
