import { describe, expect, it } from 'vitest'
import {
  AUTH_ORIGIN_REJECTED_MESSAGE,
  VPN_DNS_PERMISSION_MESSAGE,
  VPN_SERVER_UNAVAILABLE_MESSAGE,
  isAuthOriginRejected,
  isDNSPermissionDenied,
  isTunPermissionDenied,
  isVPNServerUnavailable,
  parseAppError,
  toErrorMessage,
} from './error'

describe('error helpers', () => {
  it('normalizes origin rejection errors without exposing raw gateway details', () => {
    const raw = 'auth_origin_rejected: 403 Forbidden {"ok":false,"error":"origin not allowed"}'

    expect(toErrorMessage(raw)).toBe(AUTH_ORIGIN_REJECTED_MESSAGE)
    expect(toErrorMessage(raw)).not.toContain('502 Bad Gateway')
    expect(toErrorMessage(raw)).not.toContain('{"ok":false')

    const parsed = parseAppError(raw)
    expect(parsed.category).toBe('auth_origin_rejected')
    expect(parsed.titleKey).toBe('errors.authOriginRejected.title')
  })

  it('detects legacy origin rejection payloads', () => {
    expect(isAuthOriginRejected('502 Bad Gateway: {"error":"auth: api error 403: {\\"ok\\":false,\\"error\\":\\"origin not allowed\\"}"}')).toBe(true)
  })

  it('normalizes VPN server provisioning failures', () => {
    const raw = '502 Bad Gateway: {"error":"connect: api error 502: {\\"ok\\":false,\\"error\\":\\"failed to connect to VPN server\\"}\\n"}'

    expect(isVPNServerUnavailable(raw)).toBe(true)
    expect(toErrorMessage(raw)).toBe(VPN_SERVER_UNAVAILABLE_MESSAGE)
    expect(toErrorMessage(raw)).not.toContain('502 Bad Gateway')

    const parsed = parseAppError(raw)
    expect(parsed.category).toBe('server_unavailable')
    expect(parsed.action).toBe('retry')
  })

  it('routes the resolvconf capability failure to the desktop permission flow', () => {
    const raw = '500 Internal Server Error: {"error":"wg connect: configure full tunnel: dns apply (resolvconf): write resolv.conf: open /etc/resolv.conf: permission denied"}'

    expect(isDNSPermissionDenied(raw)).toBe(true)
    expect(toErrorMessage(raw)).toBe(VPN_DNS_PERMISSION_MESSAGE)

    const parsed = parseAppError(raw)
    expect(parsed.category).toBe('dns_permission')
    expect(parsed.action).toBe('grant_caps')
    expect(parsed.titleKey).toBe('errors.dnsPermission.title')
    expect(parsed.descKey).toBe('errors.dnsPermission.desc')
  })

  it('correctly classifies structured dns_permission_denied error', () => {
    const raw = 'dns_permission_denied: Permisos insuficientes para configurar DNS en /etc/resolv.conf'
    const parsed = parseAppError(raw)
    expect(parsed.category).toBe('dns_permission')
    expect(parsed.action).toBe('grant_caps')
  })

  it('correctly classifies tun permission denied error', () => {
    const raw = 'tun_permission_denied: permisos insuficientes para crear TUN'
    expect(isTunPermissionDenied(raw)).toBe(true)

    const parsed = parseAppError(raw)
    expect(parsed.category).toBe('tun_permission')
    expect(parsed.action).toBe('grant_caps')
  })
})
