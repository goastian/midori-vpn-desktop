import { describe, expect, it } from 'vitest'
import {
  AUTH_ORIGIN_REJECTED_MESSAGE,
  VPN_SERVER_UNAVAILABLE_MESSAGE,
  isAuthOriginRejected,
  isVPNServerUnavailable,
  toErrorMessage,
} from './error'

describe('error helpers', () => {
  it('normalizes origin rejection errors without exposing raw gateway details', () => {
    const raw = 'auth_origin_rejected: 403 Forbidden {"ok":false,"error":"origin not allowed"}'

    expect(toErrorMessage(raw)).toBe(AUTH_ORIGIN_REJECTED_MESSAGE)
    expect(toErrorMessage(raw)).not.toContain('502 Bad Gateway')
    expect(toErrorMessage(raw)).not.toContain('{"ok":false')
  })

  it('detects legacy origin rejection payloads', () => {
    expect(isAuthOriginRejected('502 Bad Gateway: {"error":"auth: api error 403: {\\"ok\\":false,\\"error\\":\\"origin not allowed\\"}"}')).toBe(true)
  })

  it('normalizes VPN server provisioning failures', () => {
    const raw = '502 Bad Gateway: {"error":"connect: api error 502: {\\"ok\\":false,\\"error\\":\\"failed to connect to VPN server\\"}\\n"}'

    expect(isVPNServerUnavailable(raw)).toBe(true)
    expect(toErrorMessage(raw)).toBe(VPN_SERVER_UNAVAILABLE_MESSAGE)
    expect(toErrorMessage(raw)).not.toContain('502 Bad Gateway')
  })
})
