import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { AUTH_ORIGIN_REJECTED_MESSAGE, VPN_SERVER_UNAVAILABLE_MESSAGE } from '../lib/error'
import { useVpnStore } from '../stores/vpn'

const mocks = vi.hoisted(() => ({
  connect: vi.fn(),
}))

vi.mock('../lib/agent', () => ({
  agent: {
    servers: {
      list: vi.fn(async () => []),
    },
    vpn: {
      connect: mocks.connect,
      disconnect: vi.fn(async () => undefined),
    },
  },
}))

describe('vpn store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    mocks.connect.mockReset()
  })

  it('keeps session state local and shows a readable origin rejection error', async () => {
    mocks.connect.mockRejectedValueOnce(
      new Error('auth_origin_rejected: 403 Forbidden {"ok":false,"error":"origin not allowed"}'),
    )
    const vpn = useVpnStore()

    await vpn.connect('de')

    expect(vpn.connected).toBe(false)
    expect(vpn.error).toBe(AUTH_ORIGIN_REJECTED_MESSAGE)
    expect(vpn.error).not.toContain('502 Bad Gateway')
    expect(vpn.error).not.toContain('{"ok":false')
  })

  it('shows a readable VPN server provisioning failure', async () => {
    mocks.connect.mockRejectedValueOnce(
      new Error('502 Bad Gateway: {"error":"connect: api error 502: {\\"ok\\":false,\\"error\\":\\"failed to connect to VPN server\\"}\\n"}'),
    )
    const vpn = useVpnStore()

    await vpn.connect('de')

    expect(vpn.connected).toBe(false)
    expect(vpn.error).toBe(VPN_SERVER_UNAVAILABLE_MESSAGE)
    expect(vpn.error).not.toContain('502 Bad Gateway')
  })
})
