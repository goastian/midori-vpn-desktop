import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { AUTH_ORIGIN_REJECTED_MESSAGE, VPN_SERVER_UNAVAILABLE_MESSAGE } from '../lib/error'
import { useVpnStore } from '../stores/vpn'

const mocks = vi.hoisted(() => ({
  connect: vi.fn(),
  disconnect: vi.fn(),
  listServers: vi.fn(async () => []),
  refreshServers: vi.fn(async () => []),
}))

vi.mock('../lib/agent', () => ({
  agent: {
    servers: {
      list: mocks.listServers,
      refresh: mocks.refreshServers,
    },
    vpn: {
      connect: mocks.connect,
      disconnect: mocks.disconnect,
    },
  },
}))

describe('vpn store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    mocks.connect.mockReset()
    mocks.disconnect.mockReset()
    mocks.disconnect.mockResolvedValue(undefined)
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

  it('does not disconnect an active tunnel while refreshing servers', async () => {
    const vpn = useVpnStore()
    vpn.applyStatus({
      connected: true,
      connection_id: 'active-connection',
      server_name: 'Main',
      server_id: 'server-id',
      assigned_ip: '10.86.0.2',
      server_public_ip: '192.0.2.10',
      mesh_ip: '',
      bytes_sent: 10,
      bytes_recv: 20,
      active_protocol: 'openvpn',
    })

    await vpn.fetchServers(true)

    expect(vpn.connected).toBe(true)
    expect(vpn.connectionId).toBe('active-connection')
    expect(mocks.disconnect).not.toHaveBeenCalled()
  })

  it('sends the active connection identity and explicit user intent', async () => {
    const vpn = useVpnStore()
    vpn.applyStatus({
      connected: true,
      connection_id: 'active-connection',
      server_name: 'Main',
      server_id: 'server-id',
      assigned_ip: '10.86.0.2',
      server_public_ip: '192.0.2.10',
      mesh_ip: '',
      bytes_sent: 10,
      bytes_recv: 20,
      active_protocol: 'openvpn',
    })

    const disconnected = await vpn.disconnect('user_request')

    expect(disconnected).toBe(true)
    expect(mocks.disconnect).toHaveBeenCalledWith('active-connection', 'user_request')
    expect(vpn.connected).toBe(false)
    expect(vpn.connectionId).toBe('')
  })

  it('preserves the active state when the disconnect request is rejected', async () => {
    mocks.disconnect.mockRejectedValueOnce(new Error('ERR_VPN_CONNECTION_CHANGED'))
    const vpn = useVpnStore()
    vpn.applyStatus({
      connected: true,
      connection_id: 'active-connection',
      server_name: 'Main',
      server_id: 'server-id',
      assigned_ip: '10.86.0.2',
      server_public_ip: '192.0.2.10',
      mesh_ip: '',
      bytes_sent: 10,
      bytes_recv: 20,
      active_protocol: 'openvpn',
    })

    const disconnected = await vpn.disconnect('server_switch')

    expect(disconnected).toBe(false)
    expect(vpn.connected).toBe(true)
    expect(vpn.connectionId).toBe('active-connection')
    expect(vpn.error).toBeTruthy()
  })
})
