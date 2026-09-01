import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { AUTH_ORIGIN_REJECTED_MESSAGE, VPN_SERVER_UNAVAILABLE_MESSAGE } from '../lib/error'
import { useVpnStore } from '../stores/vpn'

const mocks = vi.hoisted(() => ({
  connect: vi.fn(),
  disconnect: vi.fn(),
  listServers: vi.fn(async () => []),
  refreshServers: vi.fn(async () => []),
  status: vi.fn(),
}))

vi.mock('../lib/agent', () => ({
  agent: {
    status: mocks.status,
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
    mocks.status.mockReset()
    mocks.status.mockRejectedValue(new Error('status unavailable'))
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
    expect(mocks.status).not.toHaveBeenCalled()
  })

  it('reconciles an ambiguous network error when the requested tunnel is already connected', async () => {
    mocks.connect.mockRejectedValueOnce(new TypeError('NetworkError when attempting to fetch resource.'))
    mocks.status.mockResolvedValueOnce({
      vpn: {
        connected: true,
        phase: 'connected',
        connection_id: 'ike-session',
        server_name: 'Main',
        server_id: 'server-id',
        assigned_ip: '10.85.0.1',
        server_public_ip: '192.0.2.10',
        mesh_ip: '',
        bytes_sent: 0,
        bytes_recv: 0,
        requested_protocol: 'ikev2',
        active_protocol: 'ikev2',
      },
    })
    const vpn = useVpnStore()

    await vpn.connect('server-id')

    expect(vpn.error).toBeNull()
    expect(vpn.connected).toBe(true)
    expect(vpn.phase).toBe('connected')
    expect(vpn.requestedProtocol).toBe('ikev2')
    expect(vpn.activeProtocol).toBe('ikev2')
    expect(mocks.status).toHaveBeenCalledOnce()
  })

  it('does not submit another connection while the agent is still negotiating', async () => {
    const vpn = useVpnStore()
    vpn.applyStatus({
      connected: false,
      phase: 'negotiating',
      connection_id: 'pending-session',
      server_name: '',
      server_id: 'server-id',
      assigned_ip: '',
      server_public_ip: '',
      mesh_ip: '',
      bytes_sent: 0,
      bytes_recv: 0,
      requested_protocol: 'ikev2',
    })

    await vpn.connect('server-id')

    expect(vpn.connectionInProgress).toBe(true)
    expect(mocks.connect).not.toHaveBeenCalled()
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
