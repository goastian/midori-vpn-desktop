import { describe, expect, it } from 'vitest'
import { protocolIsAvailable } from './protocol'
import type { Server } from './agent'

const server: Server = {
  id: 'server-id',
  name: 'Main',
  host: 'vpn.example.test',
  endpoint: 'vpn.example.test',
  location: 'Test',
  country_code: 'XX',
  wg_port: 51820,
  public_key: 'public-key',
  is_active: true,
  supports_wireguard: true,
  supports_proxy: false,
  supports_mesh_exit: false,
  transports: [{
    protocol: 'openvpn',
    host: 'vpn.example.test',
    port: 1194,
    enabled: false,
    health_status: 'healthy',
  }],
}

describe('protocol availability', () => {
  it('keeps the active OpenVPN transport selectable during a capability refresh', () => {
    expect(protocolIsAvailable('openvpn', [server], true, 'openvpn')).toBe(true)
  })

  it('disables an uncertified OpenVPN transport when no tunnel uses it', () => {
    expect(protocolIsAvailable('openvpn', [server], false, 'wireguard')).toBe(false)
  })
})
