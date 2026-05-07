import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { useMeshStore } from '../stores/mesh'

vi.mock('../lib/agent', () => ({
  agent: {
    mesh: {
      enable: vi.fn(),
      disable: vi.fn(),
      listExitNodes: vi.fn(async () => []),
      enableFullTunnel: vi.fn(),
      disableFullTunnel: vi.fn(),
    },
  },
}))

import { agent } from '../lib/agent'

describe('useMeshStore — state machine', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('starts in idle', () => {
    const m = useMeshStore()
    expect(m.meshState).toBe('idle')
  })

  it('transitions idle → enabling → error on enable failure', async () => {
    const m = useMeshStore()
    vi.mocked(agent.mesh.enable).mockRejectedValueOnce(new Error('boom'))
    await m.enable()
    expect(m.meshState).toBe('error')
    expect(m.error).toBe('boom')
  })

  it('clearError() returns from error → idle when not enabled', async () => {
    const m = useMeshStore()
    vi.mocked(agent.mesh.enable).mockRejectedValueOnce(new Error('boom'))
    await m.enable()
    expect(m.meshState).toBe('error')
    m.clearError()
    expect(m.meshState).toBe('idle')
    expect(m.error).toBeNull()
  })

  it('clearError() returns from error → enabled when actually enabled', async () => {
    const m = useMeshStore()
    // Simulate backend reported active=true via SSE.
    m.applyStatus({
      active: true, mesh_id: '', mesh_ip: '10.0.0.1', public_ip: '',
      is_exit_node: false, full_tunnel: false, peers: [],
    })
    expect(m.meshState).toBe('enabled')
    // Force error state.
    vi.mocked(agent.mesh.disable).mockRejectedValueOnce(new Error('x'))
    await m.disable()
    expect(m.meshState).toBe('error')
    m.clearError()
    expect(m.meshState).toBe('enabled')
  })

  it('allows retry from error state (does not block enable)', async () => {
    const m = useMeshStore()
    vi.mocked(agent.mesh.enable).mockRejectedValueOnce(new Error('first'))
    await m.enable()
    expect(m.meshState).toBe('error')

    vi.mocked(agent.mesh.enable).mockResolvedValueOnce({ ok: true })
    await m.enable()
    // Without an SSE update, state stays in 'enabling' (waiting for backend).
    expect(m.meshState).toBe('enabling')
  })

  it('blocks re-entry while transition is in flight', async () => {
    const m = useMeshStore()
    let resolveEnable!: () => void
    vi.mocked(agent.mesh.enable).mockImplementationOnce(
      () => new Promise<{ ok: boolean }>((r) => { resolveEnable = () => r({ ok: true }) }),
    )
    const p1 = m.enable()
    expect(m.meshState).toBe('enabling')
    // Second call must be ignored.
    await m.enable()
    expect(agent.mesh.enable).toHaveBeenCalledTimes(1)
    resolveEnable()
    await p1
  })

  it('filters invalid peers in fetchExitNodes', async () => {
    const m = useMeshStore()
    m.applyStatus({
      active: true, mesh_id: '', mesh_ip: '10.0.0.1', public_ip: '',
      is_exit_node: false, full_tunnel: false, peers: [],
    })
    vi.mocked(agent.mesh.listExitNodes).mockResolvedValueOnce([
      // self → filtered
      { user_id: 'a', mesh_ip: '10.0.0.1', proxy_scheme: 'socks5', proxy_port: 1080, supports_tcp: true, supports_udp: false, is_active: true },
      // valid
      { user_id: 'b', mesh_ip: '10.0.0.2', proxy_scheme: 'socks5', proxy_port: 1080, supports_tcp: true, supports_udp: false, is_active: true },
      // invalid IP → filtered
      { user_id: 'c', mesh_ip: 'bogus', proxy_scheme: 'socks5', proxy_port: 1080, supports_tcp: true, supports_udp: false, is_active: true },
      // invalid port → filtered
      { user_id: 'd', mesh_ip: '10.0.0.3', proxy_scheme: 'socks5', proxy_port: 99999, supports_tcp: true, supports_udp: false, is_active: true },
      // invalid scheme → filtered
      { user_id: 'e', mesh_ip: '10.0.0.4', proxy_scheme: 'ftp', proxy_port: 1080, supports_tcp: true, supports_udp: false, is_active: true },
      // duplicate of 'b' → filtered
      { user_id: 'f', mesh_ip: '10.0.0.2', proxy_scheme: 'socks5', proxy_port: 1080, supports_tcp: true, supports_udp: false, is_active: true },
    ])
    await m.fetchExitNodes()
    expect(m.exitNodes).toHaveLength(1)
    expect(m.exitNodes[0].user_id).toBe('b')
  })
})
