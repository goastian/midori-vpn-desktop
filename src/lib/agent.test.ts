import { describe, it, expect, vi, beforeEach } from 'vitest'

const mocks = vi.hoisted(() => ({
  invoke: vi.fn(),
  unlisten: vi.fn(),
  relayHandler: null as ((event: { payload: unknown }) => void) | null,
}))

vi.mock('@tauri-apps/api/core', () => ({
  invoke: mocks.invoke,
}))

vi.mock('@tauri-apps/api/event', () => ({
  listen: vi.fn((_event: string, handler: (event: { payload: unknown }) => void) => {
    mocks.relayHandler = handler
    return Promise.resolve(mocks.unlisten)
  }),
}))

import { agent, initAgentToken, type AgentSnapshot } from './agent'

function snapshot(): AgentSnapshot {
  return {
    vpn: {
      connected: false,
      server_name: '',
      server_id: '',
      assigned_ip: '',
      server_public_ip: '',
      mesh_ip: '',
      bytes_sent: 0,
      bytes_recv: 0,
    },
    mesh: {
      active: true,
      mesh_id: 'mesh-1',
      mesh_ip: '100.64.1.10',
      public_ip: '203.0.113.10',
      is_exit_node: true,
      full_tunnel: false,
      peers: [],
    },
    auth: {
      logged_in: true,
      username: 'user@example.com',
      expires_at: 123,
    },
    protection: {
      kill_switch_active: false,
      dns_protected: false,
    },
  }
}

describe('agent event relay client', () => {
  beforeEach(() => {
    mocks.invoke.mockReset()
    mocks.unlisten.mockReset()
    mocks.relayHandler = null
  })

  it('does not request the private RPC token from the WebView', async () => {
    await initAgentToken()
    expect(mocks.invoke).not.toHaveBeenCalled()
  })

  it('expands snapshot relay events and cleans up listener', async () => {
    const cb = vi.fn()
    const cleanup = agent.subscribe(cb)

    await Promise.resolve()
    mocks.relayHandler?.({ payload: { event: 'snapshot', data: snapshot() } })

    expect(cb).toHaveBeenCalledWith({ type: 'vpn_status', data: expect.objectContaining({ connected: false }) })
    expect(cb).toHaveBeenCalledWith({ type: 'mesh_status', data: expect.objectContaining({ active: true }) })
    expect(cb).toHaveBeenCalledWith({ type: 'auth_status', data: expect.objectContaining({ logged_in: true }) })
    expect(cb).toHaveBeenCalledWith({ type: 'protection_status', data: expect.objectContaining({ dns_protected: false }) })

    cleanup()
    expect(mocks.unlisten).toHaveBeenCalledOnce()
  })
})
