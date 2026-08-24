import { beforeEach, describe, expect, it, vi } from 'vitest'

describe('browser agent client', () => {
  beforeEach(() => {
    vi.resetModules()
    Reflect.deleteProperty(window, '__TAURI_INTERNALS__')
    window.history.replaceState(null, '', '/#/?agent_token=browser-secret')
  })

  it('moves the launch token out of the URL and authenticates loopback RPC', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      vpn: {}, mesh: {}, auth: {}, protection: {},
    }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    }))
    vi.stubGlobal('fetch', fetchMock)

    const { agent, initAgentToken, tauriRuntime } = await import('./agent')
    await initAgentToken()
    await agent.status()

    expect(tauriRuntime).toBe(false)
    expect(window.location.hash).toBe('')
    expect(fetchMock).toHaveBeenCalledWith('/status', expect.objectContaining({
      method: 'GET',
      credentials: 'omit',
      headers: expect.objectContaining({ 'X-Agent-Token': 'browser-secret' }),
    }))
  })

  it('fails closed when the browser was not launched by the agent', async () => {
    window.history.replaceState(null, '', '/')
    const { initAgentToken } = await import('./agent')
    await expect(initAgentToken()).rejects.toThrow('local_ui_session_missing')
  })
})
