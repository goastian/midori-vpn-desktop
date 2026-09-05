import { beforeEach, describe, expect, it, vi } from 'vitest'

describe('browser agent client', () => {
  beforeEach(() => {
    vi.resetModules()
    sessionStorage.clear()
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

    const { agent, initAgentToken } = await import('./agent')
    await initAgentToken()
    await agent.status()

    expect(window.location.hash).toBe('')
    expect(sessionStorage.getItem('midorivpn.agent_token')).toBe('browser-secret')
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

  it('restores the session token after the OAuth callback returns to this tab', async () => {
    sessionStorage.setItem('midorivpn.agent_token', 'browser-secret')
    window.history.replaceState(null, '', '/')
    const fetchMock = vi.fn().mockResolvedValue(new Response('{}', { status: 200 }))
    vi.stubGlobal('fetch', fetchMock)

    const { agent, initAgentToken } = await import('./agent')
    await initAgentToken()
    await agent.status()

    expect(fetchMock).toHaveBeenCalledWith('/status', expect.objectContaining({
      headers: expect.objectContaining({ 'X-Agent-Token': 'browser-secret' }),
    }))
  })

  it('uses authenticated same-origin requests for agent operations', async () => {
    const fetchMock = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify({
        backend: 'resolvconf',
        needs_extra_caps: true,
        caps_missing: ['cap_dac_override'],
        caps_ok: false,
      }), { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response('[]', { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }))
      .mockResolvedValueOnce(new Response('{}', { status: 200, headers: { 'Content-Type': 'application/json' } }))
    vi.stubGlobal('fetch', fetchMock)

    const { agent } = await import('./agent')
    const dns = await agent.dns.status()
    await agent.servers.refresh()
    await agent.vpn.disconnect('active-connection', 'user_request')
    await agent.vpn.connect('', 'smart_auto', 'automatic')

    expect(dns.backend).toBe('resolvconf')
    expect(fetchMock).toHaveBeenNthCalledWith(1, '/dns/status', expect.objectContaining({ method: 'GET' }))
    expect(fetchMock).toHaveBeenNthCalledWith(2, '/servers/refresh', expect.objectContaining({ method: 'POST', body: '{}' }))
    expect(fetchMock).toHaveBeenNthCalledWith(3, '/vpn/disconnect', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ connection_id: 'active-connection', reason: 'user_request' }),
    }))
    expect(fetchMock).toHaveBeenNthCalledWith(4, '/vpn/connect', expect.objectContaining({
      method: 'POST',
      body: JSON.stringify({ protocol: 'smart_auto', selection_mode: 'automatic' }),
    }))
    for (const [, request] of fetchMock.mock.calls) {
      expect(request.headers).toEqual(expect.objectContaining({ 'X-Agent-Token': 'browser-secret' }))
    }
  })
})
