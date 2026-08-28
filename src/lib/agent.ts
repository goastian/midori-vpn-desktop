/**
 * agent.ts — typed client for the local Go agent at localhost:7071.
 *
 * HTTP calls (GET/POST/DELETE) go through the Tauri Rust commands
 * (agent_get / agent_post / agent_delete → reqwest) because direct
 * fetch from the WebView to http:// is blocked by Tauri's security model.
 *
 * Tauri targets relay events through Rust. The Linux browser shell receives
 * the ephemeral token in a URL fragment, removes it immediately, and sends it
 * only in authenticated same-origin request headers.
 */

export const tauriRuntime = !__LINUX_BROWSER_SHELL__ && '__TAURI_INTERNALS__' in window
let browserAgentToken = ''
const browserTokenStorageKey = 'midorivpn.agent_token'

function loadBrowserAgentToken(): void {
  if (tauriRuntime || browserAgentToken) return
  const hash = window.location.hash.replace(/^#/, '')
  const fragment = new URLSearchParams(hash.includes('?') ? hash.slice(hash.indexOf('?') + 1) : hash)
  browserAgentToken = fragment.get('agent_token') ?? ''
  if (browserAgentToken) {
    // OAuth leaves and later returns to this same local origin. Keep the
    // per-agent token only for this browser tab so the dashboard can resume
    // after the callback without opening another tab or exposing a query key.
    sessionStorage.setItem(browserTokenStorageKey, browserAgentToken)
    window.history.replaceState(null, '', window.location.pathname + window.location.search)
  } else {
    browserAgentToken = sessionStorage.getItem(browserTokenStorageKey) ?? ''
  }
}

loadBrowserAgentToken()

/**
 * Backwards-compatible no-op kept for callers that initialise the agent
 * client before subscribing. The RPC token now stays inside Rust/Tauri.
 */
export async function initAgentToken(): Promise<void> {
  loadBrowserAgentToken()
  if (!tauriRuntime && !browserAgentToken) {
    throw new Error('local_ui_session_missing')
  }
}

// ── Types ────────────────────────────────────────────────────────────────────

export type VPNTransportProtocol = 'wireguard' | 'wss' | 'masque' | 'openvpn' | 'ikev2'

export interface VPNStatus {
  connected: boolean
  server_name: string
  server_id: string
  peer_id?: string
  assigned_ip: string
  server_public_ip: string
  mesh_ip: string
  bytes_sent: number
  bytes_recv: number
  active_protocol?: VPNTransportProtocol
  fallback_reason?: string
  connection_ms?: number
}

export interface MeshStatus {
  active: boolean
  mesh_id: string
  mesh_ip: string
  public_ip: string
  is_exit_node: boolean
  full_tunnel: boolean
  exit_node_host?: string
  exit_node_port?: number
  exit_node_scheme?: string
  peers: MeshPeer[]
	error_code?: string
	last_error?: string
}

export interface ProtectionStatus {
  kill_switch_active: boolean
  dns_protected: boolean
  mode?: string
  last_error?: string
}

export interface MeshPeer {
  mesh_ip: string
  display_name: string
  public_ip?: string
  proxy_port?: number
  is_exit_node?: boolean
}

export interface AuthStatus {
  logged_in: boolean
  username: string
  expires_at: number | null
}

export interface AgentSnapshot {
  vpn: VPNStatus
  mesh: MeshStatus
  auth: AuthStatus
  protection: ProtectionStatus
  security?: SecurityStatus
  local_rpc?: { port: number }
  local_proxy?: { port: number; active: boolean; upstream: string }
  kill_switch?: { active: boolean }
  dns_protected?: boolean
}

export interface SecurityStatus {
  token_store: string
  token_store_degraded: boolean
}

export interface Server {
  id: string
  name: string
  host: string
  endpoint: string
  location: string
  country_code: string
  wg_port: number
  public_key: string
  is_active: boolean
  supports_wireguard: boolean
  supports_proxy: boolean
  supports_mesh_exit: boolean
	transports: TransportCapability[]
}

export interface TransportCapability {
  protocol: VPNTransportProtocol | 'proxy'
  host: string
  port: number
  enabled: boolean
  priority?: number
  health_status: 'unknown' | 'healthy' | 'degraded' | 'disabled'
  metadata?: Record<string, unknown>
}

export interface ExitNode {
  user_id: string
  mesh_ip: string
  proxy_scheme: string
  proxy_port: number
  supports_tcp: boolean
  supports_udp: boolean
  is_active: boolean
}

export type AgentEvent =
  | { type: 'vpn_status'; data: VPNStatus }
  | { type: 'mesh_status'; data: MeshStatus }
  | { type: 'auth_status'; data: AuthStatus }
  | { type: 'protection_status'; data: ProtectionStatus }
  | { type: 'error'; data: { message: string } }

interface AgentRelayEvent {
  event: string
  data: AgentSnapshot
}

// ── Tauri IPC helpers ─────────────────────────────────────────────────────────

async function browserRequest<T>(method: string, path: string, body?: unknown): Promise<T> {
  loadBrowserAgentToken()
  if (!browserAgentToken) throw new Error('local_ui_session_missing')
  const response = await fetch(`/${path}`, {
    method,
    cache: 'no-store',
    credentials: 'omit',
    headers: {
      'X-Agent-Token': browserAgentToken,
      ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
  if (!response.ok) {
    const message = (await response.text()).trim()
    throw new Error(message || `agent_http_${response.status}`)
  }
  if (response.status === 204 || response.headers.get('Content-Length') === '0') {
    return undefined as T
  }
  return response.json() as Promise<T>
}

async function get<T>(path: string): Promise<T> {
  if (!tauriRuntime) return browserRequest<T>('GET', path)
  const { invoke } = await import('@tauri-apps/api/core')
  return invoke<T>('agent_get', { path })
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  if (!tauriRuntime) return browserRequest<T>('POST', path, body ?? {})
  const { invoke } = await import('@tauri-apps/api/core')
  return invoke<T>('agent_post', { path, body: body !== undefined ? JSON.stringify(body) : '{}' })
}

async function del<T>(path: string): Promise<T> {
  if (!tauriRuntime) return browserRequest<T>('DELETE', path)
  const { invoke } = await import('@tauri-apps/api/core')
  return invoke<T>('agent_delete', { path })
}

export async function invokePlatform<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  if (tauriRuntime) {
    const { invoke } = await import('@tauri-apps/api/core')
    return invoke<T>(command, args)
  }
  switch (command) {
    case 'security_check':
      return browserRequest<T>('GET', 'system/security')
    case 'agent_has_caps': {
      const result = await browserRequest<{ granted: boolean }>('GET', 'system/capabilities')
      return result.granted as T
    }
    case 'grant_agent_permissions':
      return browserRequest<T>('POST', 'system/capabilities', { extended: false })
    case 'grant_dns_protection_caps':
      return browserRequest<T>('POST', 'system/capabilities', { extended: true })
    case 'revert_agent_permissions':
      return browserRequest<T>('DELETE', 'system/capabilities')
    case 'restart_agent_cmd':
      return browserRequest<T>('POST', 'app/restart', {})
    case 'quit_app':
      return browserRequest<T>('POST', 'app/quit', {})
    case 'autostart_is_enabled': {
      const result = await browserRequest<{ enabled: boolean }>('GET', 'system/autostart')
      return result.enabled as T
    }
    case 'autostart_set':
      return browserRequest<T>('POST', 'system/autostart', { enabled: Boolean(args.enabled) })
    case 'open_oauth_url': {
      const raw = String(args.url ?? '')
      // The browser shell has a single working tab. Navigating it preserves
      // the user journey: dashboard → Authentik → loopback callback → dashboard.
      window.location.assign(raw)
      return undefined as T
    }
    default:
      throw new Error(`unsupported_browser_command:${command}`)
  }
}

export async function listenPlatform<T>(
  eventName: string,
  callback: (event: { payload: T }) => void,
): Promise<() => void> {
  if (!tauriRuntime) return () => undefined
  const { listen } = await import('@tauri-apps/api/event')
  return listen<T>(eventName, callback)
}

export async function revealPlatformWindow(): Promise<void> {
  if (!tauriRuntime) {
    window.focus()
    return
  }
  const { getCurrentWindow } = await import('@tauri-apps/api/window')
  const current = getCurrentWindow()
  await current.show()
  await current.setFocus()
}

export async function minimizePlatformWindow(): Promise<void> {
  if (!tauriRuntime) return
  const { getCurrentWindow } = await import('@tauri-apps/api/window')
  await getCurrentWindow().minimize()
}

export async function hidePlatformWindow(): Promise<void> {
  if (!tauriRuntime) {
    window.close()
    return
  }
  const { getCurrentWindow } = await import('@tauri-apps/api/window')
  await getCurrentWindow().hide()
}

export async function startPlatformDragging(): Promise<void> {
  if (!tauriRuntime) return
  const { getCurrentWindow } = await import('@tauri-apps/api/window')
  await getCurrentWindow().startDragging()
}

async function relayBrowserEvents(signal: AbortSignal, dispatch: (payload: AgentRelayEvent) => void): Promise<void> {
  loadBrowserAgentToken()
  const response = await fetch('/events', {
    cache: 'no-store',
    credentials: 'omit',
    headers: { 'X-Agent-Token': browserAgentToken },
    signal,
  })
  if (!response.ok || !response.body) throw new Error(`agent_events_http_${response.status}`)

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let buffer = ''
  while (!signal.aborted) {
    const { done, value } = await reader.read()
    if (done) return
    buffer += decoder.decode(value, { stream: true }).replace(/\r\n/g, '\n')
    let boundary = buffer.indexOf('\n\n')
    while (boundary >= 0) {
      const frame = buffer.slice(0, boundary)
      buffer = buffer.slice(boundary + 2)
      let event = 'message'
      const data: string[] = []
      for (const line of frame.split('\n')) {
        if (line.startsWith('event:')) event = line.slice(6).trim()
        if (line.startsWith('data:')) data.push(line.slice(5).trimStart())
      }
      if (data.length > 0) {
        dispatch({ event, data: JSON.parse(data.join('\n')) as AgentSnapshot })
      }
      boundary = buffer.indexOf('\n\n')
    }
  }
}

async function abortableDelay(signal: AbortSignal, duration: number): Promise<void> {
  if (signal.aborted) return
  await new Promise<void>((resolve) => {
    const timeout = window.setTimeout(resolve, duration)
    signal.addEventListener('abort', () => {
      window.clearTimeout(timeout)
      resolve()
    }, { once: true })
  })
}

async function relayBrowserEventsWithReconnect(
  signal: AbortSignal,
  dispatch: (payload: AgentRelayEvent) => void,
  reportError: (error: unknown) => void,
): Promise<void> {
  let retryDelay = 250
  while (!signal.aborted) {
    try {
      await relayBrowserEvents(signal, dispatch)
      retryDelay = 250
    } catch (error) {
      if (signal.aborted) return
      reportError(error)
    }
    await abortableDelay(signal, retryDelay)
    retryDelay = Math.min(retryDelay * 2, 5_000)
  }
}

// ── API ──────────────────────────────────────────────────────────────────────

export const agent = {
  /** Get current snapshot of all state */
  status: () => get<AgentSnapshot>('status'),

  /** Subscribe to Rust-relayed agent events; returns cleanup fn */
  subscribe(cb: (e: AgentEvent) => void): () => void {
    let stopped = false
    let unlisten: (() => void) | null = null

    const dispatch = (payload: AgentRelayEvent) => {
      if (stopped) return
      const snap = payload.data
      if (payload.event === 'vpn_status') cb({ type: 'vpn_status', data: snap.vpn })
      else if (payload.event === 'mesh_status') cb({ type: 'mesh_status', data: snap.mesh })
      else if (payload.event === 'auth_status') cb({ type: 'auth_status', data: snap.auth })
      else if (payload.event === 'protection_status') cb({ type: 'protection_status', data: snap.protection })
      else if (payload.event === 'snapshot') {
        cb({ type: 'vpn_status', data: snap.vpn })
        cb({ type: 'mesh_status', data: snap.mesh })
        cb({ type: 'auth_status', data: snap.auth })
        cb({ type: 'protection_status', data: snap.protection })
      }
    }

    if (tauriRuntime) {
      void import('@tauri-apps/api/event').then(({ listen }) =>
        listen<AgentRelayEvent>('agent://event', (event) => dispatch(event.payload)),
      ).then((fn) => {
        if (stopped) fn()
        else unlisten = fn
      }).catch((e) => cb({ type: 'error', data: { message: String(e) } }))
    } else {
      const controller = new AbortController()
      unlisten = () => controller.abort()
      void relayBrowserEventsWithReconnect(controller.signal, dispatch, (error) => {
        if (!stopped) cb({ type: 'error', data: { message: String(error) } })
      })
    }

    return () => {
      stopped = true
      unlisten?.()
    }
  },

  auth: {
    setTokens: (access_token: string, refresh_token: string, expires_in: number) =>
      post<void>('auth/set-tokens', { access_token, refresh_token, expires_in }),
    logout: () => del<void>('auth/logout'),
    refresh: () => post<void>('auth/refresh'),
  },

  servers: {
    list: () => get<Server[]>('servers'),
  },

  vpn: {
    connect: (server_id: string, protocol = 'smart_auto') =>
      post<void>('vpn/connect', { server_id, protocol }),
    disconnect: () => post<void>('vpn/disconnect'),
  },

  mesh: {
    enable: () => post<{ ok: boolean; firewall_warning?: string }>('mesh/enable'),
    disable: () => post<void>('mesh/disable'),
    listExitNodes: () => get<ExitNode[]>('mesh/exit-nodes'),
    setExitNode: (mesh_ip: string, proxy_port: number, proxy_scheme = 'socks5') => post<void>('mesh/exit-node', { mesh_ip, proxy_port, proxy_scheme }),
    clearExitNode: () => del<void>('mesh/exit-node'),
    enableFullTunnel: (mesh_ip: string, proxy_port: number, proxy_scheme = 'socks5') =>
      post<void>('mesh/full-tunnel/enable', { mesh_ip, proxy_port, proxy_scheme }),
    disableFullTunnel: () => post<void>('mesh/full-tunnel/disable'),
  },

  oauth: {
    /** Returns the Authentik authorization URL to open in the system browser. */
    start: () => post<{ url: string }>('oauth/start'),
  },

  settings: {
    get: () => get<UserSettings>('settings'),
    // Backend exposes the same handler under POST /settings so we can use
    // the existing Tauri `agent_post` bridge here.
    put: (s: UserSettings) => post<UserSettings>('settings', s),
  },

  dns: {
    /** Reports the active DNS backend and whether extra caps are needed. */
    status: () => get<DnsStatus>('dns/status'),
  },
}

export interface DnsStatus {
  backend: 'resolved' | 'resolvconf' | 'none'
  needs_extra_caps: boolean
  caps_missing: string[]
  caps_ok: boolean
}

export interface UserSettings {
  mesh?: { start_disabled?: boolean }
  autostart?: { enabled?: boolean }
  ui?: { start_minimized?: boolean; language?: string }
}
