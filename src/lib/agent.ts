/**
 * agent.ts — typed client for the local Go agent at localhost:7071.
 *
 * HTTP calls (GET/POST/DELETE) go through the Tauri Rust commands
 * (agent_get / agent_post / agent_delete → reqwest) because direct
 * fetch from the WebView to http:// is blocked by Tauri's security model.
 *
 * Live events are relayed by Rust/Tauri so the WebView never receives the
 * ephemeral local RPC token.
 */

import { invoke } from '@tauri-apps/api/core'
import { listen, type UnlistenFn } from '@tauri-apps/api/event'

/**
 * Backwards-compatible no-op kept for callers that initialise the agent
 * client before subscribing. The RPC token now stays inside Rust/Tauri.
 */
export async function initAgentToken(): Promise<void> {
  return Promise.resolve()
}

// ── Types ────────────────────────────────────────────────────────────────────

export interface VPNStatus {
  connected: boolean
  server_name: string
  server_id: string
  assigned_ip: string
  server_public_ip: string
  mesh_ip: string
  bytes_sent: number
  bytes_recv: number
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
  proxy_port: number
  supports_wireguard: boolean
  supports_proxy: boolean
  supports_mesh_exit: boolean
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

async function get<T>(path: string): Promise<T> {
  return invoke<T>('agent_get', { path })
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  return invoke<T>('agent_post', { path, body: body !== undefined ? JSON.stringify(body) : '{}' })
}

async function del<T>(path: string): Promise<T> {
  return invoke<T>('agent_delete', { path })
}

// ── API ──────────────────────────────────────────────────────────────────────

export const agent = {
  /** Get current snapshot of all state */
  status: () => get<AgentSnapshot>('status'),

  /** Subscribe to Rust-relayed agent events; returns cleanup fn */
  subscribe(cb: (e: AgentEvent) => void): () => void {
    let stopped = false
    let unlisten: UnlistenFn | null = null

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

    listen<AgentRelayEvent>('agent://event', (event) => dispatch(event.payload))
      .then((fn) => {
        if (stopped) fn()
        else unlisten = fn
      })
      .catch((e) => {
        cb({ type: 'error', data: { message: String(e) } })
      })

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
    connect: (server_id: string) => post<void>('vpn/connect', { server_id }),
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
}

export interface UserSettings {
  mesh?: { start_disabled?: boolean }
  autostart?: { enabled?: boolean }
}
