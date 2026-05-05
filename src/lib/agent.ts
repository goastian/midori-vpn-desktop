/**
 * agent.ts — typed HTTP client for the local Go agent at localhost:7071
 * Used from Vue components/stores to talk to the running agent sidecar.
 */

const BASE = 'http://127.0.0.1:7071'

// ── Types ────────────────────────────────────────────────────────────────────

export interface VPNStatus {
  connected: boolean
  server_name: string
  server_ip: string
  assigned_ip: string
  bytes_up: number
  bytes_down: number
  connected_at: string | null
}

export interface MeshStatus {
  enabled: boolean
  mesh_id: string
  public_key: string
  mesh_ip: string
  exit_node_active: boolean
  proxy_port: number
}

export interface AuthStatus {
  authenticated: boolean
  user_id: string
  email: string
  expires_at: string | null
}

export interface AgentSnapshot {
  vpn: VPNStatus
  mesh: MeshStatus
  auth: AuthStatus
}

export interface Server {
  id: string
  name: string
  ip: string
  country: string
  city: string
  load: number
}

export interface ExitNode {
  user_id: string
  mesh_ip: string
  proxy_port: number
  online: boolean
}

export type AgentEvent =
  | { type: 'vpn_status'; data: VPNStatus }
  | { type: 'mesh_status'; data: MeshStatus }
  | { type: 'auth_status'; data: AuthStatus }
  | { type: 'error'; data: { message: string } }

// ── HTTP helpers ─────────────────────────────────────────────────────────────

async function get<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}/${path}`)
  if (!r.ok) throw new Error(await r.text())
  return r.json() as Promise<T>
}

async function post<T>(path: string, body?: unknown): Promise<T> {
  const r = await fetch(`${BASE}/${path}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  if (!r.ok) throw new Error(await r.text())
  return r.json() as Promise<T>
}

async function del<T>(path: string): Promise<T> {
  const r = await fetch(`${BASE}/${path}`, { method: 'DELETE' })
  if (!r.ok) throw new Error(await r.text())
  return r.json() as Promise<T>
}

// ── API ──────────────────────────────────────────────────────────────────────

export const agent = {
  /** Get current snapshot of all state */
  status: () => get<AgentSnapshot>('status'),

  /** Subscribe to SSE events; returns cleanup fn */
  subscribe(cb: (e: AgentEvent) => void): () => void {
    const es = new EventSource(`${BASE}/events`)
    es.onmessage = (e) => {
      try {
        cb(JSON.parse(e.data) as AgentEvent)
      } catch {
        // ignore parse errors
      }
    }
    return () => es.close()
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
    enable: () => post<void>('mesh/enable'),
    disable: () => post<void>('mesh/disable'),
    listExitNodes: () => get<ExitNode[]>('mesh/exit-nodes'),
    setExitNode: (user_id: string) => post<void>('mesh/exit-node', { user_id }),
    clearExitNode: () => del<void>('mesh/exit-node'),
  },
}
