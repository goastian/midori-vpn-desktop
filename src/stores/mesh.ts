import { defineStore } from 'pinia'
import { onScopeDispose, ref } from 'vue'
import { agent, type ExitNode, type MeshStatus } from '../lib/agent'
import { toErrorMessage } from '../lib/error'
import { isValidMeshIp, isValidPort, isValidProxyScheme } from '../lib/meshValidation'

/** Mesh operation state machine.
 *  idle → enabling → enabled → disabling → idle
 *  Any state → error (on failure, stays in previous stable state)
 */
export type MeshState = 'idle' | 'enabling' | 'enabled' | 'disabling' | 'error'

const REFRESH_INTERVAL_MS = 60_000 // 1 minute

export const useMeshStore = defineStore('mesh', () => {
  const meshState = ref<MeshState>('idle')
  const enabled = ref(false)
  const meshId = ref('')
  const publicKey = ref('')
  const meshIp = ref('')
  const exitNodeActive = ref(false)
  const fullTunnel = ref(false)
  const proxyPort = ref(0)
  const proxyScheme = ref('')
  const exitNodes = ref<ExitNode[]>([])
  /** Simple boolean kept for backward compatibility with existing template bindings. */
  const loading = ref(false)
  const error = ref<string | null>(null)

  let refreshTimer: ReturnType<typeof setInterval> | null = null

  function applyStatus(s: MeshStatus) {
    const wasEnabled = enabled.value
    enabled.value = s.active
    meshId.value = s.mesh_id
    publicKey.value = ''
    meshIp.value = s.mesh_ip
    exitNodeActive.value = s.is_exit_node
    fullTunnel.value = s.full_tunnel
    proxyPort.value = s.exit_node_port ?? 0
    proxyScheme.value = s.exit_node_scheme ?? ''

    // Reconcile state machine with authoritative backend state.
    if (s.active && meshState.value !== 'enabled') {
      meshState.value = 'enabled'
    } else if (!s.active && (meshState.value === 'enabled' || meshState.value === 'enabling')) {
      meshState.value = 'idle'
    }

    // Start/stop auto-refresh based on mesh being active.
    if (s.active && !wasEnabled) {
      startRefreshTimer()
    } else if (!s.active && wasEnabled) {
      stopRefreshTimer()
    }

    error.value = null
  }

  function startRefreshTimer() {
    stopRefreshTimer()
    refreshTimer = setInterval(() => {
      if (enabled.value) fetchExitNodes()
    }, REFRESH_INTERVAL_MS)
  }

  function stopRefreshTimer() {
    if (refreshTimer) {
      clearInterval(refreshTimer)
      refreshTimer = null
    }
  }

  async function enable() {
    // Allow retry from `error`; only block if a transition is in flight.
    if (meshState.value === 'enabling' || meshState.value === 'disabling') return
    meshState.value = 'enabling'
    loading.value = true
    error.value = null
    try {
      const res = await agent.mesh.enable()
      if (res.firewall_warning) {
        error.value = `Mesh activo, pero falló la configuración de firewall: ${res.firewall_warning}`
      }
      // SSE will fire mesh_status → applyStatus reconciles state to 'enabled'.
    } catch (e) {
      error.value = toErrorMessage(e)
      meshState.value = 'error'
    } finally {
      loading.value = false
    }
  }

  async function disable() {
    // Allow retry from `error`; only block if a transition is in flight.
    if (meshState.value === 'enabling' || meshState.value === 'disabling') return
    meshState.value = 'disabling'
    loading.value = true
    error.value = null
    stopRefreshTimer()
    try {
      await agent.mesh.disable()
      // SSE will fire mesh_status → applyStatus reconciles state to 'idle'.
    } catch (e) {
      error.value = toErrorMessage(e)
      meshState.value = 'error'
    } finally {
      loading.value = false
    }
  }

  /** Clear error state and return to a stable state. Useful when the user
   *  dismisses an error banner or wants to retry a failed transition.
   */
  function clearError() {
    error.value = null
    if (meshState.value === 'error') {
      meshState.value = enabled.value ? 'enabled' : 'idle'
    }
  }

  async function fetchExitNodes() {
    try {
      const all = await agent.mesh.listExitNodes()

      // Validate and dedupe by key (mesh_ip:proxy_port:proxy_scheme).
      const seen = new Set<string>()
      exitNodes.value = all.filter(n => {
        // Filter own node.
        if (n.mesh_ip === meshIp.value) return false
        // Validate fields.
        if (!isValidMeshIp(n.mesh_ip)) return false
        if (!isValidPort(n.proxy_port)) return false
        const scheme = n.proxy_scheme || 'socks5'
        if (!isValidProxyScheme(scheme)) return false
        // Dedupe.
        const key = `${n.mesh_ip}:${n.proxy_port}:${scheme}`
        if (seen.has(key)) return false
        seen.add(key)
        return true
      })
    } catch (e) {
      // Non-fatal: peers list failure must not surface as mesh toggle error.
      // Silently swallowed here; the caller can read mesh.error if needed.
      void e
    }
  }

  async function setExitNode(exitMeshIp: string, port: number, scheme = 'socks5') {
    error.value = null
    try {
      await agent.mesh.enableFullTunnel(exitMeshIp, port, scheme)
    } catch (e) {
      error.value = toErrorMessage(e)
    }
  }

  async function clearExitNode() {
    error.value = null
    try {
      await agent.mesh.disableFullTunnel()
    } catch (e) {
      error.value = toErrorMessage(e)
    }
  }
  // Ensure the timer is stopped when the store's reactive scope is disposed
  // (e.g. when the app is unmounted or HMR replaces the store).
  onScopeDispose(stopRefreshTimer)
  return {
    meshState, enabled, meshId, publicKey, meshIp, exitNodeActive, fullTunnel,
    proxyPort, proxyScheme, exitNodes, loading, error,
    applyStatus, enable, disable, clearError, fetchExitNodes, setExitNode, clearExitNode,
  }
})
