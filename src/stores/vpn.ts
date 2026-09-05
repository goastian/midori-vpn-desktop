import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import { agent, type Server, type VPNConnectionPhase, type VPNDisconnectReason, type VPNRequestedProtocol, type VPNSelectionMode, type VPNStatus, type VPNTransportProtocol } from '../lib/agent'
import { toErrorMessage } from '../lib/error'

export const useVpnStore = defineStore('vpn', () => {
  const connected = ref(false)
  const connectionId = ref('')
  const serverName = ref('')
  const serverIp = ref('')
  const assignedIp = ref('')
  const serverPublicIp = ref('')
  const bytesUp = ref(0)
  const bytesDown = ref(0)
  const connectedAt = ref<string | null>(null)
  const phase = ref<VPNConnectionPhase>('disconnected')
  const requestedProtocol = ref<VPNRequestedProtocol | null>(null)
  const activeProtocol = ref<VPNTransportProtocol | null>(null)
  const fallbackReason = ref<string | null>(null)
  const failoverFrom = ref<string | null>(null)
  const selectionMode = ref<VPNSelectionMode>('automatic')
  const manualServerId = ref('')
  const loading = ref(false)
  const error = ref<string | null>(null)
  const servers = ref<Server[]>([])
  const connectionInProgress = computed(() =>
    ['preparing', 'authenticating', 'negotiating', 'protecting', 'reconnecting', 'disconnecting'].includes(phase.value),
  )
  const reconnecting = computed(() => phase.value === 'reconnecting')
  const canDisconnect = computed(() => connected.value || reconnecting.value)

  function applyStatus(s: VPNStatus) {
    connected.value = s.connected
    phase.value = s.phase || (s.connected ? 'connected' : 'disconnected')
    connectionId.value = s.connection_id ?? ''
    serverName.value = s.server_name
    serverIp.value = s.server_id
    assignedIp.value = s.assigned_ip
    serverPublicIp.value = s.server_public_ip ?? ''
    bytesUp.value = s.bytes_sent
    bytesDown.value = s.bytes_recv
    requestedProtocol.value = s.requested_protocol || null
    activeProtocol.value = s.active_protocol || null
    if (s.selection_mode) selectionMode.value = s.selection_mode
    fallbackReason.value = s.fallback_reason || null
    failoverFrom.value = s.failover_from || null
    connectedAt.value = null
  }

  async function fetchSelectionSettings() {
    try {
      const persisted = (await agent.settings.get()).vpn
      if (persisted?.selection_mode === 'automatic' || persisted?.selection_mode === 'manual') {
        selectionMode.value = persisted.selection_mode
      }
      manualServerId.value = persisted?.manual_server_id ?? ''
    } catch {
      // The agent default is automatic. A later successful connect persists
      // the explicit choice even if this non-critical bootstrap read failed.
    }
  }

  async function fetchServers(forceRefresh = false) {
    loading.value = true
    error.value = null
    try {
      servers.value = forceRefresh
        ? await agent.servers.refresh()
        : await agent.servers.list()
    } catch (e) {
      error.value = toErrorMessage(e)
    } finally {
      loading.value = false
    }
  }

  async function connect(serverId: string, mode: VPNSelectionMode = 'manual') {
    // Re-entry guard: if a connect is already in flight, ignore the duplicate call.
    if (loading.value || connectionInProgress.value) return
    loading.value = true
    error.value = null
    try {
      const protocol = localStorage.getItem('midori_protocol_policy') || 'smart_auto'
      await agent.vpn.connect(serverId, protocol, mode)
      selectionMode.value = mode
      manualServerId.value = mode === 'manual' ? serverId : ''
      try {
        applyStatus((await agent.status()).vpn)
      } catch {
        // The SSE snapshot remains authoritative if this immediate refresh is unavailable.
      }
    } catch (e) {
      if (isAmbiguousLocalRPCError(e) && await reconcileConnection(serverId, mode)) {
        error.value = null
        return
      }
      error.value = toErrorMessage(e)
      // If the agent reported a definitive auth failure it already cleared the
      // session and broadcast an SSE auth_status event → App.vue watch handles
      // the redirect to /login. Don't call auth.logout() here: the optimistic
      // state reset would immediately navigate away before the user sees the error.
    } finally {
      loading.value = false
    }
  }

  async function reconcileConnection(serverId: string, mode: VPNSelectionMode): Promise<boolean> {
    const delays = [0, 250, 500, 1_000, 2_000]
    for (const delay of delays) {
      if (delay > 0) await new Promise(resolve => setTimeout(resolve, delay))
      try {
        const status = (await agent.status()).vpn
        applyStatus(status)
        if (status.connected && (mode === 'automatic' || status.server_id === serverId)) return true
        if (status.phase === 'error') return false
      } catch {
        // A loopback restart can also make the status probe transiently unavailable.
      }
    }
    return false
  }

  async function disconnect(reason: VPNDisconnectReason) {
    if (!canDisconnect.value) return true
    if (!connectionId.value) {
      error.value = toErrorMessage(new Error('ERR_VPN_CONNECTION_CHANGED'))
      return false
    }
    loading.value = true
    error.value = null
    try {
      await agent.vpn.disconnect(connectionId.value, reason)
      connected.value = false
      phase.value = 'disconnected'
      connectionId.value = ''
      serverName.value = ''
      serverIp.value = ''
      assignedIp.value = ''
      serverPublicIp.value = ''
      failoverFrom.value = null
      bytesUp.value = 0
      bytesDown.value = 0
      return true
    } catch (e) {
      error.value = toErrorMessage(e)
      return false
    } finally {
      loading.value = false
    }
  }

  function clearServers() {
    servers.value = []
  }

  return {
    connected, connectionId, serverName, serverIp, assignedIp, serverPublicIp,
    bytesUp, bytesDown, connectedAt, phase, requestedProtocol, activeProtocol, fallbackReason, failoverFrom,
    selectionMode, manualServerId, reconnecting, canDisconnect,
    connectionInProgress, loading, error, servers,
    applyStatus, fetchServers, fetchSelectionSettings, connect, disconnect, clearServers,
  }
})

function isAmbiguousLocalRPCError(error: unknown): boolean {
  const message = String(error).toLowerCase()
  return error instanceof TypeError || [
    'failed to fetch',
    'networkerror',
    'network error',
    'load failed',
    'connection refused',
    'error sending request',
  ].some(fragment => message.includes(fragment))
}
