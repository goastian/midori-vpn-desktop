import { defineStore } from 'pinia'
import { ref } from 'vue'
import { agent, type Server, type VPNStatus } from '../lib/agent'
import { toErrorMessage } from '../lib/error'

export const useVpnStore = defineStore('vpn', () => {
  const connected = ref(false)
  const serverName = ref('')
  const serverIp = ref('')
  const assignedIp = ref('')
  const serverPublicIp = ref('')
  const bytesUp = ref(0)
  const bytesDown = ref(0)
  const connectedAt = ref<string | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const servers = ref<Server[]>([])

  function applyStatus(s: VPNStatus) {
    connected.value = s.connected
    serverName.value = s.server_name
    // Historical name kept for template compatibility; this is the backend
    // VPN server id, not an IP address.
    serverIp.value = s.server_id
    assignedIp.value = s.assigned_ip
    serverPublicIp.value = s.server_public_ip ?? ''
    bytesUp.value = s.bytes_sent
    bytesDown.value = s.bytes_recv
    connectedAt.value = null
  }

  async function fetchServers() {
    loading.value = true
    error.value = null
    try {
      servers.value = await agent.servers.list()
    } catch (e) {
      error.value = toErrorMessage(e)
    } finally {
      loading.value = false
    }
  }

  async function connect(serverId: string) {
    // Re-entry guard: if a connect is already in flight, ignore the duplicate call.
    if (loading.value) return
    loading.value = true
    error.value = null
    try {
      await agent.vpn.connect(serverId)
    } catch (e) {
      error.value = toErrorMessage(e)
      // If the agent reported a definitive auth failure it already cleared the
      // session and broadcast an SSE auth_status event → App.vue watch handles
      // the redirect to /login. Don't call auth.logout() here: the optimistic
      // state reset would immediately navigate away before the user sees the error.
    } finally {
      loading.value = false
    }
  }

  async function disconnect() {
    // Optimistic UI reset first, then await the actual agent call
    connected.value = false
    serverName.value = ''
    serverIp.value = ''
    assignedIp.value = ''
    serverPublicIp.value = ''
    bytesUp.value = 0
    bytesDown.value = 0
    error.value = null
    await agent.vpn.disconnect().catch(() => {/* best-effort */})
  }

  function clearServers() {
    servers.value = []
  }

  return {
    connected, serverName, serverIp, assignedIp, serverPublicIp,
    bytesUp, bytesDown, connectedAt, loading, error, servers,
    applyStatus, fetchServers, connect, disconnect, clearServers,
  }
})
