import { defineStore } from 'pinia'
import { ref } from 'vue'
import { agent, type Server, type VPNStatus } from '../lib/agent'

export const useVpnStore = defineStore('vpn', () => {
  const connected = ref(false)
  const serverName = ref('')
  const serverIp = ref('')
  const assignedIp = ref('')
  const bytesUp = ref(0)
  const bytesDown = ref(0)
  const connectedAt = ref<string | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  const servers = ref<Server[]>([])

  function applyStatus(s: VPNStatus) {
    connected.value = s.connected
    serverName.value = s.server_name
    serverIp.value = s.server_ip
    assignedIp.value = s.assigned_ip
    bytesUp.value = s.bytes_up
    bytesDown.value = s.bytes_down
    connectedAt.value = s.connected_at
  }

  async function fetchServers() {
    servers.value = await agent.servers.list()
  }

  async function connect(serverId: string) {
    loading.value = true
    error.value = null
    try {
      await agent.vpn.connect(serverId)
    } catch (e) {
      error.value = String(e)
    } finally {
      loading.value = false
    }
  }

  async function disconnect() {
    loading.value = true
    error.value = null
    try {
      await agent.vpn.disconnect()
    } catch (e) {
      error.value = String(e)
    } finally {
      loading.value = false
    }
  }

  return {
    connected, serverName, serverIp, assignedIp,
    bytesUp, bytesDown, connectedAt, loading, error, servers,
    applyStatus, fetchServers, connect, disconnect,
  }
})
