import { defineStore } from 'pinia'
import { ref } from 'vue'
import { agent, type ExitNode, type MeshStatus } from '../lib/agent'

export const useMeshStore = defineStore('mesh', () => {
  const enabled = ref(false)
  const meshId = ref('')
  const publicKey = ref('')
  const meshIp = ref('')
  const exitNodeActive = ref(false)
  const proxyPort = ref(0)
  const exitNodes = ref<ExitNode[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)

  function applyStatus(s: MeshStatus) {
    enabled.value = s.enabled
    meshId.value = s.mesh_id
    publicKey.value = s.public_key
    meshIp.value = s.mesh_ip
    exitNodeActive.value = s.exit_node_active
    proxyPort.value = s.proxy_port
  }

  async function enable() {
    loading.value = true
    error.value = null
    try { await agent.mesh.enable() } catch (e) { error.value = String(e) } finally { loading.value = false }
  }

  async function disable() {
    loading.value = true
    error.value = null
    try { await agent.mesh.disable() } catch (e) { error.value = String(e) } finally { loading.value = false }
  }

  async function fetchExitNodes() {
    exitNodes.value = await agent.mesh.listExitNodes()
  }

  async function setExitNode(userId: string) {
    await agent.mesh.setExitNode(userId)
  }

  async function clearExitNode() {
    await agent.mesh.clearExitNode()
  }

  return {
    enabled, meshId, publicKey, meshIp, exitNodeActive, proxyPort,
    exitNodes, loading, error,
    applyStatus, enable, disable, fetchExitNodes, setExitNode, clearExitNode,
  }
})
