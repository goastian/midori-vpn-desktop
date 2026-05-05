<template>
  <div class="app">
    <nav class="nav">
      <RouterLink to="/" class="nav-link" :class="{ active: $route.path === '/' }">VPN</RouterLink>
      <RouterLink to="/mesh" class="nav-link" :class="{ active: $route.path === '/mesh' }">Mesh</RouterLink>
      <RouterLink to="/settings" class="nav-link" :class="{ active: $route.path === '/settings' }">Settings</RouterLink>
    </nav>
    <main class="main">
      <RouterView />
    </main>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted } from 'vue'
import { RouterLink, RouterView } from 'vue-router'
import { agent } from './lib/agent'
import { useVpnStore } from './stores/vpn'
import { useMeshStore } from './stores/mesh'
import { useAuthStore } from './stores/auth'

const vpnStore = useVpnStore()
const meshStore = useMeshStore()
const authStore = useAuthStore()

// Load initial snapshot
async function loadSnapshot() {
  const snap = await agent.status()
  vpnStore.applyStatus(snap.vpn)
  meshStore.applyStatus(snap.mesh)
  authStore.applyStatus(snap.auth)
}

// Subscribe to live events
let unsubscribe: (() => void) | null = null

onMounted(async () => {
  await loadSnapshot()
  unsubscribe = agent.subscribe((event) => {
    if (event.type === 'vpn_status') vpnStore.applyStatus(event.data)
    else if (event.type === 'mesh_status') meshStore.applyStatus(event.data)
    else if (event.type === 'auth_status') authStore.applyStatus(event.data)
  })
})

onUnmounted(() => {
  unsubscribe?.()
})
</script>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #0f0f1a; color: #e0e0ef; }
</style>
