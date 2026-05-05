<template>
  <div>
    <!-- Connection card -->
    <div class="card">
      <div class="row" style="margin-bottom: 16px;">
        <div>
          <span class="status-dot" :class="vpn.connected ? 'connected' : 'disconnected'"></span>
          <span style="font-size: 15px; font-weight: 600;">
            {{ vpn.connected ? 'Connected' : 'Disconnected' }}
          </span>
        </div>
        <button
          class="btn"
          :class="vpn.connected ? 'btn-danger' : 'btn-primary'"
          :disabled="vpn.loading"
          @click="toggleVpn"
        >
          {{ vpn.loading ? '...' : vpn.connected ? 'Disconnect' : 'Connect' }}
        </button>
      </div>

      <div v-if="!vpn.connected" style="margin-bottom: 12px;">
        <div class="label">Server</div>
        <select v-model="selectedServer">
          <option v-for="s in vpn.servers" :key="s.id" :value="s.id">
            {{ s.name }} — {{ s.city }}, {{ s.country }}
          </option>
        </select>
      </div>

      <div v-if="vpn.connected" class="stats-grid">
        <div>
          <div class="label">Your VPN IP</div>
          <div class="value">{{ vpn.assignedIp || '—' }}</div>
        </div>
        <div>
          <div class="label">Server</div>
          <div class="value">{{ vpn.serverName || '—' }}</div>
        </div>
        <div>
          <div class="label">Upload</div>
          <div class="value">{{ formatBytes(vpn.bytesUp) }}</div>
        </div>
        <div>
          <div class="label">Download</div>
          <div class="value">{{ formatBytes(vpn.bytesDown) }}</div>
        </div>
      </div>

      <div v-if="vpn.error" class="error">{{ vpn.error }}</div>
    </div>

    <!-- Auth card -->
    <div class="card" v-if="!auth.authenticated">
      <div class="section-title">Sign In</div>
      <div class="label" style="margin-bottom:8px">Paste your tokens from the web portal</div>
      <textarea
        v-model="tokenJson"
        placeholder='{"access_token":"...","refresh_token":"...","expires_in":3600}'
        style="width:100%;background:#1e1e35;border:1px solid #2a2a45;border-radius:8px;color:#e0e0ef;padding:8px;font-size:12px;font-family:monospace;resize:vertical;min-height:80px;"
      ></textarea>
      <button class="btn btn-primary" style="margin-top:8px" @click="doLogin">Sign In</button>
      <div v-if="loginError" class="error">{{ loginError }}</div>
    </div>

    <div class="card" v-else>
      <div class="row">
        <div>
          <div class="label">Signed in as</div>
          <div class="value">{{ auth.email || auth.userId }}</div>
        </div>
        <button class="btn btn-secondary" @click="auth.logout()">Logout</button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useVpnStore } from '../stores/vpn'
import { useAuthStore } from '../stores/auth'

const vpn = useVpnStore()
const auth = useAuthStore()

const selectedServer = ref('')
const tokenJson = ref('')
const loginError = ref('')

onMounted(async () => {
  await vpn.fetchServers()
  if (vpn.servers.length > 0) selectedServer.value = vpn.servers[0].id
})

async function toggleVpn() {
  if (vpn.connected) {
    await vpn.disconnect()
  } else {
    await vpn.connect(selectedServer.value)
  }
}

async function doLogin() {
  loginError.value = ''
  try {
    const parsed = JSON.parse(tokenJson.value)
    await auth.setTokens(parsed.access_token, parsed.refresh_token, parsed.expires_in ?? 3600)
    tokenJson.value = ''
  } catch (e) {
    loginError.value = String(e)
  }
}

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1024 / 1024).toFixed(2)} MB`
}
</script>

<style scoped>
.stats-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
</style>
