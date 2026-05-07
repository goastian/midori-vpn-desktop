<template>
  <div>
    <!-- Permissions consent modal -->
    <PermissionsConsentModal
      :open="showPermsModal"
      :loading="capsGranting"
      :error="capsError"
      @cancel="showPermsModal = false"
      @granted="onConsentGranted"
    />

    <!-- Connection card -->
    <div class="card" :class="{ 'card--locked': featuresLocked }">
      <!-- Server picker -->
      <div v-if="auth.authenticated" class="picker-wrap" ref="pickerRef">
        <button
          class="picker-trigger"
          :disabled="serversLoading || switching || featuresLocked"
          @click="dropdownOpen = !dropdownOpen"
        >
          <template v-if="switching">
            <span class="cc-badge cc-loading">…</span>
            <span class="picker-text">
              <span class="picker-name muted">{{ t('server.switching') }}</span>
            </span>
          </template>
          <template v-else-if="serversLoading">
            <span class="cc-badge cc-loading">…</span>
            <span class="picker-text">
              <span class="picker-name muted">{{ t('server.loading') }}</span>
            </span>
          </template>
          <template v-else-if="selectedItem">
            <span class="cc-badge" :class="selectedItem.isMesh ? 'cc-mesh' : ''">
              {{ selectedItem.isMesh ? '🔗' : selectedItem.cc }}
            </span>
            <span class="picker-text">
              <span class="picker-name">{{ selectedItem.name }}</span>
              <span class="picker-sub">{{ selectedItem.ip }}</span>
            </span>
          </template>
          <template v-else>
            <span class="cc-badge cc-empty">—</span>
            <span class="picker-text">
              <span class="picker-name muted">{{ t('server.empty') }}</span>
            </span>
          </template>
          <svg
            class="picker-chevron" :class="{ open: dropdownOpen }"
            width="14" height="14" viewBox="0 0 24 24" fill="none"
          >
            <path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2"
              stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </button>

        <!-- Dropdown panel -->
        <div v-if="dropdownOpen" class="picker-panel">
          <div
            v-for="item in allItems" :key="item.key"
            class="picker-item"
            :class="{
              'picker-item--selected': selectedServer === item.key,
              'picker-item--active': isActive(item.key),
            }"
            @click="selectServer(item.key)"
          >
            <span class="cc-badge" :class="item.isMesh ? 'cc-mesh' : ''">
              {{ item.isMesh ? '🔗' : item.cc }}
            </span>
            <span class="item-text">
              <span class="item-name">{{ item.name }}</span>
              <span class="item-sub">{{ item.ip }}</span>
            </span>
            <span v-if="isActive(item.key)" class="item-active-dot"></span>
          </div>
          <div v-if="allItems.length === 0" class="picker-empty">
            {{ t('server.empty') }}
          </div>
        </div>
      </div>

      <!-- Status + connect button -->
      <div class="conn-row">
        <div class="conn-status">
          <span class="status-dot" :class="activeConnected ? 'connected' : 'disconnected'"></span>
          <span class="conn-label">{{ activeConnected ? t('vpn.connected') : t('vpn.disconnected') }}</span>
        </div>
        <button
          class="btn" :class="activeConnected ? 'btn-danger' : 'btn-primary'"
          :disabled="connectDisabled || featuresLocked"
          @click="toggleConnection"
        >
          {{ vpn.loading ? '…' : activeConnected ? t('vpn.disconnect') : t('vpn.connect') }}
        </button>
      </div>

      <!-- Stats when connected -->
      <div v-if="activeConnected" class="conn-stats">
        <template v-if="connectionType === 'vpn'">
          <div class="stat-cell">
            <div class="label">{{ t('stats.server') }}</div>
            <div class="value">{{ vpn.serverPublicIp || activeServerEndpoint || '—' }}</div>
          </div>
          <div class="stat-cell">
            <div class="label">{{ t('stats.upload') }}</div>
            <div class="value">{{ formatBytes(vpn.bytesUp) }}</div>
          </div>
          <div class="stat-cell">
            <div class="label">{{ t('stats.download') }}</div>
            <div class="value">{{ formatBytes(vpn.bytesDown) }}</div>
          </div>
        </template>
        <template v-else-if="connectionType === 'mesh'">
          <div class="stat-cell">
            <div class="label">{{ t('stats.exitNode') }}</div>
            <div class="value">{{ activeMeshExitIp || '—' }}</div>
          </div>
          <div class="stat-cell">
            <div class="label">{{ t('stats.meshIp') }}</div>
            <div class="value">{{ mesh.meshIp || '—' }}</div>
          </div>
        </template>
      </div>

      <div v-if="vpn.error" class="error">{{ vpn.error }}</div>
    </div>

    <!-- Permissions trigger: shown after login until caps are granted -->
    <div v-if="auth.authenticated && !capsGranted" class="card perms-trigger-card">
      <div class="perms-trigger-body">
        <div class="perms-trigger-icon">🔐</div>
        <div class="perms-trigger-text">
          <div class="perms-trigger-title">{{ t('perms.title') }}</div>
          <div class="perms-trigger-sub">{{ t('perms.body') }}</div>
        </div>
        <button class="btn btn-primary" :disabled="capsGranting" @click="showPermsModal = true">
          {{ capsGranting ? t('perms.applying') : t('perms.enable') }}
        </button>
      </div>
      <div v-if="capsError" class="error" style="margin-top:8px;font-size:12px">{{ capsError }}</div>
    </div>

    <!-- Auth card: not logged in -->
    <div class="card" v-if="!auth.authenticated">
      <div class="section-title">{{ t('auth.signIn') }}</div>
      <p class="hint-text">{{ t('auth.signInHint') }}</p>

      <button class="btn btn-primary" style="width:100%" :disabled="loginLoading" @click="doLogin">
        <svg v-if="loginLoading" class="spin" width="15" height="15" viewBox="0 0 24 24" fill="none"
          style="margin-right:6px" aria-hidden="true">
          <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-dasharray="30 10" />
        </svg>
        <svg v-else width="15" height="15" viewBox="0 0 24 24" fill="none"
          style="margin-right:6px" aria-hidden="true">
          <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
          <path d="M8 12h8M14 9l3 3-3 3" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        {{ loginLoading ? t('auth.waitingBrowser') : t('auth.signInWithAstian') }}
      </button>

      <p v-if="loginLoading" class="login-wait-hint">
        {{ t('auth.completeInBrowser') }}
        <button class="link-btn" @click="cancelLogin">{{ t('auth.cancelLogin') }}</button>
      </p>

      <div v-if="loginError" class="error">{{ loginError }}</div>
    </div>

    <!-- Auth card: logged in -->
    <div class="card" v-else>
      <div class="row">
        <div>
          <div class="label">{{ t('auth.activeSession') }}</div>
          <div class="value">{{ auth.email || auth.userId }}</div>
        </div>
        <button class="btn btn-secondary" :disabled="logoutLoading" @click="doLogout">
          <svg v-if="logoutLoading" class="spin" width="13" height="13" viewBox="0 0 24 24" fill="none"
            style="margin-right:5px" aria-hidden="true">
            <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-dasharray="30 10" />
          </svg>
          {{ logoutLoading ? t('auth.signingOut') : t('auth.signOut') }}
        </button>
      </div>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, onMounted, onUnmounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useVpnStore } from '../stores/vpn'
import { useAuthStore } from '../stores/auth'
import { useMeshStore } from '../stores/mesh'
import { useCaps } from '../composables/useCaps'
import PermissionsConsentModal from '../components/PermissionsConsentModal.vue'

const vpn = useVpnStore()
const { t } = useI18n()
const auth = useAuthStore()
const mesh = useMeshStore()

const selectedServer = ref('')
const serversLoading = ref(false)
const loginLoading = ref(false)
const loginError = ref('')
const logoutLoading = ref(false)
const dropdownOpen = ref(false)
const toggleInProgress = ref(false) // prevents double-click duplicate connects
const switching = ref(false)        // true while auto-switching to another server
const pickerRef = ref<HTMLElement | null>(null)
const connectionType = ref<'vpn' | 'mesh' | ''>('')
const activeMeshExitIp = ref('')

// ── Permissions ─────────────────────────────────────────────────────────────
const { capsGranted, capsGranting, capsError, featuresLocked, checkCaps, grantCaps: grantCapsBase } = useCaps()

const showPermsModal = ref(false)

/** Called when the user clicks "Aceptar y aplicar" in the modal. */
async function onConsentGranted() {
  const ok = await grantCapsBase()
  if (ok) {
    showPermsModal.value = false
    await loadServersAfterLogin()
  }
}

// ── Item model ─────────────────────────────────────────────────────────────

interface ServerItem {
  key: string
  cc: string       // 2-letter country code (or empty for mesh)
  isMesh: boolean
  name: string
  ip: string
}

const allItems = computed<ServerItem[]>(() => {
  const items: ServerItem[] = [
    ...vpn.servers.map(s => ({
      key: `vpn:${s.id}`,
      cc: (s.country_code || '').toUpperCase().slice(0, 2) || '?',
      isMesh: false,
      name: `${s.name} — ${s.location}`,
      ip: s.endpoint.split(':')[0] || s.host,
    })),
    ...(mesh.enabled ? mesh.exitNodes.map(n => ({
      key: `mesh:${n.mesh_ip}:${n.proxy_port}:${n.proxy_scheme || 'socks5'}`,
      cc: '',
      isMesh: true,
      name: `Mesh · ${n.mesh_ip}`,
      ip: `port ${n.proxy_port}`,
    })) : []),
  ]
  // Dedupe by item.key to prevent duplicates from backend or concurrent updates
  const seen = new Set<string>()
  return items.filter(item => {
    if (seen.has(item.key)) return false
    seen.add(item.key)
    return true
  })
})

const selectedItem = computed(() =>
  allItems.value.find(i => i.key === selectedServer.value) ?? null
)

const activeServerEndpoint = computed(() => {
  const s = vpn.servers.find(s => s.id === vpn.serverIp)
  return s ? (s.endpoint.split(':')[0] || s.host) : ''
})

// ── Connection state ────────────────────────────────────────────────────────

const activeConnected = computed(() =>
  vpn.connected || (mesh.enabled && mesh.fullTunnel)
)

const connectDisabled = computed(() => {
  if (vpn.loading || toggleInProgress.value) return true
  if (activeConnected.value) return false
  return !auth.authenticated || serversLoading.value || !selectedServer.value
})

function isActive(key: string): boolean {
  if (!activeConnected.value) return false
  if (connectionType.value === 'vpn') return key === `vpn:${vpn.serverIp}`
  if (connectionType.value === 'mesh') return key.startsWith(`mesh:${activeMeshExitIp.value}:`)
  return false
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

onMounted(async () => {
  await checkCaps()
  await loadServersAfterLogin()
  document.addEventListener('click', onClickOutside)
})

onUnmounted(() => {
  document.removeEventListener('click', onClickOutside)
})

function onClickOutside(e: MouseEvent) {
  if (pickerRef.value && !pickerRef.value.contains(e.target as Node)) {
    dropdownOpen.value = false
  }
}

watch(() => auth.authenticated, async (v) => {
  if (v) {
    loginLoading.value = false  // OAuth completed → stop the waiting spinner
    loginError.value = ''
    await checkCaps()
    if (capsGranted.value) await loadServersAfterLogin()
  } else {
    selectedServer.value = ''; vpn.error = null; vpn.clearServers()
  }
})
watch(() => mesh.enabled, async (v) => {
  if (v && auth.authenticated) { await mesh.fetchExitNodes(); syncSelectedServer() }
})
watch(() => vpn.connected, (v) => { if (v) connectionType.value = 'vpn' })
watch(() => mesh.fullTunnel, (v) => {
  if (v) connectionType.value = 'mesh'
  else if (!vpn.connected) connectionType.value = ''
})

// ── Data loading ────────────────────────────────────────────────────────────

async function loadServersAfterLogin() {
  if (!auth.authenticated || featuresLocked.value) { vpn.error = null; return }
  if (serversLoading.value) return
  vpn.error = null
  serversLoading.value = true
  try {
    await vpn.fetchServers()
    if (mesh.enabled) await mesh.fetchExitNodes()
  } finally {
    serversLoading.value = false
  }
  syncSelectedServer()
}

function syncSelectedServer() {
  if (vpn.connected && vpn.serverIp) {
    const m = vpn.servers.find(s => s.id === vpn.serverIp)
    if (m) { selectedServer.value = `vpn:${m.id}`; return }
  }
  if (
    (selectedServer.value.startsWith('vpn:') && vpn.servers.some(s => `vpn:${s.id}` === selectedServer.value)) ||
    (selectedServer.value.startsWith('mesh:') && mesh.exitNodes.some(n => selectedServer.value.startsWith(`mesh:${n.mesh_ip}:`)))
  ) return
  selectedServer.value = allItems.value.length > 0 ? allItems.value[0].key : ''
}

// ── Actions ─────────────────────────────────────────────────────────────────

async function selectServer(key: string) {
  dropdownOpen.value = false
  if (key === selectedServer.value && isActive(key)) return  // already active
  selectedServer.value = key
  if (activeConnected.value) {
    switching.value = true
    try {
      if (vpn.connected) await vpn.disconnect()
      if (mesh.fullTunnel) await mesh.clearExitNode()
      connectionType.value = ''
      activeMeshExitIp.value = ''
      await new Promise(r => setTimeout(r, 400))
      await toggleConnection()
    } finally {
      switching.value = false
    }
  }
}

async function toggleConnection() {
  if (toggleInProgress.value) return
  toggleInProgress.value = true
  try {
    if (activeConnected.value) {
      connectionType.value = ''
      activeMeshExitIp.value = ''
      await Promise.all([
        vpn.connected ? vpn.disconnect() : Promise.resolve(),
        mesh.fullTunnel ? mesh.clearExitNode() : Promise.resolve(),
      ])
      return
    }
    if (!auth.authenticated || !selectedServer.value) return

    if (selectedServer.value.startsWith('vpn:')) {
      await vpn.connect(selectedServer.value.slice(4))
      if (!vpn.error) connectionType.value = 'vpn'
    } else if (selectedServer.value.startsWith('mesh:')) {
      const rest = selectedServer.value.slice(5)
      const parts = rest.split(':')
      const scheme = parts[parts.length - 1]
      const port = Number(parts[parts.length - 2])
      const meshIp = parts.slice(0, parts.length - 2).join(':')
      await mesh.setExitNode(meshIp, port, scheme)
      activeMeshExitIp.value = meshIp
      connectionType.value = 'mesh'
    }
  } finally {
    toggleInProgress.value = false
  }
}

async function doLogin() {
  loginLoading.value = true
  loginError.value = ''
  try {
    await auth.startLogin()
    // Browser opened — keep loginLoading = true until the watcher above
    // resets it when auth.authenticated flips to true.
  } catch (e) {
    loginError.value = String(e)
    loginLoading.value = false
  }
}

function cancelLogin() {
  loginLoading.value = false
  loginError.value = ''
}

async function doLogout() {
  logoutLoading.value = true
  try { await auth.logout() }
  finally { logoutLoading.value = false }
}

function formatBytes(b: number): string {
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1024 / 1024).toFixed(2)} MB`
}
</script>

<style scoped>
/* ── Country code badge ─────────────────────────────────────────────────── */
.cc-badge {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-width: 38px;
  height: 26px;
  padding: 0 6px;
  background: var(--midori-50);
  border: 1px solid rgba(22, 163, 74, .22);
  border-radius: 5px;
  font-size: 12px;
  font-weight: 700;
  color: var(--midori-700);
  letter-spacing: 0;
  flex-shrink: 0;
  font-family: 'SF Mono', 'Fira Code', monospace;
}
.cc-badge.cc-mesh {
  background: rgba(34, 211, 238, .08);
  border-color: rgba(34, 211, 238, .28);
  color: #0891b2;
  font-family: inherit;
  font-size: 14px;
  letter-spacing: 0;
}
.cc-badge.cc-empty,
.cc-badge.cc-loading {
  background: var(--surface-2);
  border-color: var(--border);
  color: var(--muted);
}

/* ── Picker trigger ─────────────────────────────────────────────────────── */
.picker-wrap { position: relative; margin-bottom: 14px; }

.picker-trigger {
  width: 100%;
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  background: var(--surface);
  border: 1px solid var(--border-2);
  border-radius: 9px;
  color: var(--ink);
  cursor: pointer;
  text-align: left;
  transition: border-color 0.15s, box-shadow 0.15s;
  font-family: inherit;
}
.picker-trigger:hover:not(:disabled) {
  border-color: var(--midori-400);
  box-shadow: 0 0 0 3px rgba(34,197,94,.12);
}
.picker-trigger:focus-visible {
  outline: none;
  border-color: var(--midori-500);
  box-shadow: 0 0 0 3px rgba(34,197,94,.18);
}
.picker-trigger:disabled {
  opacity: 0.55;
  cursor: not-allowed;
  background: var(--surface-2);
}

.picker-text {
  flex: 1;
  min-width: 0;
  display: flex;
  flex-direction: column;
  gap: 1px;
}
.picker-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--ink);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.picker-name.muted { color: var(--muted); font-weight: 400; }
.picker-sub {
  font-size: 12px;
  color: var(--muted);
  font-family: 'SF Mono', 'Fira Code', monospace;
}

.picker-chevron {
  color: var(--muted);
  flex-shrink: 0;
  transition: transform 0.2s;
}
.picker-chevron.open { transform: rotate(180deg); }

/* ── Dropdown panel ─────────────────────────────────────────────────────── */
.picker-panel {
  position: absolute;
  top: calc(100% + 6px);
  left: 0; right: 0;
  z-index: 100;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 12px;
  box-shadow: 0 8px 24px rgba(0,0,0,.12);
  overflow: hidden;
  max-height: 260px;
  overflow-y: auto;
}
.picker-panel::-webkit-scrollbar { width: 4px; }
.picker-panel::-webkit-scrollbar-track { background: transparent; }
.picker-panel::-webkit-scrollbar-thumb { background: var(--border-2); border-radius: 2px; }

.picker-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 10px 14px;
  cursor: pointer;
  border-bottom: 1px solid var(--border);
  transition: background 0.1s;
}
.picker-item:last-child { border-bottom: none; }
.picker-item:hover { background: rgba(34, 197, 94, .08); }

.picker-item--selected {
  background: rgba(34, 197, 94, .10);
  border-left: 3px solid var(--midori-500);
  padding-left: 11px;
}
.picker-item--active {
  background: rgba(34, 197, 94, .18) !important;
}

.item-text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.item-name {
  font-size: 14px;
  font-weight: 600;
  color: var(--ink);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.item-sub {
  font-size: 12px;
  color: var(--muted);
  font-family: 'SF Mono', 'Fira Code', monospace;
}

.item-active-dot {
  width: 8px;
  height: 8px;
  border-radius: 50%;
  background: var(--midori-500);
  box-shadow: 0 0 5px rgba(34,197,94,.6);
  flex-shrink: 0;
}

.picker-empty {
  padding: 18px;
  text-align: center;
  color: var(--muted);
  font-size: 14px;
}

/* ── Connection row ─────────────────────────────────────────────────────── */
.conn-row {
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 14px;
}
.conn-status { display: flex; align-items: center; }
.conn-label { font-size: 16px; font-weight: 700; color: var(--ink); }

/* ── Stats ──────────────────────────────────────────────────────────────── */
.conn-stats {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 8px;
  margin-top: 4px;
}
.stat-cell {
  background: var(--midori-50);
  border: 1px solid rgba(22,163,74,.14);
  border-radius: 8px;
  padding: 11px 13px;
}

/* ── Misc ───────────────────────────────────────────────────────────────── */
.hint-text {
  font-size: 14px;
  color: var(--muted);
  margin-bottom: 14px;
  line-height: 1.5;
}

/* Login wait hint */
.login-wait-hint {
  font-size: 12px;
  color: var(--muted);
  margin-top: 10px;
  text-align: center;
  line-height: 1.5;
}
.link-btn {
  background: none;
  border: none;
  padding: 0;
  color: var(--midori-500);
  cursor: pointer;
  font-size: inherit;
  text-decoration: underline;
}
.link-btn:hover { color: var(--midori-700); }

/* Spinner animation */
@keyframes spin {
  to { transform: rotate(360deg); }
}
.spin {
  animation: spin 0.9s linear infinite;
  flex-shrink: 0;
}

/* ── Permissions badge ──────────────────────────────────────────────────── */
.perms-badge {
  display: flex;
  align-items: center;
  gap: 6px;
  width: 100%;
  padding: 10px 14px;
  background: #fffbeb;
  border: 1px solid #fcd34d;
  border-radius: 10px;
  font-size: 12.5px;
  font-weight: 600;
  color: #92400e;
  cursor: pointer;
  text-align: left;
  transition: background 0.15s;
}
.perms-badge:hover { background: #fef3c7; }

/* ── Permissions trigger card ────────────────────────────────────────────── */
.perms-trigger-card {
  border-color: var(--midori-300, #fde68a);
}

.perms-trigger-body {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}

.perms-trigger-icon {
  font-size: 22px;
  line-height: 1;
  flex-shrink: 0;
}

.perms-trigger-text {
  flex: 1;
  min-width: 0;
}

.perms-trigger-title {
  font-size: 13px;
  font-weight: 700;
  color: var(--text, #e0e0e0);
  margin-bottom: 2px;
}

.perms-trigger-sub {
  font-size: 11px;
  color: var(--text-muted, #aaa);
}
</style>
