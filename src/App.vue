<template>
  <div class="app">
    <header class="app-titlebar">
      <div class="title-brand" data-tauri-drag-region>
        <span class="brand-mark" aria-hidden="true">M</span>
        <span class="brand-name">MidoriVPN</span>
      </div>
      <div class="window-actions">
        <button class="window-btn" :aria-label="t('titlebar.minimize')" :title="t('titlebar.minimize')" @click="minimizeWindow">
          <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M3 8h10" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
          </svg>
        </button>
        <button class="window-btn window-btn--close" :aria-label="t('titlebar.close')" :title="t('titlebar.close')" @click="closeWindow">
          <svg width="13" height="13" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" />
          </svg>
        </button>
      </div>
    </header>

    <div class="app-body">
      <!-- Agent supervisor status banner -->
      <div v-if="agentStatus !== 'running'" class="agent-banner" :class="`agent-banner--${agentStatus}`">
        <span v-if="agentStatus === 'restarting'">{{ t('agent.restarting') }}</span>
        <span v-else-if="agentStatus === 'failed'">{{ t('agent.failed') }}</span>
      </div>

      <!-- Security warnings banner -->
      <div v-if="securityIssues.length" class="security-banner">
        <div
          v-for="issue in securityIssues"
          :key="issue.id"
          class="security-issue"
          :class="`issue-${issue.level}`"
        >
          <div class="issue-header">
            <span class="issue-icon">{{ issue.level === 'error' ? '✖' : issue.level === 'warning' ? '⚠' : 'ℹ' }}</span>
            <strong>{{ issue.title }}</strong>
            <button class="issue-close" @click="dismissIssue(issue.id)">✕</button>
          </div>
          <p class="issue-detail">{{ issue.detail }}</p>
          <div v-if="issue.fix_cmd" class="issue-fix">
            <code class="fix-cmd">{{ issue.fix_cmd }}</code>
            <button class="fix-copy" @click="copyAndFix(issue)">{{ t('security.copyAndClose') }}</button>
          </div>
        </div>
      </div>

      <nav class="nav" v-if="$route.path !== '/login'">
        <RouterLink to="/" class="nav-link" :class="{ active: $route.path === '/' }">{{ t('nav.vpn') }}</RouterLink>
        <RouterLink to="/mesh" class="nav-link" :class="{ active: $route.path === '/mesh' }">{{ t('nav.mesh') }}</RouterLink>
        <RouterLink to="/settings" class="nav-link" :class="{ active: $route.path === '/settings' }">{{ t('nav.settings') }}</RouterLink>
      </nav>
      <main class="main" :class="{ 'main--login': $route.path === '/login' }">
        <RouterView />
      </main>
    </div>
  </div>
</template>

<script setup lang="ts">
import { onMounted, onUnmounted, ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { RouterLink, RouterView, useRouter } from 'vue-router'
import { invoke } from '@tauri-apps/api/core'
import { listen } from '@tauri-apps/api/event'
import { getCurrentWindow } from '@tauri-apps/api/window'
import { agent, initAgentToken } from './lib/agent'
import { useVpnStore } from './stores/vpn'
import { useMeshStore } from './stores/mesh'
import { useAuthStore } from './stores/auth'

const { t } = useI18n()
const router = useRouter()
const appWindow = getCurrentWindow()

interface SecurityIssue { id: string; title: string; detail: string; fix_cmd: string; level: string }

const vpnStore = useVpnStore()
const meshStore = useMeshStore()
const authStore = useAuthStore()
const securityIssues = ref<SecurityIssue[]>([])

/** Status emitted by the Rust agent supervisor: "running" | "restarting" | "failed" */
const agentStatus = ref<'running' | 'restarting' | 'failed'>('running')
const SNAPSHOT_RETRY_MS = 300

function dismissIssue(id: string) {
  securityIssues.value = securityIssues.value.filter(i => i.id !== id)
}

async function copyAndFix(issue: SecurityIssue) {
  try {
    await navigator.clipboard.writeText(issue.fix_cmd)
  } catch {
    // Clipboard API unavailable — ignore silently.
  }
  dismissIssue(issue.id)
}

async function minimizeWindow() {
  await appWindow.minimize()
}

async function closeWindow() {
  await appWindow.hide()
}

function sleep(ms: number) {
  return new Promise(resolve => setTimeout(resolve, ms))
}

function isTransientAgentError(e: unknown) {
  const message = String(e)
  return message.includes('auth_expired: 403') ||
    message.includes('Connection refused') ||
    message.includes('error sending request')
}

// Load a snapshot, retrying during startup while the supervisor is still
// replacing stale agents and syncing the ephemeral token.
async function loadSnapshot(retries = 0) {
  for (let attempt = 0; ; attempt++) {
    try {
      const snap = await agent.status()
      vpnStore.applyStatus(snap.vpn)
      meshStore.applyStatus(snap.mesh)
      authStore.applyStatus(snap.auth)
      return
    } catch (e) {
      if (attempt >= retries || !isTransientAgentError(e)) {
        throw e
      }
      await sleep(SNAPSHOT_RETRY_MS)
    }
  }
}

function refreshSnapshot() {
  void loadSnapshot(3).catch(() => {
    agentStatus.value = 'restarting'
  })
}

// When authenticated drops to false, redirect to /login so the user can
// sign in again regardless of which page they are on.
watch(() => authStore.authenticated, (isNow, wasBefore) => {
  if (!isNow && wasBefore) {
    const reason = authStore.sessionExpired ? 'expired' : 'logout'
    router.push(`/login?reason=${reason}`)
  }
})

// Subscribe to live events
let unsubscribe: (() => void) | null = null
let keepAliveTimer: ReturnType<typeof setInterval> | null = null
let unlistenAgentStatus: (() => void) | null = null

onMounted(async () => {
  // Fetch ephemeral token first so EventSource URL includes ?token=
  await initAgentToken()
  await loadSnapshot(20)
  unsubscribe = agent.subscribe((event) => {
    if (event.type === 'vpn_status') vpnStore.applyStatus(event.data)
    else if (event.type === 'mesh_status') meshStore.applyStatus(event.data)
    else if (event.type === 'auth_status') authStore.applyStatus(event.data)
  })

  // Listen for agent supervisor status changes from Rust.
  listen<{ status: string }>('agent://status', async (ev) => {
    const s = ev.payload.status
    if (s === 'running') {
      // Re-fetch token (supervisor regenerates it on restart) then reconnect SSE.
      await initAgentToken()
      await loadSnapshot(10)
      agentStatus.value = 'running'
    } else if (s === 'restarting') {
      agentStatus.value = 'restarting'
    } else if (s === 'failed') {
      agentStatus.value = 'failed'
    }
  }).then(fn => { unlistenAgentStatus = fn })

  // Re-poll snapshot when the window regains focus (WebKit may pause EventSource
  // while the OAuth browser tab is open, causing the auth_status event to be missed).
  window.addEventListener('focus', refreshSnapshot)

  // Keep-alive: silently refresh the token every 8 minutes so the session
  // never expires due to inactivity on a desktop app. The agent also schedules
  // its own proactive refresh; this is belt-and-suspenders for edge cases.
  keepAliveTimer = setInterval(async () => {
    if (authStore.authenticated) {
      try { await agent.auth.refresh() } catch { /* silent — agent will log */ }
    }
  }, 8 * 60 * 1000)

  // Check for SELinux / AppArmor / firewall issues
  try {
    const issues = await invoke<SecurityIssue[]>('security_check')
    if (issues.length) securityIssues.value = issues
  } catch {
    // non-critical: ignore if command fails
  }
})

onUnmounted(() => {
  unsubscribe?.()
  unlistenAgentStatus?.()
  window.removeEventListener('focus', refreshSnapshot)
  if (keepAliveTimer) clearInterval(keepAliveTimer)
})
</script>

<style>
* { box-sizing: border-box; margin: 0; padding: 0; }

.app {
  height: 100vh;
  overflow: hidden;
  background: var(--app-bg);
  color: var(--ink);
  border: 1px solid rgba(76, 255, 147, .16);
}

.app-titlebar {
  height: 46px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 10px 0 14px;
  background: linear-gradient(180deg, rgba(19, 31, 27, .96), rgba(9, 15, 14, .96));
  border-bottom: 1px solid rgba(74, 222, 128, .16);
  user-select: none;
}

.window-actions,
.window-actions * {
  -webkit-app-region: no-drag;
}

.title-brand {
  display: inline-flex;
  align-items: center;
  gap: 10px;
  min-width: 0;
}

.brand-mark {
  width: 24px;
  height: 24px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border-radius: 7px;
  background: linear-gradient(135deg, var(--midori-500), var(--midori-700));
  color: #04110b;
  font-size: 13px;
  font-weight: 900;
  box-shadow: 0 0 18px rgba(34, 197, 94, .28);
}

.brand-name {
  color: #ecfdf5;
  font-size: 13px;
  font-weight: 700;
  letter-spacing: .01em;
}

.window-actions {
  display: inline-flex;
  align-items: center;
  gap: 4px;
}

.window-btn {
  width: 32px;
  height: 30px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 0;
  border-radius: 8px;
  background: transparent;
  color: var(--muted-2);
  cursor: pointer;
  pointer-events: auto;
  -webkit-app-region: no-drag;
  transition: background .15s, color .15s;
}

.window-btn:hover {
  background: rgba(148, 163, 184, .12);
  color: #f8fafc;
}

.window-btn--close:hover {
  background: rgba(248, 113, 113, .16);
  color: #fecaca;
}

.app-body {
  height: calc(100vh - 46px);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* Agent supervisor status banner */
.agent-banner { padding: 8px 14px; font-size: 0.82rem; text-align: center; font-weight: 500; }
.agent-banner--restarting { background: #2d2012; color: #fefcbf; border-bottom: 1px solid #d69e2e; }
.agent-banner--failed     { background: #2d1212; color: #fed7d7; border-bottom: 1px solid #e53e3e; }

/* Security banner */
.security-banner { display: flex; flex-direction: column; gap: 4px; }
.security-issue { padding: 10px 14px; font-size: 0.82rem; border-left: 4px solid; }
.issue-error   { background: #2d1212; border-color: #e53e3e; color: #fed7d7; }
.issue-warning { background: #2d2012; border-color: #d69e2e; color: #fefcbf; }
.issue-info    { background: #12202d; border-color: #3182ce; color: #bee3f8; }
.issue-header  { display: flex; align-items: center; gap: 8px; }
.issue-icon    { font-size: 1rem; }
.issue-close   { margin-left: auto; background: none; border: none; color: inherit; cursor: pointer; font-size: 1rem; opacity: 0.7; }
.issue-close:hover { opacity: 1; }
.issue-detail  { margin-top: 6px; font-size: 0.80rem; line-height: 1.4; }
.issue-fix     { display: flex; align-items: center; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
.fix-cmd       { flex: 1; padding: 6px 10px; background: rgba(0,0,0,.45); border-radius: 4px;
                 font-family: monospace; font-size: 0.78rem; white-space: pre; overflow-x: auto; }
.fix-copy      { flex-shrink: 0; padding: 4px 10px; border: 1px solid currentColor; border-radius: 4px;
                 background: none; color: inherit; cursor: pointer; font-size: 0.78rem; opacity: 0.85; white-space: nowrap; }
.fix-copy:hover { opacity: 1; background: rgba(255,255,255,.1); }
</style>
