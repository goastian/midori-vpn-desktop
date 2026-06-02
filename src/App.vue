<template>
  <div class="app">
    <header class="app-titlebar" @pointerdown="startDragPointer" @mousedown="startDragMouse">
      <div class="title-drag-area">
        <div class="title-brand">
          <img class="brand-logo" :src="brandIcon" alt="MidoriVPN" />
          <span class="brand-name">MidoriVPN</span>
        </div>
      </div>
      <div class="window-actions" @pointerdown.stop @mousedown.stop>
        <button class="window-btn" :aria-label="t('titlebar.minimize')" :title="t('titlebar.minimize')" @click="minimizeWindow">
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M3 8h10" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
          </svg>
        </button>
        <button class="window-btn window-btn--close" :aria-label="t('titlebar.close')" :title="t('titlebar.close')" @click="closeWindow">
          <svg width="12" height="12" viewBox="0 0 16 16" fill="none" aria-hidden="true">
            <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="2" stroke-linecap="round" />
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
import brandIcon from './assets/midori-mv.png'
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

function tryStartDrag(button: number, target: EventTarget | null) {
  if (button !== 0) return
  const el = target as HTMLElement | null
  if (!el) return
  if (el.closest('.window-actions, button, a, input, select, textarea, [role="button"]')) return
  appWindow.startDragging().catch(() => { /* ignore */ })
}

function startDragMouse(e: MouseEvent) {
  tryStartDrag(e.button, e.target)
}

function startDragPointer(e: PointerEvent) {
  tryStartDrag(e.button, e.target)
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
  // Initialise the agent client before subscribing to Rust-relayed events.
  await initAgentToken()
  await loadSnapshot(20)
  unsubscribe = agent.subscribe((event) => {
    if (event.type === 'vpn_status') vpnStore.applyStatus(event.data)
    else if (event.type === 'mesh_status') meshStore.applyStatus(event.data)
    else if (event.type === 'auth_status') authStore.applyStatus(event.data)
  })

  // Listen for agent supervisor status changes from Rust.
  // On 'running' the SSE relay reconnects and the agent re-sends the full
  // snapshot, so we don't poll loadSnapshot here (avoids racing the SSE
  // snapshot with a stale HTTP GET that can overwrite mesh state).
  listen<{ status: string }>('agent://status', async (ev) => {
    const s = ev.payload.status
    if (s === 'running') {
      await initAgentToken()
      agentStatus.value = 'running'
    } else if (s === 'restarting') {
      agentStatus.value = 'restarting'
    } else if (s === 'failed') {
      agentStatus.value = 'failed'
    }
  }).then(fn => { unlistenAgentStatus = fn })

  // Re-poll snapshot when the window regains focus (WebKit may pause event
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
  border: 1px solid rgba(22, 163, 74, .18);
}

.app-titlebar {
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 8px 0 12px;
  background: var(--surface);
  border-bottom: 2px solid var(--midori-500);
  user-select: none;
}

.title-drag-area {
  flex: 1;
  min-width: 0;
  height: 100%;
  display: flex;
  align-items: center;
  cursor: grab;
}

.title-brand {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  min-width: 0;
  cursor: default;
}

.brand-logo {
  flex-shrink: 0;
  width: 34px;
  height: 21px;
  object-fit: contain;
}

.brand-name {
  color: var(--ink);
  font-size: 13px;
  font-weight: 700;
  letter-spacing: .01em;
}

.window-actions {
  display: inline-flex;
  align-items: center;
  gap: 2px;
}

.window-btn {
  width: 30px;
  height: 28px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  border: 0;
  border-radius: 6px;
  background: transparent;
  color: var(--muted);
  cursor: pointer;
  transition: background .12s, color .12s;
}

.window-btn:hover {
  background: var(--surface-3);
  color: var(--ink);
}

.window-btn--close:hover {
  background: #fee2e2;
  color: #dc2626;
}

.app-body {
  height: calc(100vh - 44px);
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

/* Agent supervisor status banner */
.agent-banner { padding: 7px 14px; font-size: 0.82rem; text-align: center; font-weight: 500; }
.agent-banner--restarting { background: #fffbeb; color: #92400e; border-bottom: 1px solid #fcd34d; }
.agent-banner--failed     { background: #fef2f2; color: #991b1b; border-bottom: 1px solid #fca5a5; }

/* Security banner */
.security-banner { display: flex; flex-direction: column; gap: 0; }
.security-issue { padding: 9px 14px; font-size: 0.82rem; border-left: 3px solid; background: var(--surface); border-bottom: 1px solid var(--border); }
.issue-error   { border-color: #ef4444; }
.issue-warning { border-color: #f59e0b; }
.issue-info    { border-color: #3b82f6; }
.issue-header  { display: flex; align-items: center; gap: 8px; }
.issue-icon    { font-size: 1rem; }
.issue-close   { margin-left: auto; background: none; border: none; color: var(--muted); cursor: pointer; font-size: 1rem; opacity: 0.7; }
.issue-close:hover { opacity: 1; color: var(--ink); }
.issue-detail  { margin-top: 4px; font-size: 0.80rem; line-height: 1.4; color: var(--ink-3); }
.issue-fix     { display: flex; align-items: center; gap: 8px; margin-top: 8px; flex-wrap: wrap; }
.fix-cmd       { flex: 1; padding: 5px 9px; background: var(--surface-3); border: 1px solid var(--border); border-radius: 4px;
                 font-family: monospace; font-size: 0.78rem; white-space: pre; overflow-x: auto; color: var(--ink-2); }
.fix-copy      { flex-shrink: 0; padding: 4px 10px; border: 1px solid var(--border); border-radius: 4px;
                 background: none; color: var(--midori-700); cursor: pointer; font-size: 0.78rem; white-space: nowrap; }
.fix-copy:hover { background: var(--midori-50); }
</style>
