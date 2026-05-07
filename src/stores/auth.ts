import { defineStore } from 'pinia'
import { ref } from 'vue'
import { open } from '@tauri-apps/plugin-shell'
import { agent, type AuthStatus } from '../lib/agent'

export const useAuthStore = defineStore('auth', () => {
  const authenticated = ref(false)
  const userId = ref('')
  const email = ref('')
  const expiresAt = ref<string | null>(null)
  // Tracks whether the agent has reported an initial /status snapshot. The
  // router guard waits on this so a slow agent boot doesn't bounce the user
  // straight to /login while their session is actually valid.
  const initialized = ref(false)
  // Set to true when the session drops unexpectedly (not from manual logout).
  // Used to show a "session expired" banner on the login screen.
  const sessionExpired = ref(false)

  // Internal flag: prevents applyStatus from treating an intentional logout
  // as an unexpected session expiry.
  let _isLoggingOut = false

  function applyStatus(s: AuthStatus) {
    // If auth goes away without an explicit logout, mark it as expired.
    if (!s.logged_in && authenticated.value && !_isLoggingOut) {
      sessionExpired.value = true
    }
    authenticated.value = s.logged_in
    userId.value = s.username
    email.value = s.username
    expiresAt.value = s.expires_at ? new Date(s.expires_at * 1000).toISOString() : null
    initialized.value = true
  }

  /** Open Authentik in the system browser using PKCE flow. */
  async function startLogin() {
    sessionExpired.value = false
    const { url } = await agent.oauth.start()
    await open(url)
  }

  async function setTokens(accessToken: string, refreshToken: string, expiresIn: number) {
    await agent.auth.setTokens(accessToken, refreshToken, expiresIn)
  }

  async function logout() {
    _isLoggingOut = true
    sessionExpired.value = false
    // Optimistic: reset local state immediately so the UI reacts before SSE.
    authenticated.value = false
    userId.value = ''
    email.value = ''
    expiresAt.value = null
    try {
      await agent.auth.logout()
    } finally {
      _isLoggingOut = false
    }
  }

  return { authenticated, userId, email, expiresAt, initialized, sessionExpired, applyStatus, startLogin, setTokens, logout }
})
