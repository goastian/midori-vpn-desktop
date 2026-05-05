import { defineStore } from 'pinia'
import { ref } from 'vue'
import { agent, type AuthStatus } from '../lib/agent'

export const useAuthStore = defineStore('auth', () => {
  const authenticated = ref(false)
  const userId = ref('')
  const email = ref('')
  const expiresAt = ref<string | null>(null)

  function applyStatus(s: AuthStatus) {
    authenticated.value = s.authenticated
    userId.value = s.user_id
    email.value = s.email
    expiresAt.value = s.expires_at
  }

  async function setTokens(accessToken: string, refreshToken: string, expiresIn: number) {
    await agent.auth.setTokens(accessToken, refreshToken, expiresIn)
  }

  async function logout() {
    await agent.auth.logout()
  }

  return { authenticated, userId, email, expiresAt, applyStatus, setTokens, logout }
})
