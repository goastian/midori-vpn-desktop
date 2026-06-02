<template>
  <!-- Not authenticated -->
  <div class="card" v-if="!auth.authenticated">
    <div class="section-title">{{ t('auth.signIn') }}</div>
    <p class="hint-text">{{ t('auth.signInHint') }}</p>

    <button
      class="btn btn-primary"
      data-test="sign-in-btn"
      style="width:100%"
      :disabled="loginLoading"
      @click="doLogin"
    >
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
      <button class="link-btn" data-test="cancel-login-btn" @click="cancelLogin">{{ t('auth.cancelLogin') }}</button>
    </p>

    <div v-if="loginError" class="error" data-test="login-error">{{ loginError }}</div>
  </div>

  <!-- Authenticated -->
  <div class="card" v-else>
    <div class="row">
      <div>
        <div class="label">{{ t('auth.activeSession') }}</div>
        <div class="value" data-test="active-user">{{ auth.email || auth.userId }}</div>
      </div>
      <button
        class="btn btn-secondary"
        data-test="sign-out-btn"
        :disabled="logoutLoading"
        @click="doLogout"
      >
        <svg v-if="logoutLoading" class="spin" width="13" height="13" viewBox="0 0 24 24" fill="none"
          style="margin-right:5px" aria-hidden="true">
          <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-dasharray="30 10" />
        </svg>
        {{ logoutLoading ? t('auth.signingOut') : t('auth.signOut') }}
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { ref, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../../stores/auth'

const auth = useAuthStore()
const { t } = useI18n()

const loginLoading = ref(false)
const loginError = ref('')
const logoutLoading = ref(false)

const emit = defineEmits<{
  (e: 'authenticated'): void
}>()

watch(
  () => auth.authenticated,
  (v) => {
    if (v) {
      loginLoading.value = false
      loginError.value = ''
      emit('authenticated')
    }
  },
)

async function doLogin() {
  loginLoading.value = true
  loginError.value = ''
  try {
    await auth.startLogin()
    // Stay in loading state until the watch above resets it when
    // auth.authenticated flips.
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
  try {
    await auth.logout()
  } finally {
    logoutLoading.value = false
  }
}
</script>

<style scoped>
.hint-text {
  font-size: 14px;
  color: var(--muted);
  margin-bottom: 14px;
  line-height: 1.5;
}

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

@keyframes spin { to { transform: rotate(360deg); } }
.spin { animation: spin 0.9s linear infinite; flex-shrink: 0; }
</style>
