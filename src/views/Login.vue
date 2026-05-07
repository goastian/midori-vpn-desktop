<template>
  <div class="login-wrap">
    <div class="login-card">
      <div class="brand">
        <div class="brand-logo-wrap">
          <img class="brand-logo" :src="brandIcon" alt="MidoriVPN" />
        </div>
        <h1>MidoriVPN</h1>
        <span class="brand-pill">{{ t('login.tagline') }}</span>
      </div>

      <!-- Session expired banner -->
      <div v-if="isExpired" class="expired-banner">
        <span class="expired-icon">⚠</span>
        {{ t('auth.sessionExpired') }}
      </div>

      <p class="subtitle">
        {{ t('login.subtitle') }}
      </p>

      <div class="language-row">
        <LanguageSelect compact />
      </div>

      <button
        class="btn btn-primary signin-btn"
        :disabled="loading"
        @click="doLogin"
      >
        <svg v-if="loading" class="spin" width="16" height="16" viewBox="0 0 24 24" fill="none"
          style="margin-right:6px" aria-hidden="true">
          <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2" stroke-dasharray="30 10" />
        </svg>
        <svg v-else width="16" height="16" viewBox="0 0 24 24" fill="none"
          style="margin-right:6px" aria-hidden="true">
          <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
          <path d="M8 12h8M14 9l3 3-3 3" stroke="currentColor" stroke-width="2"
            stroke-linecap="round" stroke-linejoin="round"/>
        </svg>
        {{ loading ? t('auth.waitingBrowser') : t('auth.signInWithAstian') }}
      </button>
      <button v-if="loading" class="cancel-btn" @click="cancelLogin">{{ t('auth.cancelLogin') }}</button>
      <div v-if="error" class="error">{{ error }}</div>
      <p class="hint">
        {{ t('login.hint') }}
      </p>
    </div>

    <button class="quit-fab" @click="quitApp" :aria-label="t('login.quit')">
      <span class="quit-fab__icon" aria-hidden="true">
        <svg width="12" height="12" viewBox="0 0 16 16" fill="none">
          <path d="M4 4l8 8M12 4l-8 8" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
        </svg>
      </span>
      <span class="quit-fab__text">{{ t('login.quit') }}</span>
    </button>
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { invoke } from '@tauri-apps/api/core'
import { useAuthStore } from '../stores/auth'
import brandIcon from '../assets/midori-mv.png'
import LanguageSelect from '../components/LanguageSelect.vue'

const auth = useAuthStore()
const { t } = useI18n()
const router = useRouter()
const route = useRoute()
const loading = ref(false)
const error = ref('')

// Show banner when redirected due to expiry.
const isExpired = computed(() => route.query.reason === 'expired')

// As soon as auth flips to logged-in (callback received via SSE), bounce
// back to wherever the user was trying to reach.
watch(
  () => auth.authenticated,
  (ok) => {
    if (!ok) return
    const target = (route.query.next as string) || '/'
    router.replace(target)
  },
  { immediate: true },
)

async function doLogin() {
  loading.value = true
  error.value = ''
  try {
    await auth.startLogin()
    // Browser opened — keep loading=true; the watch above navigates away
    // as soon as auth.authenticated flips to true via SSE.
  } catch (e) {
    error.value = String(e)
    loading.value = false
  }
}

function cancelLogin() {
  loading.value = false
  error.value = ''
}

async function quitApp() {
  try {
    await invoke('quit_app')
  } catch {
    // ignore
  }
}
</script>

<style scoped>
.login-wrap {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100%;
  padding: 32px 20px;
  background: var(--app-bg);
}
.login-card {
  position: relative;
  max-width: 356px;
  width: 100%;
  text-align: center;
  padding: 30px 24px 26px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 16px;
  box-shadow: 0 4px 16px rgba(0,0,0,.08);
}
.brand {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  margin-bottom: 20px;
}
.brand-logo-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
}
.brand-logo {
  width: 84px;
  height: 52px;
  object-fit: contain;
}
h1 {
  color: var(--ink);
  font-size: 26px;
  line-height: 1;
  margin: 0;
  font-weight: 800;
}
.brand-pill {
  display: inline-flex;
  align-items: center;
  height: 22px;
  padding: 0 10px;
  border: 1px solid var(--border-2);
  border-radius: 999px;
  color: var(--midori-700);
  background: var(--midori-50);
  font-size: 11px;
  font-weight: 700;
}
.subtitle {
  font-size: 14px;
  color: var(--muted);
  margin: 0 0 20px;
  line-height: 1.55;
}
.language-row {
  display: flex;
  justify-content: center;
  margin: 0 0 18px;
}
.signin-btn {
  width: 100%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 15px;
  padding: 11px 20px;
}
.hint {
  font-size: 12px;
  color: var(--muted-2);
  margin-top: 16px;
  line-height: 1.5;
}
.error {
  margin-top: 10px;
  font-size: 13px;
  color: var(--danger);
}
.expired-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 9px 14px;
  margin-bottom: 16px;
  background: #fffbeb;
  border: 1px solid #fcd34d;
  border-radius: 8px;
  color: #92400e;
  font-size: 13px;
  text-align: left;
}
.expired-icon {
  font-size: 15px;
  flex-shrink: 0;
}
.cancel-btn {
  display: block;
  width: 100%;
  margin-top: 10px;
  background: none;
  border: none;
  font-size: 13px;
  color: var(--muted);
  cursor: pointer;
  text-decoration: underline;
}
.cancel-btn:hover { color: var(--ink); }

.quit-fab {
  position: fixed;
  right: 14px;
  bottom: 14px;
  z-index: 20;
  border: 1px solid rgba(220, 38, 38, .22);
  background: linear-gradient(180deg, #ffffff 0%, #fff5f5 100%);
  color: #b91c1c;
  border-radius: 999px;
  padding: 8px 12px 8px 10px;
  font-size: 12px;
  font-weight: 700;
  line-height: 1;
  display: inline-flex;
  align-items: center;
  gap: 8px;
  cursor: pointer;
  box-shadow: 0 8px 20px rgba(0, 0, 0, .12);
  transition: transform .14s, box-shadow .14s, border-color .14s, color .14s, background .14s;
}
.quit-fab:hover {
  transform: translateY(-1px);
  color: #991b1b;
  border-color: rgba(220, 38, 38, .36);
  background: linear-gradient(180deg, #ffffff 0%, #ffe8e8 100%);
  box-shadow: 0 12px 24px rgba(0, 0, 0, .16);
}
.quit-fab:active {
  transform: translateY(0);
  box-shadow: 0 6px 14px rgba(0, 0, 0, .12);
}
.quit-fab:focus-visible {
  outline: none;
  box-shadow: 0 0 0 3px rgba(239, 68, 68, .22), 0 10px 20px rgba(0, 0, 0, .14);
}
.quit-fab__icon {
  width: 18px;
  height: 18px;
  border-radius: 999px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  background: rgba(220, 38, 38, .12);
}
.quit-fab__text {
  letter-spacing: .01em;
}

@media (max-height: 720px) {
  .quit-fab {
    right: 10px;
    bottom: 10px;
    padding: 7px 10px 7px 9px;
    font-size: 11px;
    gap: 7px;
  }
}

@keyframes spin { to { transform: rotate(360deg); } }
.spin { animation: spin 0.9s linear infinite; flex-shrink: 0; }
</style>
