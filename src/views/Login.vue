<template>
  <div class="login-wrap">
    <div class="login-panel" aria-hidden="true">
      <div class="signal-line signal-line--one"></div>
      <div class="signal-line signal-line--two"></div>
      <div class="signal-line signal-line--three"></div>
    </div>

    <div class="login-card">
      <div class="brand">
        <div class="brand-orbit">
          <span class="brand-core">M</span>
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
  </div>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../stores/auth'

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
</script>

<style scoped>
.login-wrap {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  min-height: 100%;
  padding: 34px 28px;
  overflow: hidden;
}
.login-wrap::before {
  content: '';
  position: absolute;
  inset: 0;
  background:
    linear-gradient(150deg, rgba(34, 197, 94, .18) 0%, transparent 34%),
    linear-gradient(180deg, rgba(10, 20, 17, .22), rgba(5, 10, 9, .72));
  pointer-events: none;
}
.login-panel {
  position: absolute;
  inset: 28px;
  opacity: .42;
  pointer-events: none;
}
.signal-line {
  position: absolute;
  height: 1px;
  background: linear-gradient(90deg, transparent, rgba(74, 222, 128, .36), transparent);
}
.signal-line--one {
  top: 20%;
  left: -20%;
  width: 88%;
  transform: rotate(-22deg);
}
.signal-line--two {
  top: 48%;
  right: -28%;
  width: 98%;
  transform: rotate(-22deg);
}
.signal-line--three {
  bottom: 18%;
  left: 2%;
  width: 72%;
  transform: rotate(-22deg);
}
.login-card {
  position: relative;
  max-width: 372px;
  width: 100%;
  text-align: center;
  padding: 30px 24px 26px;
  background: rgba(12, 23, 19, .86);
  border: 1px solid rgba(74, 222, 128, .18);
  border-radius: 18px;
  box-shadow: 0 24px 70px rgba(0, 0, 0, .44), inset 0 1px 0 rgba(255, 255, 255, .04);
  backdrop-filter: blur(18px);
}
.brand {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 10px;
  margin-bottom: 18px;
}
.brand-orbit {
  width: 58px;
  height: 58px;
  display: grid;
  place-items: center;
  border-radius: 18px;
  background: linear-gradient(135deg, rgba(34,197,94,.28), rgba(20,83,45,.10));
  border: 1px solid rgba(134, 239, 172, .20);
  box-shadow: 0 0 34px rgba(34,197,94,.22);
}
.brand-core {
  width: 40px;
  height: 40px;
  display: grid;
  place-items: center;
  border-radius: 13px;
  background: linear-gradient(135deg, var(--midori-400), var(--midori-700));
  color: #04130a;
  font-weight: 900;
  font-size: 20px;
}
h1 {
  color: var(--ink);
  font-size: 27px;
  line-height: 1;
  margin: 0;
}
.brand-pill {
  display: inline-flex;
  align-items: center;
  height: 24px;
  padding: 0 10px;
  border: 1px solid rgba(74, 222, 128, .18);
  border-radius: 999px;
  color: var(--midori-200);
  background: rgba(34, 197, 94, .08);
  font-size: 11px;
  font-weight: 700;
}
.subtitle {
  font-size: 14px;
  color: var(--muted);
  margin: 0 0 22px;
  line-height: 1.5;
}
.signin-btn {
  width: 100%;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.hint {
  font-size: 12.5px;
  color: var(--muted);
  margin-top: 18px;
  line-height: 1.5;
}
.error {
  margin-top: 12px;
  font-size: 12px;
}
.expired-banner {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 10px 14px;
  margin-bottom: 16px;
  background: rgba(245, 158, 11, 0.12);
  border: 1px solid rgba(245, 158, 11, 0.35);
  border-radius: 8px;
  color: #fbbf24;
  font-size: 13px;
  text-align: left;
}
.expired-icon {
  font-size: 16px;
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
@keyframes spin { to { transform: rotate(360deg); } }
.spin { animation: spin 0.9s linear infinite; flex-shrink: 0; }
</style>
