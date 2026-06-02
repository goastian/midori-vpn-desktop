<template>
  <div v-if="visible" class="card dns-trigger-card">
    <div class="dns-trigger-body">
      <div class="dns-trigger-icon" aria-hidden="true">🛡️</div>
      <div class="dns-trigger-text">
        <div class="dns-trigger-title">{{ t('dnsProtection.title') }}</div>
        <div class="dns-trigger-sub">{{ t('dnsProtection.body') }}</div>
      </div>
      <button
        class="btn btn-primary"
        data-test="grant-dns-caps-btn"
        :disabled="granting"
        @click="onClick"
      >
        {{ granting ? t('dnsProtection.applying') : t('dnsProtection.enable') }}
      </button>
    </div>
    <div
      v-if="error"
      class="error"
      data-test="dns-perms-error"
      style="margin-top:8px;font-size:12px"
    >
      {{ error }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, watch } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../../stores/auth'
import { useCaps } from '../../composables/useCaps'
import { useDnsProtection } from '../../composables/useDnsProtection'

const { t } = useI18n()
const auth = useAuthStore()
const { capsGranted } = useCaps()
const { needsPrompt, granting, error, refresh, grantExtraCaps } = useDnsProtection()

// Only show after the base caps have been granted and the agent reports
// the resolvconf backend with missing extra caps.
const visible = computed(() => auth.authenticated && capsGranted.value && needsPrompt.value)

async function onClick() {
  await grantExtraCaps()
}

onMounted(() => {
  if (auth.authenticated && capsGranted.value) refresh()
})

watch(
  () => [auth.authenticated, capsGranted.value],
  ([authed, caps]) => {
    if (authed && caps) refresh()
  },
)
</script>

<style scoped>
.dns-trigger-card {
  border-color: var(--midori-300, #fde68a);
}
.dns-trigger-body {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.dns-trigger-icon {
  font-size: 22px;
  line-height: 1;
  flex-shrink: 0;
}
.dns-trigger-text { flex: 1; min-width: 0; }
.dns-trigger-title {
  font-size: 13px;
  font-weight: 700;
  color: var(--text, #e0e0e0);
  margin-bottom: 2px;
}
.dns-trigger-sub {
  font-size: 11px;
  color: var(--text-muted, #aaa);
}
</style>
