<template>
  <div v-if="error" class="error-alert-card" :class="`error-alert--${error.category}`">
    <div class="error-alert-header">
      <div class="error-alert-title-wrap">
        <span class="error-alert-icon">
          <svg v-if="isPermissionError" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            <path d="M12 8v4"/>
            <path d="M12 16h.01"/>
          </svg>
          <svg v-else-if="error.category === 'server_unavailable'" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="12" y1="8" x2="12" y2="12"/>
            <line x1="12" y1="16" x2="12.01" y2="16"/>
          </svg>
          <svg v-else width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"/>
            <line x1="15" y1="9" x2="9" y2="15"/>
            <line x1="9" y1="9" x2="15" y2="15"/>
          </svg>
        </span>
        <span class="error-alert-title">{{ localizedTitle }}</span>
      </div>
      <button class="error-alert-close" type="button" :title="t('titlebar.close')" @click="$emit('dismiss')">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <line x1="18" y1="6" x2="6" y2="18"/>
          <line x1="6" y1="6" x2="18" y2="6"/>
        </svg>
      </button>
    </div>

    <div class="error-alert-body">
      {{ localizedDescription }}
    </div>

    <div v-if="error.action" class="error-alert-actions">
      <button
        v-if="error.action === 'grant_caps'"
        type="button"
        class="btn-alert-action btn-alert-primary"
        @click="$emit('action', 'grant_caps')"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <circle cx="7.5" cy="15.5" r="5.5"/>
          <path d="m21 2-9.6 9.6"/>
          <path d="m15.5 7.5 3 3L22 7l-3-3"/>
        </svg>
        <span>{{ t('errors.dnsPermission.action') || 'Conceder permisos' }}</span>
      </button>
      <button
        v-else-if="error.action === 'retry'"
        type="button"
        class="btn-alert-action btn-alert-secondary"
        @click="$emit('action', 'retry')"
      >
        <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/>
        </svg>
        <span>{{ t('errors.serverUnavailable.action') || 'Reintentar' }}</span>
      </button>
      <button
        v-else-if="error.action === 'relogin'"
        type="button"
        class="btn-alert-action btn-alert-primary"
        @click="$emit('action', 'relogin')"
      >
        <span>{{ t('auth.signIn') }}</span>
      </button>
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { ParsedError } from '../../lib/error'

const props = defineProps<{
  error: ParsedError | null
}>()

defineEmits<{
  (e: 'action', type: string): void
  (e: 'dismiss'): void
}>()

const { t, te } = useI18n()

const isPermissionError = computed(() => {
  return props.error?.category === 'dns_permission' || props.error?.category === 'tun_permission'
})

const localizedTitle = computed(() => {
  if (!props.error) return ''
  if (te(props.error.titleKey)) {
    return t(props.error.titleKey)
  }
  if (isPermissionError.value) {
    return 'Permisos requeridos'
  }
  return 'Error de conexión'
})

const localizedDescription = computed(() => {
  if (!props.error) return ''
  if (props.error.descKey && te(props.error.descKey)) {
    return t(props.error.descKey)
  }
  return props.error.rawMessage
})
</script>

<style scoped>
.error-alert-card {
  margin-top: 14px;
  padding: 12px 14px;
  background: rgba(239, 68, 68, 0.08);
  border: 1px solid rgba(239, 68, 68, 0.28);
  border-radius: 12px;
  backdrop-filter: blur(12px);
  animation: fadeIn 0.2s ease-out;
  display: flex;
  flex-direction: column;
  gap: 8px;
}

.error-alert--dns_permission,
.error-alert--tun_permission {
  background: rgba(245, 158, 11, 0.08);
  border-color: rgba(245, 158, 11, 0.32);
}

.error-alert-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.error-alert-title-wrap {
  display: flex;
  align-items: center;
  gap: 8px;
}

.error-alert-icon {
  display: flex;
  align-items: center;
  color: #ef4444;
}

.error-alert--dns_permission .error-alert-icon,
.error-alert--tun_permission .error-alert-icon {
  color: #f59e0b;
}

.error-alert-title {
  font-size: 13px;
  font-weight: 600;
  color: #f87171;
}

.error-alert--dns_permission .error-alert-title,
.error-alert--tun_permission .error-alert-title {
  color: #fbbf24;
}

.error-alert-close {
  background: transparent;
  border: none;
  color: rgba(255, 255, 255, 0.4);
  cursor: pointer;
  padding: 2px;
  display: flex;
  align-items: center;
  justify-content: center;
  border-radius: 4px;
  transition: all 0.15s ease;
}

.error-alert-close:hover {
  color: rgba(255, 255, 255, 0.9);
  background: rgba(255, 255, 255, 0.1);
}

.error-alert-body {
  font-size: 12px;
  line-height: 1.45;
  color: rgba(255, 255, 255, 0.82);
  word-break: break-word;
}

.error-alert-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 4px;
}

.btn-alert-action {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12px;
  font-weight: 600;
  padding: 6px 12px;
  border-radius: 8px;
  cursor: pointer;
  border: none;
  transition: all 0.15s ease;
}

.btn-alert-primary {
  background: #f59e0b;
  color: #0f172a;
}

.btn-alert-primary:hover {
  background: #fbbf24;
  transform: translateY(-1px);
}

.btn-alert-secondary {
  background: rgba(255, 255, 255, 0.12);
  color: #f1f5f9;
  border: 1px solid rgba(255, 255, 255, 0.2);
}

.btn-alert-secondary:hover {
  background: rgba(255, 255, 255, 0.18);
}

@keyframes fadeIn {
  from {
    opacity: 0;
    transform: translateY(-4px);
  }
  to {
    opacity: 1;
    transform: translateY(0);
  }
}
</style>
