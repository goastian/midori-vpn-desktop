<template>
  <div v-if="visible" class="card perms-trigger-card">
    <div class="perms-trigger-body">
      <div class="perms-trigger-icon" aria-hidden="true">🔐</div>
      <div class="perms-trigger-text">
        <div class="perms-trigger-title">{{ t('perms.title') }}</div>
        <div class="perms-trigger-sub">{{ t('perms.body') }}</div>
      </div>
      <button
        class="btn btn-primary"
        data-test="open-perms-modal-btn"
        :disabled="capsGranting"
        @click="emit('request')"
      >
        {{ capsGranting ? t('perms.applying') : t('perms.enable') }}
      </button>
    </div>
    <div
      v-if="capsError"
      class="error"
      data-test="perms-error"
      style="margin-top:8px;font-size:12px"
    >
      {{ capsError }}
    </div>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import { useAuthStore } from '../../stores/auth'

const props = defineProps<{
  capsGranted: boolean
  capsGranting: boolean
  capsError: string
}>()

const emit = defineEmits<{
  (e: 'request'): void
}>()

const { t } = useI18n()
const auth = useAuthStore()

// Only meaningful after login and while caps have not been granted.
const visible = computed(() => auth.authenticated && !props.capsGranted)
</script>

<style scoped>
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

.perms-trigger-text { flex: 1; min-width: 0; }

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
