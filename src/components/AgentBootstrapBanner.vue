<template>
  <div
    v-if="phase !== 'ready'"
    class="bootstrap-banner"
    :class="`bootstrap-banner--${phase}`"
    :role="phase === 'failed' ? 'alert' : 'status'"
    :aria-live="phase === 'failed' ? 'assertive' : 'polite'"
  >
    <span class="bootstrap-indicator" aria-hidden="true">{{ phase === 'failed' ? '!' : '…' }}</span>
    <span>{{ message }}</span>
    <button
      v-if="phase === 'failed'"
      type="button"
      class="bootstrap-retry"
      @click="emit('retry')"
    >
      {{ t('agent.retry') }}
    </button>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { useI18n } from 'vue-i18n'
import type { BootstrapPhase } from '../lib/bootstrap'

const props = defineProps<{ phase: BootstrapPhase }>()
const emit = defineEmits<{ retry: [] }>()
const { t } = useI18n()

const message = computed(() => {
  if (props.phase === 'failed') return t('agent.failed')
  if (props.phase === 'retrying') return t('agent.restarting')
  return t('agent.starting')
})
</script>
