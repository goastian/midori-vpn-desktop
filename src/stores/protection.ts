import { defineStore } from 'pinia'
import { computed, ref } from 'vue'
import type { ProtectionStatus } from '../lib/agent'

export const useProtectionStore = defineStore('protection', () => {
  const killSwitchActive = ref(false)
  const dnsProtected = ref(false)
  const mode = ref('')
  const lastError = ref('')
  const initialized = ref(false)

  const hasSignal = computed(() =>
    initialized.value && (killSwitchActive.value || dnsProtected.value || !!lastError.value)
  )

  function applyStatus(s: ProtectionStatus | null | undefined) {
    initialized.value = true
    killSwitchActive.value = !!s?.kill_switch_active
    dnsProtected.value = !!s?.dns_protected
    mode.value = s?.mode ?? ''
    lastError.value = s?.last_error ?? ''
  }

  function clear() {
    killSwitchActive.value = false
    dnsProtected.value = false
    mode.value = ''
    lastError.value = ''
  }

  return {
    killSwitchActive,
    dnsProtected,
    mode,
    lastError,
    initialized,
    hasSignal,
    applyStatus,
    clear,
  }
})
