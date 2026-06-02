/**
 * useDnsProtection — tracks the agent's DNS backend and the optional
 * elevated capabilities (CAP_DAC_OVERRIDE + CAP_LINUX_IMMUTABLE) required
 * by the resolvconf backend.
 *
 * Singleton refs so every component shares the same banner state.
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { agent, type DnsStatus } from '../lib/agent'

const status = ref<DnsStatus | null>(null)
const loading = ref(false)
const granting = ref(false)
const error = ref('')

export function useDnsProtection() {
  /** Fetch DNS backend status from the agent. Safe to call repeatedly. */
  async function refresh(): Promise<void> {
    loading.value = true
    try {
      status.value = await agent.dns.status()
    } catch (e) {
      // Agent unreachable or non-Linux. Treat as "nothing to prompt".
      status.value = { backend: 'none', needs_extra_caps: false, caps_missing: [], caps_ok: true }
      error.value = String(e)
    } finally {
      loading.value = false
    }
  }

  /** Request the extended cap set via pkexec. Returns true on success. */
  async function grantExtraCaps(): Promise<boolean> {
    granting.value = true
    error.value = ''
    try {
      const ok = await invoke<boolean>('grant_dns_protection_caps')
      if (ok) {
        // Restart agent so the new file caps land in the effective set.
        try {
          await invoke('restart_agent_cmd')
        } catch {
          // Non-fatal: caller can retry refresh().
        }
        await refresh()
        return status.value?.caps_ok ?? false
      }
      error.value = 'No se pudieron aplicar los permisos extendidos.'
      return false
    } catch (e) {
      error.value = String(e)
      return false
    } finally {
      granting.value = false
    }
  }

  /** True when the UI should show the "Grant DNS protection caps" banner. */
  const needsPrompt = computed(() => {
    const s = status.value
    return !!s && s.backend === 'resolvconf' && !s.caps_ok
  })

  return {
    status,
    loading,
    granting,
    error,
    needsPrompt,
    refresh,
    grantExtraCaps,
  }
}
