/**
 * useCaps — shared reactive state for Linux capability gate.
 *
 * Used by Dashboard, Mesh, and Settings to disable firewall-sensitive
 * features until the user explicitly grants capabilities to the agent binary.
 *
 * The module-level refs are intentionally singleton so every component that
 * calls useCaps() shares the same state without a Pinia store.
 */

import { ref, computed } from 'vue'
import { invoke } from '@tauri-apps/api/core'
import { initAgentToken } from '../lib/agent'

const capsGranted = ref(false)   // default false — assume not granted until checked
const capsGranting = ref(false)
const capsError = ref('')

export function useCaps() {
  /**
   * Query the Tauri backend for whether the agent binary has CAP_NET_ADMIN.
   * Should be called once on mount and once after successful login.
   */
  async function checkCaps() {
    try {
      capsGranted.value = await invoke<boolean>('agent_has_caps')
    } catch {
      // Non-Linux platforms (macOS, Windows) don't need caps.
      capsGranted.value = true
    }
  }

  /**
   * Invoke pkexec setcap via the Tauri backend.
    * On success, restarts the agent process so it picks up the newly-applied
    * file capabilities in its effective set.
   */
  async function grantCaps(): Promise<boolean> {
    capsGranting.value = true
    capsError.value = ''
    try {
      const ok = await invoke<boolean>('grant_agent_permissions')
      if (ok) {
        // The currently running agent may still have CapEff=0 if it was
        // started before setcap. Restart it so create TUN succeeds.
        try {
		  await invoke('restart_agent_cmd')
		  await initAgentToken()
        } catch {
          // If restart fails we'll still expose granted state; callers surface
          // runtime errors and the user can retry.
        }

        capsGranted.value = await invoke<boolean>('agent_has_caps')
        if (!capsGranted.value) {
          capsError.value = 'Permisos aplicados, pero no se pudieron verificar en el agente.'
          return false
        }
        return true
      } else {
        capsError.value = 'No se pudo aplicar. Ejecuta el comando manualmente como root.'
        return false
      }
    } catch (e) {
      capsError.value = String(e)
      return false
    } finally {
      capsGranting.value = false
    }
  }

  /** True when user is authenticated but caps have not been granted yet. */
  const featuresLocked = computed(() => !capsGranted.value)

  /**
   * Revoke capabilities from the agent binary via pkexec setcap -r.
   * On success, capsGranted is reset to false so the UI re-locks.
   */
  async function revertCaps(): Promise<boolean> {
    capsGranting.value = true
    capsError.value = ''
    try {
      const ok = await invoke<boolean>('revert_agent_permissions')
      if (ok) {
        capsGranted.value = false
        return true
      } else {
        capsError.value = 'No se pudo revertir. Ejecuta "sudo setcap -r /usr/local/bin/midorivpn-agent" manualmente.'
        return false
      }
    } catch (e) {
      capsError.value = String(e)
      return false
    } finally {
      capsGranting.value = false
    }
  }

  return {
    capsGranted,
    capsGranting,
    capsError,
    featuresLocked,
    checkCaps,
    grantCaps,
    revertCaps,
  }
}
