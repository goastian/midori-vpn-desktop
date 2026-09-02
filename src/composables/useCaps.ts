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
import { invokePlatform } from '../lib/agent'
import { text } from '../lib/i18nText'

const capsGranted = ref(false)   // default false — assume not granted until checked
const capsGranting = ref(false)
const capsError = ref('')

export function useCaps() {
  /**
   * Query the local agent for whether its binary has CAP_NET_ADMIN.
   * Should be called once on mount and once after successful login.
   */
  async function checkCaps() {
    try {
      capsGranted.value = await invokePlatform<boolean>('agent_has_caps')
    } catch {
      capsGranted.value = false
    }
  }

  /**
   * Ask the local agent to invoke pkexec setcap.
    * On success, restarts the agent process so it picks up the newly-applied
    * file capabilities in its effective set.
   */
  /**
   * Single-prompt grant. On Linux we always request the extended cap set so
   * the agent can manage DNS regardless of the host's resolver (systemd-
   * resolved or plain /etc/resolv.conf). This makes the post-login UX a
   * single polkit dialog and avoids the "permission denied" on /etc/resolv.conf
   * that surfaces when only the minimal caps are applied on resolvconf hosts.
   */
  async function grantCapsSmart(): Promise<boolean> {
    capsGranting.value = true
    capsError.value = ''
    try {
      const ok = await invokePlatform<boolean>('grant_dns_protection_caps')
      if (!ok) {
        capsError.value = text('errors.capsApplyFailed')
        return false
      }
      try {
        await invokePlatform('restart_agent_cmd')
      } catch {
        // Non-fatal: surfaced via runtime errors.
      }
      capsGranted.value = await invokePlatform<boolean>('agent_has_caps')
      if (!capsGranted.value) {
        capsError.value = text('errors.capsVerifyFailed')
        return false
      }
      return true
    } catch (e) {
      capsError.value = String(e)
      return false
    } finally {
      capsGranting.value = false
    }
  }

  /** True when user is authenticated but caps have not been granted yet. */
  const featuresLocked = computed(() => !capsGranted.value)
  async function revertCaps(): Promise<boolean> {
    capsGranting.value = true
    capsError.value = ''
    try {
      const ok = await invokePlatform<boolean>('revert_agent_permissions')
      if (ok) {
        capsGranted.value = false
        return true
      } else {
        capsError.value = text('errors.capsRevertFailed')
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
    grantCapsSmart,
    revertCaps,
  }
}
