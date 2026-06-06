import { beforeEach, describe, expect, it } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useProtectionStore } from '../stores/protection'

describe('protection store', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('applies kill switch and DNS protection status', () => {
    const protection = useProtectionStore()

    protection.applyStatus({
      kill_switch_active: true,
      dns_protected: true,
      mode: 'full-tunnel',
      last_error: '',
    })

    expect(protection.initialized).toBe(true)
    expect(protection.killSwitchActive).toBe(true)
    expect(protection.dnsProtected).toBe(true)
    expect(protection.mode).toBe('full-tunnel')
    expect(protection.hasSignal).toBe(true)
  })

  it('keeps last error visible even when protection is inactive', () => {
    const protection = useProtectionStore()

    protection.applyStatus({
      kill_switch_active: false,
      dns_protected: false,
      last_error: 'resolv.conf restore failed',
    })

    expect(protection.killSwitchActive).toBe(false)
    expect(protection.dnsProtected).toBe(false)
    expect(protection.lastError).toBe('resolv.conf restore failed')
    expect(protection.hasSignal).toBe(true)
  })
})
