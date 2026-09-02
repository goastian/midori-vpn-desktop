import { beforeEach, describe, expect, it, vi } from 'vitest'

import { invokePlatform } from '../lib/agent'
import { CAPABILITIES_CHANGED_EVENT, useCaps } from './useCaps'

vi.mock('../lib/agent', () => ({
  invokePlatform: vi.fn(),
}))

const invoke = vi.mocked(invokePlatform)

describe('useCaps', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    const caps = useCaps()
    caps.capsGranted.value = false
    caps.capsError.value = ''
  })

  it('announces a successful permission change so global warnings refresh', async () => {
    invoke
      .mockResolvedValueOnce(true)
      .mockResolvedValueOnce({ ok: true })
      .mockResolvedValueOnce(true)
    const changed = vi.fn()
    window.addEventListener(CAPABILITIES_CHANGED_EVENT, changed)

    await expect(useCaps().grantCapsSmart()).resolves.toBe(true)

    expect(changed).toHaveBeenCalledOnce()
    window.removeEventListener(CAPABILITIES_CHANGED_EVENT, changed)
  })

  it('announces revocation so the global warning returns', async () => {
    invoke.mockResolvedValueOnce(true)
    const changed = vi.fn()
    window.addEventListener(CAPABILITIES_CHANGED_EVENT, changed)

    await expect(useCaps().revertCaps()).resolves.toBe(true)

    expect(changed).toHaveBeenCalledOnce()
    window.removeEventListener(CAPABILITIES_CHANGED_EVENT, changed)
  })
})
