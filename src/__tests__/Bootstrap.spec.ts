import { describe, expect, it, vi } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'

import AgentBootstrapBanner from '../components/AgentBootstrapBanner.vue'
import { createBootstrapCoordinator, type BootstrapPhase } from '../lib/bootstrap'

function buildI18n() {
  return createI18n({
    legacy: false,
    locale: 'en',
    messages: {
      en: {
        agent: {
          starting: 'Loading the local VPN service…',
          restarting: 'Reconnecting…',
          failed: 'The local VPN service could not be reached.',
          retry: 'Try again',
        },
      },
    },
  })
}

describe('desktop bootstrap recovery', () => {
  it('recovers after failure without duplicating the subscription', async () => {
    const phases: BootstrapPhase[] = []
    const cleanup = vi.fn()
    const initialize = vi.fn()
      .mockRejectedValueOnce(new Error('agent unavailable'))
      .mockResolvedValue(undefined)
    const subscribe = vi.fn(() => cleanup)
    const coordinator = createBootstrapCoordinator({
      initialize,
      subscribe,
      onPhaseChange: (phase) => phases.push(phase),
    })

    await expect(coordinator.run('initial')).resolves.toBe(false)
    await expect(coordinator.run('retry')).resolves.toBe(true)
    await expect(coordinator.run('retry')).resolves.toBe(true)

    expect(phases).toEqual(['loading', 'failed', 'retrying', 'ready', 'retrying', 'ready'])
    expect(subscribe).toHaveBeenCalledTimes(1)
    coordinator.stop()
    expect(cleanup).toHaveBeenCalledTimes(1)
  })

  it('coalesces concurrent retries into one initialization', async () => {
    let finish!: () => void
    const initialize = vi.fn(() => new Promise<void>((resolve) => { finish = resolve }))
    const subscribe = vi.fn(() => vi.fn())
    const coordinator = createBootstrapCoordinator({
      initialize,
      subscribe,
      onPhaseChange: vi.fn(),
    })

    const first = coordinator.run('initial')
    const second = coordinator.run('retry')
    expect(first).toBe(second)
    expect(initialize).toHaveBeenCalledTimes(1)

    finish()
    await expect(first).resolves.toBe(true)
    expect(subscribe).toHaveBeenCalledTimes(1)
  })

  it('does not subscribe when stopped during initialization', async () => {
    let finish!: () => void
    const initialize = vi.fn(() => new Promise<void>((resolve) => { finish = resolve }))
    const subscribe = vi.fn(() => vi.fn())
    const onPhaseChange = vi.fn()
    const coordinator = createBootstrapCoordinator({ initialize, subscribe, onPhaseChange })

    const pending = coordinator.run('initial')
    coordinator.stop()
    finish()

    await expect(pending).resolves.toBe(false)
    expect(subscribe).not.toHaveBeenCalled()
    expect(onPhaseChange).toHaveBeenCalledTimes(1)
    await expect(coordinator.run('retry')).resolves.toBe(false)
  })

  it('shows progress and an actionable localized failure', async () => {
    const loading = mount(AgentBootstrapBanner, {
      props: { phase: 'loading' },
      global: { plugins: [buildI18n()] },
    })
    expect(loading.get('[role="status"]').text()).toContain('Loading the local VPN service')

    const failed = mount(AgentBootstrapBanner, {
      props: { phase: 'failed' },
      global: { plugins: [buildI18n()] },
    })
    expect(failed.get('[role="alert"]').attributes('aria-live')).toBe('assertive')
    await failed.get('button').trigger('click')
    expect(failed.emitted('retry')).toHaveLength(1)
  })
})
