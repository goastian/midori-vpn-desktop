import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import { nextTick } from 'vue'

import PermissionsTriggerCard from '../components/dashboard/PermissionsTriggerCard.vue'
import { useAuthStore } from '../stores/auth'

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(async () => undefined),
}))

vi.mock('../lib/agent', () => ({
  agent: { auth: { status: vi.fn(async () => ({ logged_in: false })) } },
}))

function buildI18n() {
  return createI18n({
    legacy: false,
    locale: 'en',
    fallbackLocale: 'en',
    missingWarn: false,
    fallbackWarn: false,
    messages: {
      en: {
        perms: {
          title: 'Enable permissions',
          body: 'MidoriVPN needs CAP_NET_ADMIN to manage the tunnel.',
          enable: 'Enable',
          applying: 'Applying…',
        },
      },
    },
  })
}

function mountCard(props: { capsGranted: boolean; capsGranting: boolean; capsError: string }) {
  return mount(PermissionsTriggerCard, {
    props,
    global: { plugins: [buildI18n()] },
  })
}

describe('PermissionsTriggerCard', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('is hidden when user is not authenticated', () => {
    const w = mountCard({ capsGranted: false, capsGranting: false, capsError: '' })
    expect(w.find('.perms-trigger-card').exists()).toBe(false)
  })

  it('is hidden when caps are already granted', () => {
    const auth = useAuthStore()
    auth.authenticated = true
    const w = mountCard({ capsGranted: true, capsGranting: false, capsError: '' })
    expect(w.find('.perms-trigger-card').exists()).toBe(false)
  })

  it('shows trigger and emits "request" when clicked', async () => {
    const auth = useAuthStore()
    auth.authenticated = true

    const w = mountCard({ capsGranted: false, capsGranting: false, capsError: '' })
    await nextTick()

    const btn = w.find('[data-test="open-perms-modal-btn"]')
    expect(btn.exists()).toBe(true)
    expect((btn.element as HTMLButtonElement).disabled).toBe(false)

    await btn.trigger('click')
    expect(w.emitted('request')).toBeTruthy()
    expect(w.emitted('request')!.length).toBe(1)
  })

  it('disables the trigger and shows label while applying', () => {
    const auth = useAuthStore()
    auth.authenticated = true

    const w = mountCard({ capsGranted: false, capsGranting: true, capsError: '' })
    const btn = w.find('[data-test="open-perms-modal-btn"]')
    expect((btn.element as HTMLButtonElement).disabled).toBe(true)
    expect(btn.text()).toBe('Applying…')
  })

  it('surfaces capsError text when provided', () => {
    const auth = useAuthStore()
    auth.authenticated = true

    const w = mountCard({ capsGranted: false, capsGranting: false, capsError: 'pkexec failed' })
    const err = w.find('[data-test="perms-error"]')
    expect(err.exists()).toBe(true)
    expect(err.text()).toBe('pkexec failed')
  })
})
