import { describe, it, expect, beforeEach, vi } from 'vitest'
import { setActivePinia, createPinia } from 'pinia'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'
import { nextTick } from 'vue'

import AuthSection from '../components/dashboard/AuthSection.vue'
import { useAuthStore } from '../stores/auth'

vi.mock('@tauri-apps/api/core', () => ({
  invoke: vi.fn(async () => undefined),
}))

vi.mock('../lib/agent', () => ({
  agent: {
    auth: {
      status: vi.fn(async () => ({ logged_in: false })),
      logout: vi.fn(async () => undefined),
      startLogin: vi.fn(async () => ({ url: 'https://accounts.astian.org/application/o/foo/' })),
    },
  },
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
        auth: {
          signIn: 'Sign in',
          signInHint: 'Use your Astian account',
          signInWithAstian: 'Sign in with Astian',
          waitingBrowser: 'Waiting for browser…',
          completeInBrowser: 'Complete the flow in your browser.',
          cancelLogin: 'Cancel',
          activeSession: 'Active session',
          signOut: 'Sign out',
          signingOut: 'Signing out…',
        },
      },
    },
  })
}

function mountAuth() {
  return mount(AuthSection, {
    global: { plugins: [buildI18n()] },
  })
}

describe('AuthSection', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    vi.clearAllMocks()
  })

  it('renders sign-in card when unauthenticated', () => {
    const wrapper = mountAuth()
    expect(wrapper.find('[data-test="sign-in-btn"]').exists()).toBe(true)
    expect(wrapper.find('[data-test="sign-out-btn"]').exists()).toBe(false)
  })

  it('renders signed-in card with email when authenticated', async () => {
    const auth = useAuthStore()
    auth.authenticated = true
    auth.email = 'alice@example.com'
    auth.userId = 'alice'

    const wrapper = mountAuth()
    await nextTick()

    expect(wrapper.find('[data-test="sign-in-btn"]').exists()).toBe(false)
    const user = wrapper.find('[data-test="active-user"]')
    expect(user.exists()).toBe(true)
    expect(user.text()).toBe('alice@example.com')
  })

  it('shows an error when startLogin rejects', async () => {
    const auth = useAuthStore()
    const startSpy = vi.spyOn(auth, 'startLogin').mockRejectedValueOnce(new Error('refused'))

    const wrapper = mountAuth()
    await wrapper.find('[data-test="sign-in-btn"]').trigger('click')
    await nextTick()
    await nextTick()

    expect(startSpy).toHaveBeenCalledOnce()
    const err = wrapper.find('[data-test="login-error"]')
    expect(err.exists()).toBe(true)
    expect(err.text()).toContain('refused')
  })

  it('emits "authenticated" when auth flips to true', async () => {
    const auth = useAuthStore()
    const wrapper = mountAuth()

    auth.authenticated = true
    await nextTick()

    expect(wrapper.emitted('authenticated')).toBeTruthy()
    expect(wrapper.emitted('authenticated')!.length).toBe(1)
  })
})
