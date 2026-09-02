import { describe, expect, it } from 'vitest'
import { mount } from '@vue/test-utils'
import { createI18n } from 'vue-i18n'

import ToggleSwitch from '../components/ToggleSwitch.vue'
import ErrorAlertCard from '../components/dashboard/ErrorAlertCard.vue'

function buildI18n() {
  return createI18n({
    legacy: false,
    locale: 'en',
    fallbackLocale: 'en',
    missingWarn: false,
    fallbackWarn: false,
    messages: {
      en: {
        titlebar: { close: 'Close' },
        auth: { signIn: 'Sign in' },
        errors: {
          generic: { title: 'Connection error' },
          serverUnavailable: {
            title: 'Server unavailable',
            desc: 'Choose another server.',
            action: 'Retry',
          },
          dnsPermission: { action: 'Grant permissions' },
        },
      },
    },
  })
}

describe('accessible interactive controls', () => {
  it('announces and changes switch state through a native button', async () => {
    const wrapper = mount(ToggleSwitch, {
      props: { checked: false, label: 'Launch at login' },
    })
    const button = wrapper.get('button')

    expect(button.attributes('role')).toBe('switch')
    expect(button.attributes('aria-checked')).toBe('false')
    expect(button.attributes('aria-label')).toBe('Launch at login')

    await button.trigger('click')
    expect(wrapper.emitted('change')).toEqual([[true]])
  })

  it('keeps a disabled switch inert', async () => {
    const wrapper = mount(ToggleSwitch, {
      props: { checked: true, label: 'Start minimized', disabled: true },
    })
    const button = wrapper.get('button')

    expect(button.attributes('aria-checked')).toBe('true')
    expect(button.attributes()).toHaveProperty('disabled')
    await button.trigger('click')
    expect(wrapper.emitted('change')).toBeUndefined()
  })

  it('announces connection errors and names the dismiss action', () => {
    const wrapper = mount(ErrorAlertCard, {
      props: {
        error: {
          category: 'server_unavailable',
          titleKey: 'errors.serverUnavailable.title',
          descKey: 'errors.serverUnavailable.desc',
          rawMessage: 'request failed',
          action: 'retry',
        },
      },
      global: { plugins: [buildI18n()] },
    })

    expect(wrapper.get('[role="alert"]').text()).toContain('Server unavailable')
    expect(wrapper.get('.error-alert-close').attributes('aria-label')).toBe('Close')
    expect(wrapper.get('.btn-alert-secondary').text()).toBe('Retry')
  })
})
