import { describe, it, expect, beforeEach, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

import LanguageSelect from '../components/LanguageSelect.vue'
import { getLocale, i18n, setLocale } from '../i18n'

describe('i18n locale loading', () => {
  beforeEach(async () => {
    localStorage.clear()
    await setLocale('en')
  })

  it('loads secondary locale messages on demand', async () => {
    expect(i18n.global.getLocaleMessage('pt')).toEqual({})

    await setLocale('pt')

    expect(getLocale()).toBe('pt')
    expect(document.documentElement.lang).toBe('pt')
    expect(i18n.global.getLocaleMessage('pt')).toMatchObject({
      settings: expect.any(Object),
    })
  })

  it('updates LanguageSelect after the async locale switch completes', async () => {
    const wrapper = mount(LanguageSelect, {
      global: { plugins: [i18n] },
    })
    const select = wrapper.get('select')

    ;(select.element as HTMLSelectElement).value = 'es'
    await select.trigger('change')
    await flushPromises()

    await vi.waitFor(() => expect(getLocale()).toBe('es'))
    expect((select.element as HTMLSelectElement).disabled).toBe(false)
    expect((select.element as HTMLSelectElement).value).toBe('es')
  })
})
