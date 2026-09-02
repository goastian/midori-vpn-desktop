import { describe, it, expect, beforeEach, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'

import LanguageSelect from '../components/LanguageSelect.vue'
import { getLocale, i18n, setLocale } from '../i18n'
import en from '../i18n/locales/en.json'
import es from '../i18n/locales/es.json'
import pt from '../i18n/locales/pt.json'
import de from '../i18n/locales/de.json'
import fr from '../i18n/locales/fr.json'
import ru from '../i18n/locales/ru.json'

function messageKeys(value: unknown, prefix = ''): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return [prefix]
  return Object.entries(value).flatMap(([key, child]) =>
    messageKeys(child, prefix ? `${prefix}.${key}` : key),
  )
}

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

  it('keeps every supported locale aligned with the English message contract', () => {
    const expected = messageKeys(en).sort()
    for (const messages of [es, pt, de, fr, ru]) {
      expect(messageKeys(messages).sort()).toEqual(expected)
    }
  })
})
