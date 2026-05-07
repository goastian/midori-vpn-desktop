import { createI18n } from 'vue-i18n'
import en from './locales/en.json'
import es from './locales/es.json'
import pt from './locales/pt.json'
import de from './locales/de.json'
import fr from './locales/fr.json'
import ru from './locales/ru.json'

const STORAGE_KEY = 'midorivpn_lang'
const SUPPORTED = ['en', 'es', 'pt', 'de', 'fr', 'ru'] as const
export type Locale = (typeof SUPPORTED)[number]

function detectLocale(): Locale {
  const stored = localStorage.getItem(STORAGE_KEY)
  if (stored && SUPPORTED.includes(stored as Locale)) return stored as Locale
  const nav = navigator.language.split('-')[0]
  if (SUPPORTED.includes(nav as Locale)) return nav as Locale
  return 'es'
}

export const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: 'en',
  messages: { en, es, pt, de, fr, ru },
})

export function setLocale(lang: Locale) {
  ;(i18n.global.locale as { value: string }).value = lang
  localStorage.setItem(STORAGE_KEY, lang)
}

export function getLocale(): Locale {
  return (i18n.global.locale as { value: string }).value as Locale
}
