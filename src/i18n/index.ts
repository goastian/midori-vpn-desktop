import { createI18n } from 'vue-i18n'
import en from './locales/en.json'
import es from './locales/es.json'
import pt from './locales/pt.json'
import de from './locales/de.json'
import fr from './locales/fr.json'
import ru from './locales/ru.json'

const STORAGE_KEY = 'midorivpn_lang'
const DEFAULT_LOCALE = 'en'
export const SUPPORTED_LOCALES = ['en', 'es', 'pt', 'de', 'fr', 'ru'] as const
export type Locale = (typeof SUPPORTED_LOCALES)[number]

function isSupportedLocale(value: string): value is Locale {
  return SUPPORTED_LOCALES.includes(value as Locale)
}

function normalizeLocale(value: string | null | undefined): Locale | null {
  if (!value) return null
  const normalized = value.toLowerCase().split('-')[0]
  return isSupportedLocale(normalized) ? normalized : null
}

function detectLocale(): Locale {
  const stored = normalizeLocale(localStorage.getItem(STORAGE_KEY))
  if (stored) return stored

  const candidates = [...navigator.languages, navigator.language]
  for (const candidate of candidates) {
    const locale = normalizeLocale(candidate)
    if (locale) return locale
  }

  return DEFAULT_LOCALE
}

function applyDocumentLocale(lang: Locale) {
  document.documentElement.lang = lang
}

export const i18n = createI18n({
  legacy: false,
  locale: detectLocale(),
  fallbackLocale: DEFAULT_LOCALE,
  messages: { en, es, pt, de, fr, ru },
})

export function setLocale(lang: Locale) {
  ;(i18n.global.locale as { value: string }).value = lang
  localStorage.setItem(STORAGE_KEY, lang)
  applyDocumentLocale(lang)
}

export function getLocale(): Locale {
  return (i18n.global.locale as { value: string }).value as Locale
}

applyDocumentLocale(getLocale())
