import { createI18n } from 'vue-i18n'
import en from './locales/en.json'

const STORAGE_KEY = 'midorivpn_lang'
const DEFAULT_LOCALE = 'en'
export const SUPPORTED_LOCALES = ['en', 'es', 'pt', 'de', 'fr', 'ru'] as const
export type Locale = (typeof SUPPORTED_LOCALES)[number]
type LocaleMessages = typeof en

const localeLoaders: Record<Exclude<Locale, 'en'>, () => Promise<LocaleMessages>> = {
  es: () => import('./locales/es.json').then((m) => m.default as LocaleMessages),
  pt: () => import('./locales/pt.json').then((m) => m.default as LocaleMessages),
  de: () => import('./locales/de.json').then((m) => m.default as LocaleMessages),
  fr: () => import('./locales/fr.json').then((m) => m.default as LocaleMessages),
  ru: () => import('./locales/ru.json').then((m) => m.default as LocaleMessages),
}

const loadedLocales = new Set<Locale>([DEFAULT_LOCALE])

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

const detectedLocale = detectLocale()

export const i18n = createI18n({
  legacy: false,
  locale: DEFAULT_LOCALE,
  fallbackLocale: DEFAULT_LOCALE,
  messages: { en },
})

async function loadLocale(lang: Locale): Promise<void> {
  if (loadedLocales.has(lang)) return
  if (lang === DEFAULT_LOCALE) return
  const messages = await localeLoaders[lang]()
  i18n.global.setLocaleMessage(lang, messages)
  loadedLocales.add(lang)
}

export async function initLocale(): Promise<void> {
  await applyLocale(detectedLocale, false)
}

export async function setLocale(lang: Locale): Promise<void> {
  await applyLocale(lang, true)
}

async function applyLocale(lang: Locale, persist: boolean): Promise<void> {
  await loadLocale(lang)
  ;(i18n.global.locale as { value: string }).value = lang
  if (persist) {
    localStorage.setItem(STORAGE_KEY, lang)
  }
  applyDocumentLocale(lang)
}

export function getLocale(): Locale {
  return (i18n.global.locale as { value: string }).value as Locale
}

applyDocumentLocale(getLocale())
