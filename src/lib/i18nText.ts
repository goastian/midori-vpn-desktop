import { i18n } from '../i18n'

export function text(key: string, params?: Record<string, unknown>): string {
  const t = i18n.global.t as (key: string, params?: Record<string, unknown>) => string
  return t(key, params)
}
