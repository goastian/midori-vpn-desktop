import { i18n } from '../i18n'

export const AUTH_ORIGIN_REJECTED_MESSAGE =
  'The desktop app could not refresh your session because the server rejected its allowed origin. Check API_URL and CORS_ALLOWED_ORIGINS.'
export const VPN_SERVER_UNAVAILABLE_MESSAGE =
  'The selected VPN server could not accept the connection. Try another server or check the vpn-core server logs for the failed peer provisioning.'
export const VPN_DNS_PERMISSION_MESSAGE =
  'MidoriVPN needs its system permissions refreshed before it can protect DNS. Click “Enable required permissions” in the VPN tab, approve the system prompt, and connect again.'
export const AUTH_FAILED_MESSAGE =
  'No se pudo comunicar con el servidor de autenticación. Por favor, verifica tu conexión o vuelve a iniciar sesión.'

export type ErrorCategory =
  | 'dns_permission'
  | 'tun_permission'
  | 'server_unavailable'
  | 'auth_expired'
  | 'auth_failed'
  | 'auth_origin_rejected'
  | 'generic'

export interface ParsedError {
  category: ErrorCategory
  titleKey: string
  descKey: string
  rawMessage: string
  action?: 'grant_caps' | 'retry' | 'relogin'
}

/** Extracts clean error message from API JSON envelopes and localizes known backend keys. */
export function extractErrorMessage(raw: string): string {
  if (!raw) return ''
  let cleaned = raw.trim()

  // Structured local-agent errors carry a stable code alongside a fallback
  // message. Resolve the code before extracting that message so the selected
  // UI language remains authoritative.
  if (cleaned.includes('ERR_CERTIFICATE_IN_USE')) {
    return i18n.global.t('errors.certificateInUse')
  }
  if (cleaned.includes('ERR_LOCAL_CREDENTIAL_DELETE_FAILED')) {
    return i18n.global.t('errors.certificateLocalCleanup')
  }

  const jsonMatch = cleaned.match(/\{.*"error"\s*:\s*"([^"]+)".*\}/)
  if (jsonMatch && jsonMatch[1]) {
    cleaned = jsonMatch[1]
  } else {
    cleaned = cleaned.replace(/^api error \d+:\s*/i, '')
  }

  const lower = cleaned.toLowerCase()

  if (
    lower.includes('unsupported protocol scheme') ||
    lower.includes('api_url is not configured') ||
    lower.includes('auth: http post') ||
    lower.includes('failed to refresh token')
  ) {
    return i18n.global.t('errors.authExpired.desc') || AUTH_FAILED_MESSAGE
  }

  if (lower.includes('device_name_already_active') || lower.includes('ya tienes un dispositivo activo') || lower.includes('device with this name')) {
    return i18n.global.t('errors.deviceNameActive')
  }
  if (lower.includes('device limit reached') || lower.includes('device_limit_reached') || lower.includes('límite de dispositivos')) {
    return i18n.global.t('errors.deviceLimitReached')
  }
  if (lower.includes('too many connection requests') || lower.includes('too_many_requests') || lower.includes('demasiadas solicitudes')) {
    return i18n.global.t('errors.tooManyRequests')
  }
  if (lower.includes('server is full') || lower.includes('server_full') || lower.includes('servidor seleccionado está lleno')) {
    return i18n.global.t('errors.serverFull')
  }

  return cleaned
}

/** Converts any caught value to a human-readable string. */
export function toErrorMessage(e: unknown): string {
  const raw = typeof e === 'string'
    ? e
    : e instanceof Error
      ? e.message
      : String(e)

  if (isAuthOriginRejected(raw)) return AUTH_ORIGIN_REJECTED_MESSAGE
  if (isVPNServerUnavailable(raw)) return VPN_SERVER_UNAVAILABLE_MESSAGE
  if (isDNSPermissionDenied(raw)) return VPN_DNS_PERMISSION_MESSAGE
  if (isAuthTechnicalError(raw)) return i18n.global.t('errors.authExpired.desc') || AUTH_FAILED_MESSAGE

  const message = extractErrorMessage(raw)

  if (isAuthOriginRejected(message)) return AUTH_ORIGIN_REJECTED_MESSAGE
  if (isVPNServerUnavailable(message)) return VPN_SERVER_UNAVAILABLE_MESSAGE
  if (isDNSPermissionDenied(message)) return VPN_DNS_PERMISSION_MESSAGE
  if (isAuthTechnicalError(message)) return i18n.global.t('errors.authExpired.desc') || AUTH_FAILED_MESSAGE

  return message
}

export function isAuthTechnicalError(message: string): boolean {
  const lower = message.toLowerCase()
  return (
    lower.includes('unsupported protocol scheme') ||
    lower.includes('api_url is not configured') ||
    lower.includes('auth: http post') ||
    lower.includes('/api/v1/auth/refresh')
  )
}

export function isAuthOriginRejected(message: string): boolean {
  return message.includes('auth_origin_rejected:') || message.includes('origin not allowed')
}

export function isVPNServerUnavailable(message: string): boolean {
  return message.includes('failed to connect to VPN server') ||
    message.includes('ERR_SERVER_UNAVAILABLE') ||
    message.includes('502 Bad Gateway')
}

export function isDNSPermissionDenied(message: string): boolean {
  const lower = message.toLowerCase()
  return message.startsWith('dns_permission_denied:') ||
    lower.includes('err_dns_permission_denied') ||
    ((lower.includes('dns apply') || lower.includes('resolv.conf') || lower.includes('resolvconf')) &&
      (lower.includes('permission denied') || lower.includes('operation not permitted')))
}

export function isTunPermissionDenied(message: string): boolean {
  const lower = message.toLowerCase()
  return message.startsWith('tun_permission_denied:') ||
    lower.includes('err_tun_permission_denied') ||
    ((lower.includes('create tun') || lower.includes('wireguard') || lower.includes('permisos insuficientes para crear')) &&
      (lower.includes('operation not permitted') || lower.includes('permission denied') || lower.includes('permisos insuficientes')))
}

export function parseAppError(e: unknown): ParsedError {
  const rawMessage = typeof e === 'string'
    ? e
    : e instanceof Error
      ? e.message
      : String(e)

  const lower = rawMessage.toLowerCase()

  if (isDNSPermissionDenied(rawMessage)) {
    return {
      category: 'dns_permission',
      titleKey: 'errors.dnsPermission.title',
      descKey: 'errors.dnsPermission.desc',
      rawMessage,
      action: 'grant_caps',
    }
  }

  if (isTunPermissionDenied(rawMessage)) {
    return {
      category: 'tun_permission',
      titleKey: 'errors.tunPermission.title',
      descKey: 'errors.tunPermission.desc',
      rawMessage,
      action: 'grant_caps',
    }
  }

  if (isAuthOriginRejected(rawMessage)) {
    return {
      category: 'auth_origin_rejected',
      titleKey: 'errors.authOriginRejected.title',
      descKey: 'errors.authOriginRejected.desc',
      rawMessage,
      action: 'retry',
    }
  }

  if (
    rawMessage.startsWith('auth_expired:') ||
    isAuthTechnicalError(rawMessage) ||
    lower.includes('not authenticated') ||
    lower.includes('unauthorized')
  ) {
    return {
      category: 'auth_expired',
      titleKey: 'errors.authExpired.title',
      descKey: 'errors.authExpired.desc',
      rawMessage,
      action: 'relogin',
    }
  }

  if (isVPNServerUnavailable(rawMessage)) {
    return {
      category: 'server_unavailable',
      titleKey: 'errors.serverUnavailable.title',
      descKey: 'errors.serverUnavailable.desc',
      rawMessage,
      action: 'retry',
    }
  }

  return {
    category: 'generic',
    titleKey: 'errors.generic.title',
    descKey: '',
    rawMessage,
    action: 'retry',
  }
}
