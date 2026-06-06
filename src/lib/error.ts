/**
 * Shared error helpers used by Pinia stores.
 */

export const AUTH_ORIGIN_REJECTED_MESSAGE =
  'The desktop app could not refresh your session because the server rejected its allowed origin. Check API_URL and CORS_ALLOWED_ORIGINS.'
export const VPN_SERVER_UNAVAILABLE_MESSAGE =
  'The selected VPN server could not accept the connection. Try another server or check the vpn-core server logs for the failed peer provisioning.'

/** Converts any caught value to a human-readable string. */
export function toErrorMessage(e: unknown): string {
  const message = typeof e === 'string'
    ? e
    : e instanceof Error
      ? e.message
      : String(e)

  if (isAuthOriginRejected(message)) return AUTH_ORIGIN_REJECTED_MESSAGE
  if (isVPNServerUnavailable(message)) return VPN_SERVER_UNAVAILABLE_MESSAGE

  return message
}

export function isAuthOriginRejected(message: string): boolean {
  return message.includes('auth_origin_rejected:') || message.includes('origin not allowed')
}

export function isVPNServerUnavailable(message: string): boolean {
  return message.includes('failed to connect to VPN server')
}
