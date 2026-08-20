/**
 * Shared error helpers used by Pinia stores.
 */

export const AUTH_ORIGIN_REJECTED_MESSAGE =
  'The desktop app could not refresh your session because the server rejected its allowed origin. Check API_URL and CORS_ALLOWED_ORIGINS.'
export const VPN_SERVER_UNAVAILABLE_MESSAGE =
  'The selected VPN server could not accept the connection. Try another server or check the vpn-core server logs for the failed peer provisioning.'
export const VPN_DNS_PERMISSION_MESSAGE =
  'MidoriVPN needs its system permissions refreshed before it can protect DNS. Click “Enable required permissions” in the VPN tab, approve the system prompt, and connect again.'

/** Converts any caught value to a human-readable string. */
export function toErrorMessage(e: unknown): string {
  const message = typeof e === 'string'
    ? e
    : e instanceof Error
      ? e.message
      : String(e)

  if (isAuthOriginRejected(message)) return AUTH_ORIGIN_REJECTED_MESSAGE
  if (isVPNServerUnavailable(message)) return VPN_SERVER_UNAVAILABLE_MESSAGE
  if (isDNSPermissionDenied(message)) return VPN_DNS_PERMISSION_MESSAGE

  return message
}

export function isAuthOriginRejected(message: string): boolean {
  return message.includes('auth_origin_rejected:') || message.includes('origin not allowed')
}

export function isVPNServerUnavailable(message: string): boolean {
  return message.includes('failed to connect to VPN server')
}

/**
 * Recognise the legacy/minimal-capability failure emitted by the Linux
 * resolvconf backend. This is a desktop-local permission state, not a
 * vpn-core provisioning error, so the UI must point users back to its
 * permission consent flow rather than exposing the raw 500 response.
 */
export function isDNSPermissionDenied(message: string): boolean {
  return message.includes('dns apply (resolvconf)')
    && message.includes('/etc/resolv.conf')
    && message.includes('permission denied')
}
