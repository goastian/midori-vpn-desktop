/**
 * Validation helpers for mesh peer data received from the agent.
 * Used to filter out malformed peers before they reach the UI.
 */

const VALID_PROXY_SCHEMES = new Set(['socks5', 'http', 'https'])

/** Returns true if the string looks like an IPv4 or IPv6 address. */
export function isValidMeshIp(ip: string): boolean {
  if (!ip || typeof ip !== 'string') return false
  // IPv4
  const ipv4 = /^(\d{1,3}\.){3}\d{1,3}$/
  if (ipv4.test(ip)) {
    return ip.split('.').every(seg => parseInt(seg, 10) <= 255)
  }
  // IPv6 (simplified: allow full and compressed forms)
  const ipv6 = /^[0-9a-fA-F:]{2,39}$/
  return ipv6.test(ip) && ip.includes(':')
}

/** Returns true if port is a valid TCP/UDP port number (1–65535). */
export function isValidPort(port: unknown): port is number {
  return typeof port === 'number' && Number.isInteger(port) && port >= 1 && port <= 65535
}

/** Returns true if the proxy scheme is one of the supported values. */
export function isValidProxyScheme(scheme: unknown): scheme is string {
  return typeof scheme === 'string' && VALID_PROXY_SCHEMES.has(scheme)
}
