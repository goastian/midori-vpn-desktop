import type { Server, VPNTransportProtocol } from './agent'

export type ProtocolPolicy = VPNTransportProtocol | 'smart_auto'

export function protocolIsAvailable(
  policy: ProtocolPolicy,
  servers: Server[],
  connected: boolean,
  activeProtocol: VPNTransportProtocol,
): boolean {
  if (policy === 'smart_auto') return true
  if (connected && activeProtocol === policy) return true
  return servers.some((server) => {
    if (policy === 'wireguard') return server.supports_wireguard
    return server.transports?.some((transport) =>
      transport.protocol === policy && transport.enabled && transport.health_status === 'healthy',
    ) ?? false
  })
}
