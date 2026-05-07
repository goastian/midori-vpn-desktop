import { describe, it, expect } from 'vitest'
import { isValidMeshIp, isValidPort, isValidProxyScheme } from '../lib/meshValidation'

describe('isValidMeshIp', () => {
  it('accepts valid IPv4', () => {
    expect(isValidMeshIp('10.0.0.1')).toBe(true)
    expect(isValidMeshIp('192.168.1.100')).toBe(true)
    expect(isValidMeshIp('100.64.0.1')).toBe(true)
  })

  it('rejects invalid IPv4', () => {
    expect(isValidMeshIp('999.999.999.999')).toBe(false)
    expect(isValidMeshIp('256.0.0.1')).toBe(false)
    expect(isValidMeshIp('1.2.3')).toBe(false)
  })

  it('accepts valid IPv6', () => {
    expect(isValidMeshIp('fd00::1')).toBe(true)
    expect(isValidMeshIp('2001:db8::1')).toBe(true)
  })

  it('rejects non-IP strings', () => {
    expect(isValidMeshIp('')).toBe(false)
    expect(isValidMeshIp('not-an-ip')).toBe(false)
    expect(isValidMeshIp('localhost')).toBe(false)
  })
})

describe('isValidPort', () => {
  it('accepts valid ports', () => {
    expect(isValidPort(1)).toBe(true)
    expect(isValidPort(8080)).toBe(true)
    expect(isValidPort(65535)).toBe(true)
  })

  it('rejects out-of-range ports', () => {
    expect(isValidPort(0)).toBe(false)
    expect(isValidPort(65536)).toBe(false)
    expect(isValidPort(-1)).toBe(false)
    expect(isValidPort(99999)).toBe(false)
  })

  it('rejects non-integer values', () => {
    expect(isValidPort(8080.5)).toBe(false)
    expect(isValidPort('8080')).toBe(false)
    expect(isValidPort(null)).toBe(false)
    expect(isValidPort(undefined)).toBe(false)
  })
})

describe('isValidProxyScheme', () => {
  it('accepts valid schemes', () => {
    expect(isValidProxyScheme('socks5')).toBe(true)
    expect(isValidProxyScheme('http')).toBe(true)
    expect(isValidProxyScheme('https')).toBe(true)
  })

  it('rejects invalid schemes', () => {
    expect(isValidProxyScheme('ftp')).toBe(false)
    expect(isValidProxyScheme('')).toBe(false)
    expect(isValidProxyScheme('SOCKS5')).toBe(false)
    expect(isValidProxyScheme(42)).toBe(false)
  })
})
