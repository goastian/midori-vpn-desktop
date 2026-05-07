/**
 * Shared error helpers used by Pinia stores.
 */

/** Converts any caught value to a human-readable string. */
export function toErrorMessage(e: unknown): string {
  if (typeof e === 'string') return e
  if (e instanceof Error) return e.message
  return String(e)
}
