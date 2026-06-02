/**
 * Tiny formatting helpers used across the dashboard UI. Extracted from
 * Dashboard.vue so they can be unit-tested without mounting a component.
 */

/**
 * Format a byte count as a human-readable string ("12 B", "3.4 KB", "1.23 MB").
 * Negative or non-finite inputs are normalised to "0 B".
 */
export function formatBytes(b: number): string {
  if (!Number.isFinite(b) || b < 0) return '0 B'
  if (b < 1024) return `${b} B`
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`
  return `${(b / 1024 / 1024).toFixed(2)} MB`
}
