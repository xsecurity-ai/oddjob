/** Severity colours, shared.
 *
 * Was defined inside VulnsView, which meant anything else showing a
 * severity had to either import a view or invent its own palette.
 */
import { neon } from '../theme'

export const SEVERITY_COLOUR: Record<string, string> = {
  critical: neon.red, high: neon.orange, medium: neon.yellow,
  low: neon.cyan, info: neon.muted,
}
