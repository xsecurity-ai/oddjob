import { useCallback, useEffect, useState } from 'react'

/**
 * A boolean UI preference that survives reloads.
 *
 * localStorage, not a cookie: a cookie is attached to every request to the
 * server, and the server has no use for which way a sidebar is pointing.
 *
 * Every access is wrapped — storage throws in private mode, with site data
 * blocked, and in some embedded webviews. The flag must degrade to its
 * default rather than taking the page down with it.
 */
export function useStoredFlag(key: string, fallback: boolean) {
  const [value, setValue] = useState<boolean>(() => {
    try {
      const raw = window.localStorage.getItem(key)
      return raw === null ? fallback : raw === '1'
    } catch {
      return fallback
    }
  })

  useEffect(() => {
    try {
      window.localStorage.setItem(key, value ? '1' : '0')
    } catch {
      // Preference simply will not persist. Not worth surfacing.
    }
  }, [key, value])

  const toggle = useCallback(() => setValue((v) => !v), [])
  return [value, toggle, setValue] as const
}
