import { useCallback, useEffect, useState } from 'react'

/**
 * A one-of-several UI preference that survives a reload.
 *
 * The string sibling of `useStoredFlag`, and storage is wrapped for the
 * same reason: it throws in private mode, with site data blocked, and in
 * some embedded webviews. The preference must degrade to its default
 * rather than taking the page down with it.
 *
 * **`allowed` is not decoration.** A stored value outlives the code that
 * wrote it: a tab gets renamed or removed and the key still holds the old
 * name, which would select a tab that no longer exists and render an
 * empty view that a reload cannot clear — the bad value is what gets read
 * back every time. Anything not in `allowed` falls back, so the worst a
 * stale key can do is start you on the default tab.
 */
export function readChoice<T extends string>(
  raw: string | null, allowed: readonly T[], fallback: T,
): T {
  return allowed.includes(raw as T) ? (raw as T) : fallback
}


export function useStoredChoice<T extends string>(
  key: string, allowed: readonly T[], fallback: T,
) {
  const [value, setValue] = useState<T>(() => {
    try {
      return readChoice(window.localStorage.getItem(key), allowed, fallback)
    } catch {
      return fallback
    }
  })

  useEffect(() => {
    try {
      window.localStorage.setItem(key, value)
    } catch {
      // The preference simply will not persist. Not worth surfacing.
    }
  }, [key, value])

  // Guarded here too, so a caller wiring this to a component that can
  // emit an arbitrary value cannot write a choice back that the reader
  // would then reject on the next load.
  const choose = useCallback((next: string) => {
    if (allowed.includes(next as T)) setValue(next as T)
    // `allowed` is a module-level literal at every call site; listing it
    // as a dep would re-make this callback on every render if a caller
    // ever passed an inline array.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return [value, choose] as const
}
