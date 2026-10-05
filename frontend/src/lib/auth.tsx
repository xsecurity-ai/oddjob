import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { api, ApiError, type Me } from './api'

type Ctx = {
  me: Me | null
  loading: boolean
  setupRequired: boolean
  /** Effective role on a project code, or null if no grant. */
  roleOn: (code: string | null) => string | null
  canWrite: (code: string | null) => boolean
  refresh: () => Promise<void>
  signOut: () => Promise<void>
}

const AuthCtx = createContext<Ctx | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const qc = useQueryClient()
  const [bump, setBump] = useState(0)

  const setup = useQuery({
    queryKey: ['setup-required', bump],
    queryFn: api.setupRequired,
    retry: false,
  })

  const me = useQuery({
    queryKey: ['me', bump],
    queryFn: api.me,
    // A 401 here is the normal signed-out state, not a failure worth retrying.
    retry: (count, err) => !(err instanceof ApiError && err.status === 401) && count < 1,
    enabled: setup.data?.setup_required === false,
  })

  const refresh = useCallback(async () => {
    setBump((b) => b + 1)
    await qc.invalidateQueries()
  }, [qc])

  const signOut = useCallback(async () => {
    await api.logout().catch(() => {})
    qc.clear()
    setBump((b) => b + 1)
  }, [qc])

  const value = useMemo<Ctx>(() => {
    const data = (me.data as Me | undefined) ?? null
    const roleOn = (code: string | null) => (code ? data?.projects?.[code] ?? null : null)
    return {
      me: data,
      loading: setup.isLoading || (setup.data?.setup_required === false && me.isLoading),
      setupRequired: setup.data?.setup_required === true,
      roleOn,
      // readonly can look but not touch; user and admin can write.
      canWrite: (code) => {
        const r = roleOn(code)
        return r === 'user' || r === 'admin'
      },
      refresh,
      signOut,
    }
  }, [me.data, me.isLoading, setup.data, setup.isLoading, refresh, signOut])

  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>
}

export function useAuth(): Ctx {
  const c = useContext(AuthCtx)
  if (!c) throw new Error('useAuth outside AuthProvider')
  return c
}
