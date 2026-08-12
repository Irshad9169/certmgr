// ── Auth provider: login, MFA, profile + permissions ───────────────────────

import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { api, apiErrorMessage, ensureCsrf, setCsrfToken } from './api'
import { tokenStore } from './session'
import type { User } from '../types'
import { AuthContext } from './auth-context'
import type { AuthState } from './auth-context'

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  const refreshProfile = useCallback(async () => {
    try {
      const { data } = await api.get<User>('/auth/me')
      setUser(data)
    } catch {
      setUser(null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    void refreshProfile()
  }, [refreshProfile])

  const login = useCallback(async (username: string, password: string, mfaCode?: string) => {
    try {
      // CSRF is enforced on login in production — ensure the token exists first.
      await ensureCsrf()
      const { data } = await api.post<{
        access_token: string
        refresh_token: string
        user: User
        csrf_token?: string
      }>('/auth/login', { username, password, mfa_code: mfaCode })
      tokenStore.set(data.access_token, data.refresh_token)
      // Keep the client's CSRF token in sync with the server's cookie.
      if (data.csrf_token) setCsrfToken(data.csrf_token)
      setUser(data.user)
      setLoading(false)
    } catch (err) {
      throw new Error(apiErrorMessage(err))
    }
  }, [])

  const logout = useCallback(async () => {
    const refresh = tokenStore.refresh
    try {
      if (refresh) await api.post('/auth/logout', { refresh_token: refresh })
    } catch {
      /* ignore */
    }
    tokenStore.clear()
    setUser(null)
  }, [])

  // Local-only reset (no API call) — used when a session is unrecoverable so
  // we never risk a logout→401→redirect loop.
  const resetSession = useCallback(() => {
    tokenStore.clear()
    setUser(null)
  }, [])

  const can = useCallback(
    (permission: string) => user?.permissions?.includes(permission) ?? false,
    [user],
  )

  const value = useMemo<AuthState>(
    () => ({ user, loading, login, logout, resetSession, can, refreshProfile }),
    [user, loading, login, logout, resetSession, can, refreshProfile],
  )

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}
