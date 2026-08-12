// ── Auth context + hook (separate module so HMR can hot-swap the provider
//    file without forcing a full page reload, which would drop the session) ──

import { createContext, useContext } from 'react'
import type { User } from '../types'

export interface AuthState {
  user: User | null
  loading: boolean
  login: (username: string, password: string, mfaCode?: string) => Promise<void>
  logout: () => Promise<void>
  resetSession: () => void
  can: (permission: string) => boolean
  refreshProfile: () => Promise<void>
}

export const AuthContext = createContext<AuthState | null>(null)

export function useAuth(): AuthState {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
