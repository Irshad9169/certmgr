// ── Axios client with JWT refresh, API-key support and error normalization ──

import axios, { AxiosError } from 'axios'
import { redirectToLogin, tokenStore } from './session'

export { tokenStore } from './session'

export const api = axios.create({
  baseURL: '/api/v1',
  timeout: 60000,
  headers: { 'Content-Type': 'application/json' },
})

// ── CSRF double-submit token ───────────────────────────────────────────────
// The backend sets a HttpOnly `certmgr_csrf` cookie via GET /auth/csrf; we
// keep the matching token in memory/localStorage and send it as X-CSRF-Token
// on state-changing requests. Login is CSRF-protected in production, so the
// UI MUST obtain a token BEFORE logging in.
let csrfToken: string | null = (() => {
  try {
    return window.localStorage.getItem('certmgr_csrf')
  } catch {
    return null
  }
})()

export async function ensureCsrf(): Promise<string | null> {
  if (csrfToken) return csrfToken
  try {
    const { data } = await axios.get<{ csrf_token: string }>('/api/v1/auth/csrf')
    setCsrfToken(data.csrf_token)
    return csrfToken
  } catch {
    return null
  }
}

// Adopt a token returned by the backend (e.g. from the login response) so the
// client never holds a stale token after the server (re)issues the cookie.
export function setCsrfToken(token: string): void {
  csrfToken = token
  try {
    window.localStorage.setItem('certmgr_csrf', token)
  } catch {
    /* storage blocked — keep in memory */
  }
}

api.interceptors.request.use((config) => {
  const token = tokenStore.access
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
    // Some preview/reverse proxies strip `Authorization`; the backend also
    // accepts the JWT via this custom header.
    config.headers['X-CertMgr-Token'] = token
  }
  const method = (config.method ?? 'get').toUpperCase()
  if (method !== 'GET' && !config.url?.includes('/auth/csrf')) {
    const csrf = csrfToken ?? (() => {
      try {
        return window.localStorage.getItem('certmgr_csrf')
      } catch {
        return null
      }
    })()
    if (csrf) config.headers['X-CSRF-Token'] = csrf
  }
  return config
})

let refreshing: Promise<string | null> | null = null

async function tryRefresh(): Promise<string | null> {
  const refresh = tokenStore.refresh
  if (!refresh) return null
  try {
    // Use the api instance so the CSRF header (and any auth header) is attached.
    const { data } = await api.post('/auth/refresh', { refresh_token: refresh })
    tokenStore.set(data.access_token, refresh)
    return data.access_token
  } catch {
    tokenStore.clear()
    return null
  }
}

api.interceptors.response.use(
  (res) => res,
  async (error: AxiosError) => {
    const original = error.config as (typeof error.config & { _retry?: boolean })
    if (error.response?.status === 401 && original && !original._retry) {
      original._retry = true
      if (!tokenStore.refresh) {
        tokenStore.clear()
        redirectToLogin()
        return Promise.reject(error)
      }
      // Deduplicate concurrent refreshes; never use a stale resolved promise twice.
      const current = refreshing ?? tryRefresh()
      refreshing = current
      const token = await current
      if (refreshing === current) refreshing = null

      if (token) {
        const headers = { ...(original.headers as Record<string, string> | undefined) }
        headers.Authorization = `Bearer ${token}`
        headers['X-CertMgr-Token'] = token
        try {
          return await api.request({ ...original, headers })
        } catch (retryErr) {
          // Even the fresh token failed — session is unrecoverable; force clean
          // re-login instead of leaving the UI stuck on error boxes.
          tokenStore.clear()
          redirectToLogin()
          return Promise.reject(retryErr)
        }
      }
      tokenStore.clear()
      redirectToLogin()
    }
    return Promise.reject(error)
  },
)

export function apiErrorMessage(err: unknown): string {
  const e = err as AxiosError<{ error?: { message?: string; details?: unknown } }>
  const message = e.response?.data?.error?.message
  if (message) return message
  if (e.code === 'ECONNABORTED') return 'Request timed out'
  if (!e.response) return 'Network error — is the API reachable?'
  return `HTTP ${e.response.status}`
}

export function downloadBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

export async function downloadFile(path: string, params: Record<string, unknown>, filename: string) {
  const res = await api.get(path, { params, responseType: 'blob' })
  downloadBlob(res.data, filename)
}
