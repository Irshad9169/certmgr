// ── Resilient session store ────────────────────────────────────────────────
// The app may run inside a sandboxed preview iframe where localStorage throws
// (opaque origin without allow-same-origin) AND the iframe gets reloaded
// periodically by the host. Three persistence layers, in order:
//
//   1. memory      – survives SPA navigation / HMR hot-swaps (fastest)
//   2. localStorage – survives full reloads in a normal browser tab
//   3. window.name – survives full reloads of the SAME iframe even when
//                    localStorage is blocked (opaque-origin sandbox).
//                    Cleared on logout; only our app runs in this window.
//
// SECURITY NOTE: window.name is readable by any script executing in this
// window/browsing-context (e.g. if the host later navigates the same iframe
// to another app). Acceptable for evaluation/demo; production deployments
// run in a normal tab where localStorage is used and window.name is not
// consulted. A timestamp + expiry keeps stale entries from being honored.

const ACCESS_KEY = 'certmgr_access'
const REFRESH_KEY = 'certmgr_refresh'
const WN_PREFIX = 'certmgr_session_v1::'
const WN_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000 // ignore entries older than 7 days

const memory: { access: string | null; refresh: string | null } = {
  access: null,
  refresh: null,
}

// ── localStorage layer (best-effort) ───────────────────────────────────────
function readStorage(key: string): string | null {
  try {
    return window.localStorage.getItem(key)
  } catch {
    return null // storage blocked (sandboxed iframe)
  }
}

function writeStorage(key: string, value: string): void {
  try {
    window.localStorage.setItem(key, value)
  } catch {
    /* storage unavailable — other layers keep the session alive */
  }
}

function removeStorage(key: string): void {
  try {
    window.localStorage.removeItem(key)
  } catch {
    /* ignore */
  }
}

// ── window.name layer (survives iframe reloads with blocked storage) ───────
interface WnPayload {
  access: string
  refresh: string
  ts: number
}

function readWindowName(): WnPayload | null {
  try {
    const raw = window.name
    if (!raw || !raw.startsWith(WN_PREFIX)) return null
    const data = JSON.parse(raw.slice(WN_PREFIX.length)) as WnPayload
    if (typeof data.access === 'string' && typeof data.refresh === 'string') {
      if (Date.now() - (data.ts || 0) > WN_MAX_AGE_MS) return null
      return data
    }
  } catch {
    /* ignore malformed */
  }
  return null
}

function writeWindowName(access: string, refresh: string): void {
  try {
    window.name = WN_PREFIX + JSON.stringify({ access, refresh, ts: Date.now() } satisfies WnPayload)
  } catch {
    /* ignore */
  }
}

function clearWindowName(): void {
  try {
    if (window.name.startsWith(WN_PREFIX)) window.name = ''
  } catch {
    /* ignore */
  }
}

export const tokenStore = {
  get access(): string | null {
    if (memory.access) return memory.access
    const ls = readStorage(ACCESS_KEY)
    if (ls) return ls
    return readWindowName()?.access ?? null
  },
  get refresh(): string | null {
    if (memory.refresh) return memory.refresh
    const ls = readStorage(REFRESH_KEY)
    if (ls) return ls
    return readWindowName()?.refresh ?? null
  },
  set(access: string, refresh: string): void {
    memory.access = access
    memory.refresh = refresh
    writeStorage(ACCESS_KEY, access)
    writeStorage(REFRESH_KEY, refresh)
    writeWindowName(access, refresh)
  },
  clear(): void {
    memory.access = null
    memory.refresh = null
    removeStorage(ACCESS_KEY)
    removeStorage(REFRESH_KEY)
    clearWindowName()
  },
}

// ── Session-expiry redirect (in-app, no full page reload) ──────────────────
// Full page reloads are dangerous in sandboxed iframes (they can wipe any
// storage) and are slow — so auth failures navigate via React Router instead.
// The app registers its navigate() implementation at mount.
type RedirectFn = () => void
let redirectFn: RedirectFn = () => {
  window.location.assign('/login')
}

export function registerLoginRedirect(fn: RedirectFn): void {
  redirectFn = fn
}

export function redirectToLogin(): void {
  redirectFn()
}
