;(function () {
  if (window.__atsAuthHelperInstalled) {
    return
  }
  window.__atsAuthHelperInstalled = true

  const STORAGE_KEY = 'atsAuthToken'
  const TOKEN_EXP_UPDATE_MS = 1000

  const safeStorage = {
    get(key) {
      try {
        return localStorage.getItem(key)
      } catch {
        return null
      }
    },
    set(key, value) {
      try {
        localStorage.setItem(key, value)
        return true
      } catch {
        return false
      }
    },
    remove(key) {
      try {
        localStorage.removeItem(key)
        return true
      } catch {
        return false
      }
    },
  }

  const emitTokenChange = (token) => {
    window.dispatchEvent(
      new CustomEvent('ats-token-changed', {
        detail: { token },
      })
    )
  }

  const getToken = () => safeStorage.get(STORAGE_KEY) || ''
  const decodeJwtPayload = (token) => {
    if (!token || typeof token !== 'string') return null
    const parts = token.split('.')
    if (parts.length < 2) return null
    try {
      // base64url 디코드
      const padded = parts[1].replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(parts[1].length / 4) * 4, '=')
      const json = atob(padded)
      return JSON.parse(json)
    } catch {
      return null
    }
  }

  const isTokenExpired = (token) => {
    const payload = decodeJwtPayload(token)
    if (!payload || typeof payload.exp !== 'number') return false
    const nowSec = Math.floor(Date.now() / 1000)
    return nowSec >= payload.exp
  }

  const setToken = (token) => {
    if (typeof token !== 'string' || token.trim() === '') {
      safeStorage.remove(STORAGE_KEY)
      emitTokenChange('')
      return
    }
    safeStorage.set(STORAGE_KEY, token.trim())
    emitTokenChange(token.trim())
  }

  const clearToken = () => {
    safeStorage.remove(STORAGE_KEY)
    emitTokenChange('')
  }

  const originalFetch = window.fetch.bind(window)
  let authErrorNotified = false

  const isAuthFailureStatus = (status) => [401, 403, 498].includes(Number(status))

  const shouldHandleAuthError = (input) => {
    try {
      const url = typeof input === 'string' ? new URL(input, window.location.href) : input.url ? new URL(input.url) : null
      if (!url) return true
      // 로그인 페이지/자원에 대한 호출은 건너뜀
      return !url.pathname.includes('/login')
    } catch {
      return true
    }
  }

  window.fetch = (input, init = {}) => {
    const token = getToken()
    let headers = new Headers(init.headers || {})

    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`)
    }

    const newInit = { ...init, headers }
    return originalFetch(input, newInit).then((resp) => {
      if (!authErrorNotified && isAuthFailureStatus(resp.status) && shouldHandleAuthError(input)) {
        authErrorNotified = true
        // 만료/무효 토큰은 즉시 무효화하고 로그인 페이지로 이동
        clearToken()
        // 약간 늦게 리디렉션하여 UI 메시지가 보일 시간 확보
        setTimeout(() => window.location.replace('/login'), 50)
      }
      return resp
    })
  }

  window.atsAuth = {
    getToken,
    setToken,
    clearToken,
    STORAGE_KEY,
    decodeJwtPayload,
    isTokenExpired,
  }

  const LOGIN_PATHS = new Set(['/login', '/login.html', '/static/login.html'])
  const STATIC_ASSET_EXTS = new Set([
    '.js',
    '.css',
    '.png',
    '.jpg',
    '.jpeg',
    '.gif',
    '.svg',
    '.ico',
    '.map',
    '.json',
    '.txt',
    '.woff',
    '.woff2',
    '.ttf',
  ])

  const normalizePath = (value) => {
    if (!value) return '/'
    const trimmed = value.replace(/\/+$/, '') || '/'
    return trimmed
  }

  const isStaticAssetPath = (path) => {
    const lower = path.toLowerCase()
    for (const ext of STATIC_ASSET_EXTS) {
      if (lower.endsWith(ext)) return true
    }
    return false
  }

  const requiresAuth = () => {
    const path = normalizePath(window.location.pathname)
    if (LOGIN_PATHS.has(path)) return false
    // 정적 자산(js/css/img)은 허용하되, static 경로라도 HTML은 인증 요구
    if (isStaticAssetPath(path)) return false
    return true
  }

  const enforceAuth = () => {
    const token = getToken()
    if (!requiresAuth()) return
    if (!token || isTokenExpired(token)) {
      clearToken()
      window.location.replace('/login')
    }
  }

  enforceAuth()
  // exp 뱃지 주기적 업데이트
  const formatRemaining = (seconds) => {
    const safe = Math.max(0, Math.floor(seconds))
    const hours = Math.floor(safe / 3600)
    const minutes = Math.floor((safe % 3600) / 60)
    const secs = safe % 60
    if (hours > 0) {
      return `${String(hours).padStart(2, '0')}:${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
    }
    return `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`
  }

  const updateTokenExpBadges = () => {
    const token = getToken()
    const payload = decodeJwtPayload(token)
    const exp = payload && typeof payload.exp === 'number' ? payload.exp : null
    const nowSec = Math.floor(Date.now() / 1000)
    let label = ''
    let warn = false
    if (exp) {
      const remaining = exp - nowSec
      if (remaining <= 0) {
        label = '자동 로그아웃됨'
        warn = true
      } else {
        label = `자동 로그아웃 ${formatRemaining(remaining)}`
        warn = remaining <= 60
      }
    }
    document.querySelectorAll('[data-token-exp]').forEach((el) => {
      el.textContent = label
      el.classList.toggle('warn', warn)
    })
  }
  updateTokenExpBadges()
  setInterval(updateTokenExpBadges, TOKEN_EXP_UPDATE_MS)
  window.addEventListener('ats-token-changed', updateTokenExpBadges)

  window.addEventListener('storage', (event) => {
    if (event.key === STORAGE_KEY && event.storageArea === localStorage) {
      if (!event.newValue) {
        enforceAuth()
      }
    }
  })

  const performLogout = () => {
    if (window.atsAuth) {
      window.atsAuth.clearToken()
    }
    window.location.replace('/login')
  }

  const bindLogoutLinks = () => {
    document.querySelectorAll('[data-logout]').forEach((link) => {
      if (link.dataset.logoutBound) return
      link.dataset.logoutBound = '1'
      link.addEventListener('click', (event) => {
        event.preventDefault()
        performLogout()
      })
    })
  }

  document.addEventListener('DOMContentLoaded', bindLogoutLinks)
})()
