;(function () {
  if (window.__atsAuthHelperInstalled) {
    return
  }
  window.__atsAuthHelperInstalled = true

  const STORAGE_KEY = 'atsAuthToken'

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

  window.fetch = (input, init = {}) => {
    const token = getToken()
    let headers = new Headers(init.headers || {})

    if (token && !headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`)
    }

    const newInit = { ...init, headers }
    return originalFetch(input, newInit)
  }

  window.atsAuth = {
    getToken,
    setToken,
    clearToken,
    STORAGE_KEY,
  }

  const LOGIN_PATHS = new Set(['/login', '/login.html'])
  const normalizePath = (value) => {
    if (!value) return '/'
    const trimmed = value.replace(/\/+$/, '') || '/'
    return trimmed
  }

  const requiresAuth = () => {
    const path = normalizePath(window.location.pathname)
    if (LOGIN_PATHS.has(path)) return false
    return !path.startsWith('/static') // allow static assets when next to HTML? (unlikely to load script there)
  }

  const enforceAuth = () => {
    if (requiresAuth() && !getToken()) {
      window.location.replace('/login')
    }
  }

  enforceAuth()

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
