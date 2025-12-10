const REDIRECT_TARGET = '/dashboard'

const showLoginStatus = (message, isError = false) => {
  const statusEl = document.getElementById('login-status')
  if (!statusEl) return
  statusEl.textContent = message
  statusEl.classList.toggle('status-error', isError)
  statusEl.classList.toggle('status-success', !isError)
}

const ADMIN_VERIFY_PATH = '/api/verify-admin'

const verifyAdminToken = async (token) => {
  const response = await fetch(ADMIN_VERIFY_PATH, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: 'application/json',
    },
  })
  if (response.ok) {
    return response.json().catch(() => ({}))
  }
  const payload = await response.json().catch(() => null)
  const message =
    payload?.message || payload?.detail || '관리자 권한을 확인할 수 없습니다.'
  throw new Error(message)
}

const handleFormSubmit = async (event) => {
  event.preventDefault()
  if (!window.atsAuth) {
    showLoginStatus('인증 모듈을 준비하는 중입니다.', true)
    return
  }

  const form = event.target
  const formData = new FormData(form)
  const email = (formData.get('email') || '').trim()
  const password = (formData.get('password') || '').toString()

  if (!email || !password) {
    showLoginStatus('이메일과 비밀번호를 모두 입력해주세요.', true)
    return
  }

  showLoginStatus('로그인 중...')

  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ email, password }),
    })

    if (!response.ok) {
      const payload = await response.json().catch(() => null)
      const message = payload?.message || '로그인에 실패했습니다. 자격 증명을 확인하세요.'
      showLoginStatus(message, true)
      return
    }

    const data = await response.json()
    const token = data?.access_token
    if (!token) {
      showLoginStatus('서버에서 JWT를 반환하지 않았습니다.', true)
      return
    }

    showLoginStatus('관리자 권한을 확인 중입니다...')
    await verifyAdminToken(token)

    window.atsAuth.setToken(token)
    showLoginStatus('로그인 성공! 곧 이동합니다.')
    setTimeout(() => {
      window.location.href = REDIRECT_TARGET
    }, 800)
  } catch (error) {
    console.error('Auth login failed', error)
    const friendlyMessage =
      error?.message || '인증 서버 요청 중 오류가 발생했습니다. 자격 증명을 확인해 주세요.'
    showLoginStatus(friendlyMessage, true)
  }
}

document.addEventListener('DOMContentLoaded', () => {
  const loginForm = document.getElementById('login-form')
  if (loginForm) {
    loginForm.addEventListener('submit', handleFormSubmit)
  }
})
