"""
JWT 인증/권한 유틸리티.

1. Authorization 헤더에서 Bearer 토큰 파싱
2. USERME API 호출로 사용자 정보(email) 확인
3. 일관된 에러 응답(JSON) 헬퍼 제공
4. ADMIN_EMAIL 기반 관리자 권한 검사
"""

import os
import requests
from flask import request, jsonify, g

from .tenants import normalize_tenants


# --- 관리자 이메일 기준값 ---
ADMIN_EMAIL = os.environ.get('ADMIN_EMAIL', 'admin@example.com')

def _norm_email(v: str | None) -> str:
    return v.strip().lower() if isinstance(v, str) else ""

_ADMIN_EMAIL_NORM = _norm_email(ADMIN_EMAIL)


def _userme_url() -> str:
    """USERME 서비스(me) 엔드포인트 URL을 반환."""
    return os.environ.get('USERME_DIRECT_URL', 'http://127.0.0.1:8000/users/me')


def send_error(status: int, code: str, message: str):
    """일관된 에러 응답 포맷(JSON)으로 반환."""
    return jsonify({"error": code, "message": message}), status


def get_user_me(user_token: str):
    """USERME API를 호출해 토큰의 사용자 정보를 조회.

    반환값은 {"status": HTTP 상태코드|0, "json": dict} 형태.
    네트워크 오류 등 예외 시 status=0, 빈 JSON을 반환.
    """
    try:
        r = requests.get(
            _userme_url(),
            headers={"Authorization": f"Bearer {user_token}", "Accept": "application/json"},
            timeout=5,
        )
        try:
            data = r.json()
        except Exception:
            data = {}
        return {"status": r.status_code, "json": data}
    except requests.RequestException:
        return {"status": 0, "json": {}}


def require_jwt():
    """JWT가 필요한 엔드포인트에서 사용.

    - Authorization: Bearer <token> 형식 검증
    - USERME 연동으로 토큰 유효성 확인 및 email 추출
    - 성공 시 g.jwt = {"sub": email} 설정, 실패 시 에러 응답 반환
    """
    auth = request.headers.get("Authorization", "")
    if not auth:
        try:
            from .logging import append_log  # lazy to avoid circular import
            append_log('인증 실패: Authorization 헤더 누락 (401 Unauthorized)', False, status=401)
        except Exception:
            pass
        return send_error(401, "TOKEN_MISSING", "Missing Authorization header")
    parts = auth.split(" ")
    if len(parts) != 2 or parts[0] != "Bearer" or not parts[1]:
        try:
            from .logging import append_log
            append_log('인증 실패: Authorization 형식 오류 (401 Unauthorized)', False, status=401)
        except Exception:
            pass
        return send_error(401, "INVALID_AUTH_FORMAT", "Expected: Authorization: Bearer <token>")
    result = get_user_me(parts[1])
    status, data = result.get("status"), result.get("json") or {}
    if status == 200 and isinstance(data.get("email"), str):
        tenants = normalize_tenants(data.get("tenants"))
        # 일부 토큰은 단일 tenant 필드를 사용하므로 보강
        if not tenants and isinstance(data.get("tenant"), str):
            tenants = normalize_tenants([data["tenant"]])
        g.jwt = {"sub": data["email"], "tenants": tenants}
        if _norm_email(data["email"]) == _ADMIN_EMAIL_NORM:
            g.jwt["role"] = "admin"
        return None
    if status == 401 and data.get("detail") == "Invalid token":
        try:
            from .logging import append_log
            append_log('신원 검증 실패 : 토큰 무효 (401 Unauthorized)', False, status=401)
        except Exception:
            pass
        return send_error(401, "INVALID_TOKEN", "Invalid or malformed token")
    try:
        from .logging import append_log
        append_log(f'인증 실패: 토큰 서비스 오류 ({status})', False, status=status or 502)
    except Exception:
        pass
    return send_error(502, "TOKEN_SERVICE_ERROR", "Token service unavailable")


def require_admin():
    """관리자 권한이 필요한 엔드포인트에서 사용.

    - g.jwt.sub 가 존재하고 ADMIN_EMAIL 과 일치해야 함
    - 성공 시 g.jwt["role"] = "admin" 설정
    """
    email = getattr(g, "jwt", {}).get("sub")
    if not email:
        try:
            from .logging import append_log
            append_log('권한 거부: 토큰 정보 없음 (401 Unauthorized)', False, status=401)
        except Exception:
            pass
        return send_error(401, "INVALID_TOKEN", "Invalid or malformed token")
    # 이메일은 대소문자/공백 차이를 무시하고 비교
    if _norm_email(email) != _ADMIN_EMAIL_NORM:
        try:
            from .logging import append_log
            append_log('신원 검증 실패 : 관리자 권한 아님 (403 Forbidden)', False, status=403)
        except Exception:
            pass
        return send_error(403, "FORBIDDEN", "Admin privileges required")
    g.jwt["role"] = "admin"
    return None
