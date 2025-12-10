from flask import jsonify, g

from . import api_bp
from ..core.auth import require_jwt, require_admin


# --- JWT 검증/권한 확인 ---
@api_bp.get('/auth/me')
def auth_me():
    """JWT 검증 후 현재 사용자 정보를 반환."""
    err = require_jwt()
    if err:
        return err
    sub = getattr(g, 'jwt', {}).get('sub')
    return jsonify({"email": sub})


# --- JWT 단순 검증 ---
@api_bp.get('/verify-jwt')
def verify_jwt():
    """간단한 토큰 검증용 엔드포인트 (성공 시 email 반환)."""
    err = require_jwt()
    if err:
        return err
    sub = getattr(g, 'jwt', {}).get('sub')
    return jsonify({"ok": True, "email": sub})


# --- 관리자 권한 검증 ---
@api_bp.get('/verify-admin')
def verify_admin():
    """토큰 검증 후 관리자 권한 여부 확인."""
    err = require_jwt()
    if err:
        return err
    err2 = require_admin()
    if err2:
        return err2
    sub = getattr(g, 'jwt', {}).get('sub')
    return jsonify({"ok": True, "email": sub, "role": "admin"})
