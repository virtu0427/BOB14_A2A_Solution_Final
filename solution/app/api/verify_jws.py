from flask import request, jsonify

from . import api_bp
from ..core.auth import require_jwt, require_admin
from ..core.logging import append_log
from ..core.validators import validate_card_basic
import os
import requests


# --- 외부 서명 서버 설정 ---
JWS_SERVER_URL = os.environ.get('JWS_SERVER_URL', 'http://127.0.0.1:8001')
JWS_SIGN_URL = f"{JWS_SERVER_URL.rstrip('/')}/sign"
JWS_VERIFY_URL = f"{JWS_SERVER_URL.rstrip('/')}/verify"
DEFAULT_JWS_KID = os.environ.get('JWS_KID', 'registry-hs256-key-1')


def _derive_sub_from_card(card: dict) -> str:
    """입력 card 에서 sub 값을 유추."""
    try:
        org = ''
        if isinstance(card.get('provider'), dict):
            org = str(card['provider'].get('organization') or '').strip()
        name = str(card.get('name') or '').strip()
        ver = str(card.get('version') or '').strip()
        if org and name and ver:
            return f"{org}#agent:{name}.v{ver}"
        if name and ver:
            return f"agent:{name}.v{ver}"
        return name or 'agent:unknown'
    except Exception:
        return 'agent:unknown'


# --- 카드 서명 API ---
@api_bp.post('/jws/sign-card')
def jws_sign_card():
    """관리자 전용 card 서명 위임 API (/sign 프록시)."""
    # 관리자 토큰만 서명 허용
    err = require_jwt() or require_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    card = body.get('card') if isinstance(body.get('card'), dict) else body
    if not isinstance(card, dict):
        append_log('JWS 서명 실패 : card 필드 누락 (422 Unprocessable Entity)', False, status=422)
        return jsonify({"error": 'REQUIRED_FIELDS_MISSING', "errors": ['card is required']}), 422

    ok, errors = validate_card_basic(card)
    if not ok:
        append_log('JWS 서명 실패 : 필수 필드 누락 (422 Unprocessable Entity)', False, status=422)
        return jsonify({"error": 'REQUIRED_FIELDS_MISSING', "errors": errors}), 422

    # jws-server 에 전달할 페이로드 구성
    sign_payload = {
        'sub': body.get('sub') or _derive_sub_from_card(card),
        'version_id': body.get('version_id') or 1,
        'policy_version': body.get('policy_version') or os.environ.get('POLICY_VERSION', 'registry.policy.v3'),
        'iss': body.get('iss') or os.environ.get('JWS_ISS', 'ans-registry.example'),
        'kid': body.get('kid') or DEFAULT_JWS_KID,
        'card': card,
    }

    try:
        r = requests.post(JWS_SIGN_URL, json=sign_payload, timeout=5)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        append_log(f'JWS 서명 실패 : 서버 오류({exc})', False, status=502)
        return jsonify({"error": 'JWS_SIGN_FAILED', "message": str(exc)}), 502

    token = data.get('jws')
    if not isinstance(token, str):
        append_log('JWS 서명 실패 : 응답 토큰 없음', False, status=502)
        return jsonify({"error": 'JWS_SIGN_FAILED', "message": 'missing token'}), 502

    # compact JWS 를 AgentCard signatures 형식으로 변환
    try:
        parts = token.split('.')
        protected_b64, _payload_b64, signature_b64 = parts[0], parts[1], parts[2]
    except Exception:
        append_log('JWS 서명 실패 : 토큰 형식 오류', False, status=502)
        return jsonify({"error": 'JWS_SIGN_FAILED', "message": 'invalid token format'}), 502

    kid = sign_payload['kid']
    sig_entry = {
        'protected': protected_b64,
        'signature': signature_b64,
        'header': {'kid': kid},
    }

    signatures = card.get('signatures') if isinstance(card.get('signatures'), list) else []
    signatures.append(sig_entry)
    card['signatures'] = signatures

    append_log('JWS 서명 성공 : 시그니처 추가', True)
    return jsonify({'card': card, 'jws': token, 'payload': data.get('payload') or {}}), 200


# --- JWS 검증 API ---
@api_bp.post('/jws/verify')
def jws_verify():
    """jws-server /verify 프록시 (일관된 로그 메시지)."""
    err = require_jwt() or require_admin()
    if err:
        return err
    body = request.get_json(silent=True) or {}
    token = body.get('jws')
    if not isinstance(token, str) or not token:
        return jsonify({"error": 'BAD_REQUEST', "message": 'jws is required'}), 400
    payload = {'jws': token}
    # 카드 전체 또는 해시를 전달하면 서버 측에서 해시 검증 가능
    if isinstance(body.get('card'), dict):
        payload['card'] = body['card']
    elif isinstance(body.get('card_hash'), str):
        payload['card_hash'] = body['card_hash']

    try:
        r = requests.post(JWS_VERIFY_URL, json=payload, timeout=5)
        status = r.status_code
        data = r.json() if r.content else {}
    except Exception as exc:
        append_log(f'JWS 검증 실패 : 서버 오류({exc})', False, status=502)
        return jsonify({"error": 'JWS_VERIFY_FAILED', "message": str(exc)}), 502

    # 표준화된 로그 메시지
    if status == 200:
        if isinstance(data, dict) and data.get('hash_verified') is True:
            append_log('JWS 검증 성공 : 카드 해시 일치', True)
        else:
            append_log('JWS 검증 성공', True)
        return jsonify(data), 200

    # 실패 케이스 (jws-server 가 400에서 detail 형태를 다르게 반환함)
    detail = None
    try:
        detail = data.get('detail') if isinstance(data, dict) else None
    except Exception:
        detail = None

    if status == 400:
        # 카드 해시 불일치
        if isinstance(detail, dict) and detail.get('code') == 'CARD_HASH_MISMATCH':
            append_log('JWS 검증 실패 : 카드 해시 불일치 (400 Bad Request)', False, status=400)
        else:
            # 일반적인 토큰 오류
            append_log('JWS 검증 실패 : 토큰 무효 (400 Bad Request)', False, status=400)
        return jsonify(data), 400

    append_log(f'JWS 검증 실패 : 서버 오류 ({status})', False, status=status)
    return jsonify({"error": 'JWS_VERIFY_FAILED', "status": status, "detail": detail}), 502


# --- 카드 재서명 API ---
@api_bp.post('/jws/resign-card')
def jws_resign_card():
    """기존 signatures 를 제거하고 재서명하여 단일 시그니처로 교체.

    - 관리자 전용 엔드포인트
    - 카드 스키마 검증 이후 jws-server /sign 호출
    - 반환된 JWS 를 signatures[0] 으로 덮어씀
    """
    err = require_jwt() or require_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    card = body.get('card') if isinstance(body.get('card'), dict) else body
    if not isinstance(card, dict):
        append_log('JWS 재서명 실패 : card 필드 누락 (422 Unprocessable Entity)', False, status=422)
        return jsonify({"error": 'REQUIRED_FIELDS_MISSING', "errors": ['card is required']}), 422

    ok, errors = validate_card_basic(card)
    if not ok:
        append_log('JWS 재서명 실패 : 필수 필드 누락 (422 Unprocessable Entity)', False, status=422)
        return jsonify({"error": 'REQUIRED_FIELDS_MISSING', "errors": errors}), 422

    # 기존 서명 제거한 사본으로 해시가 계산되도록, 원본 card는 그대로 전달(서버에서 signatures 무시하고 해시 계산)
    sign_payload = {
        'sub': body.get('sub') or _derive_sub_from_card(card),
        'version_id': body.get('version_id') or 1,
        'policy_version': body.get('policy_version') or os.environ.get('POLICY_VERSION', 'registry.policy.v3'),
        'iss': body.get('iss') or os.environ.get('JWS_ISS', 'ans-registry.example'),
        'kid': body.get('kid') or DEFAULT_JWS_KID,
        'card': card,
    }

    try:
        r = requests.post(JWS_SIGN_URL, json=sign_payload, timeout=5)
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        append_log(f'JWS 재서명 실패 : 서버 오류({exc})', False, status=502)
        return jsonify({"error": 'JWS_SIGN_FAILED', "message": str(exc)}), 502

    token = data.get('jws')
    if not isinstance(token, str):
        append_log('JWS 재서명 실패 : 응답 토큰 없음', False, status=502)
        return jsonify({"error": 'JWS_SIGN_FAILED', "message": 'missing token'}), 502

    # compact JWS 를 AgentCard signatures[0] 형태로 변환
    try:
        protected_b64, _payload_b64, signature_b64 = token.split('.')
    except Exception:
        append_log('JWS 재서명 실패 : 토큰 형식 오류', False, status=502)
        return jsonify({"error": 'JWS_SIGN_FAILED', "message": 'invalid token format'}), 502

    kid = sign_payload['kid']
    sig_entry = {
        'protected': protected_b64,
        'signature': signature_b64,
        'header': {'kid': kid},
    }

    card['signatures'] = [sig_entry]

    append_log('JWS 재서명 성공 : 시그니처 교체', True)
    return jsonify({'card': card, 'jws': token, 'payload': data.get('payload') or {}}), 200
