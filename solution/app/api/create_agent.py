import os
import json
import secrets
from datetime import datetime, timezone, timedelta
from flask import request, jsonify

from . import api_bp
from ..core.auth import require_jwt, require_admin
from ..core.logging import append_log
from ..core import repo
from ..core.validators import (
    validate_card_basic,
    DEFAULT_MAX_AGENT_CARD_BYTES,
)
from ..core.signatures import verify_jws, validate_signatures_jws_like
from ..core.policy import check_duplicate_card, PolicyEvaluator
from ..core.tenants import extract_tenants
import requests

# --- 외부 서명 서버 설정 (선택적 자동 서명) ---
JWS_SERVER_URL = os.environ.get('JWS_SERVER_URL', 'http://127.0.0.1:8001')
JWS_SIGN_URL = f"{JWS_SERVER_URL.rstrip('/')}/sign"
DEFAULT_JWS_KID = os.environ.get('JWS_KID', 'registry-hs256-key-1')


# --- 에이전트 등록 ---
@api_bp.post('/create-agent')
def create_agent():
    """에이전트 등록 엔드포인트 (JWT + 관리자 권한 필요)."""
    # --- 인증 및 권한 확인 ---
    err = require_jwt()
    if err:
        status = err[1] if isinstance(err, tuple) and len(err) > 1 else 500
        if status == 401:
            append_log('에이전트 추가 거부: 토큰 누락/유효하지 않음 (401 Unauthorized)', False)
        else:
            append_log(f'에이전트 추가 거부: 토큰 서비스 오류 ({status})', False)
        return err
    err2 = require_admin()
    if err2:
        append_log('에이전트 추가 거부: 관리자 권한 아님 (403 Forbidden)', False)
        return err2

    # --- 본문 크기 및 JSON 문법 검증 ---
    raw = request.get_data(as_text=True) or ''
    try:
        byte_len = len(raw.encode('utf-8'))
        if byte_len > DEFAULT_MAX_AGENT_CARD_BYTES:
            # 표준화된 로그 메시지 (요청 포맷)
            append_log('스키마 검증 실패 : 에이전트 최대 바이트 넘김 (413 Payload Too Larg)', False)
            return jsonify({"error": 'PAYLOAD_TOO_LARGE', "message": f"payload exceeds {DEFAULT_MAX_AGENT_CARD_BYTES} bytes"}), 413
    except Exception:
        pass
    try:
        body = json.loads(raw)
    except Exception:
        append_log('스키마 검증 실패 : 잘못된 JSON 문법 (400 Bad Request)', False)
        return jsonify({"error": 'BAD_JSON', "message": 'Invalid JSON'}), 400

    # --- card 객체 추출 ---
    card = None
    if isinstance(body, dict):
        if isinstance(body.get('card'), dict):
            card = body.get('card')
        else:
            card = body
    # 카드 객체가 없을 때는 명시적으로 에러 반환
    if not isinstance(card, dict):
        append_log('스키마 검증 실패 :   card 필드 누락', False)
        return jsonify({"error": 'REQUIRED_FIELDS_MISSING', "errors": ['card is required']}), 422

    # --- Tenant 필수 여부 확인 ---
    tenants = []
    if isinstance(body, dict):
        tenants = extract_tenants(body.get('tenants'))

    if not tenants:
        append_log('스키마 검증 실패 : tenant 선택 누락 (422 Unprocessable Entity)', False)
        return jsonify({"error": 'TENANT_REQUIRED', "message": 'at least one tenant must be specified'}), 422

    # --- 퍼블리셔 서명 보존 ---
    original_sigs = card.get('signatures') if isinstance(card.get('signatures'), list) else []
    if original_sigs:
        sig_ok, sig_reason = verify_jws(card)
        if not sig_ok:
            try:
                append_log('스키마 검증 실패 : 시그니처 필드의 JWS 불일치 (498 Invalid Token)', False)
            except Exception:
                pass
            return jsonify({"error": 'INVALID_TOKEN', "message": sig_reason or 'Invalid JWS signature'}), 498

    # Basic field-level validation (schema-lite)
    ok, errors = validate_card_basic(card)
    if not ok:
        try:
            append_log('스키마 검증 실패 : 필수 필드 누락 (422 Unprocessable Entity)', False)
        except Exception:
            pass
        return jsonify({"error": 'REQUIRED_FIELDS_MISSING', "errors": errors}), 422

    if not original_sigs:
        try:
            def _derive_sub_from_card(c: dict) -> str:
                try:
                    org = ''
                    if isinstance(c.get('provider'), dict):
                        org = str(c['provider'].get('organization') or '').strip()
                    name_v = str(c.get('name') or '').strip()
                    ver_v = str(c.get('version') or '').strip()
                    if org and name_v and ver_v:
                        return f"{org}#agent:{name_v}.v{ver_v}"
                    if name_v and ver_v:
                        return f"agent:{name_v}.v{ver_v}"
                    return name_v or 'agent:unknown'
                except Exception:
                    return 'agent:unknown'

            sign_payload = {
                'sub': _derive_sub_from_card(card),
                'version_id': 1,
                'policy_version': os.environ.get('POLICY_VERSION', 'registry.policy.v3'),
                'iss': os.environ.get('JWS_ISS', 'ans-registry.example'),
                'kid': DEFAULT_JWS_KID,
                'card': card,
            }
            try:
                r = requests.post(JWS_SIGN_URL, json=sign_payload, timeout=5)
                if r.ok:
                    data = r.json()
                    token = data.get('jws')
                    parts = token.split('.') if isinstance(token, str) else []
                    if len(parts) == 3:
                        protected_b64, _payload_b64, signature_b64 = parts
                        sig_entry = {
                            'protected': protected_b64,
                            'signature': signature_b64,
                            'header': {'kid': DEFAULT_JWS_KID},
                        }
                        # 카드에 있던 퍼블리셔 서명은 레지스트리 서명으로 교체
                        card['signatures'] = [sig_entry]
            except Exception:
                # 자동 서명 실패 시에도 본 검증 흐름을 진행
                pass
        except Exception:
            pass

    # --- 기본 스키마 검증 ---
    ok, errors = validate_card_basic(card)
    if not ok:
        try:
            # 표준화된 422 로그 메시지
            append_log('스키마 검증 실패 : 필수 필드 누락 (422 Unprocessable Entity)', False)
        except Exception:
            pass
        return jsonify({"error": 'REQUIRED_FIELDS_MISSING', "errors": errors}), 422

    # --- JWS 구조 검증 (암호 검증 제외) ---
    sig_ok, sig_reason = verify_jws(card)
    if not sig_ok:
        try:
            # 표준화된 서명 불일치 로그
            append_log('스키마 검증 실패 : 시그니처 필드의 JWS 불일치 (498 Invalid Token)', False)
        except Exception:
            pass
        # 498 상태코드: Invalid Token (비표준 매핑)
        return jsonify({"error": 'INVALID_TOKEN', "message": sig_reason or 'Invalid JWS signature'}), 498

    # --- 중복 name/url 검사 ---
    agents = repo.load_agents()
    dup = check_duplicate_card(card, agents)
    if isinstance(dup, str) and dup:
        try:
            # 표준화된 정책 실패 로그 메시지
            append_log('정책 검사 실패 : 동일 name/url 이 존재 (409 Conflict)', False)
        except Exception:
            pass
        return jsonify({"error": 'CONFLICT', "message": dup}), 409

    # 도메인 / IP 화이트리스트 검사 (.env 기반) + extension 제한
    evaluator: PolicyEvaluator | None = None
    try:
        evaluator = PolicyEvaluator()  # 환경변수(AGENT_DOMAIN_WHITELIST, AGENT_IP_WHITELIST)에서 값 읽기
        wle = evaluator._check_whitelist(card)
    except Exception:
        wle = None
    if isinstance(wle, str) and wle:
        try:
            append_log('정책 검사 실패 : 도메인/IP 화이트리스트 불일치 (400 Bad Request)', False)
        except Exception:
            pass
        return jsonify({"error": 'WHITELIST_REJECTED', "message": wle}), 400
    if evaluator:
        try:
            capabilities = card.get("capabilities") or {}
            extensions = capabilities.get("extensions")
            extension_error = evaluator._check_extension_limits(extensions)
        except Exception:
            extension_error = None
        if isinstance(extension_error, str) and extension_error:
            try:
                append_log('정책 검사 실패 : extension 제한 초과 (400 Bad Request)', False)
            except Exception:
                pass
            return jsonify({"error": 'EXTENSION_LIMIT_EXCEEDED', "message": extension_error}), 400

    name = str(card.get('name', ''))

    # --- 메타데이터 구성 및 저장 ---
    def _derive_agent_id(c: dict) -> str:
        """organization/name/version 조합으로 agent_id 생성."""
        try:
            org = ''
            if isinstance(c.get('provider'), dict):
                org = str(c['provider'].get('organization') or '').strip()
            name_v = str(c.get('name') or '').strip()
            ver_v = str(c.get('version') or '').strip()
            if org and name_v and ver_v:
                return f"{org}#agent:{name_v}.v{ver_v}"
            if name_v and ver_v:
                return f"agent:{name_v}.v{ver_v}"
            return name_v or 'agent:unknown'
        except Exception:
            return 'agent:unknown'

    # 레지스트리 표준 시간(UTC+9)으로 타임스탬프 기록
    jst = timezone(timedelta(hours=9))
    now_local = datetime.now(jst).isoformat()

    # 새 ETag 및 초기 버전 설정
    version_id = 1
    short = secrets.token_hex(3)
    etag = f"W/\"{version_id}-{short}\""

    # 요청 본문에 포함된 publisher 서명 추출
    publisher_jws = None
    try:
        publisher_jws = (
            body.get('publisher_jws')
            or body.get('publisherJws')
            or body.get('jws')
        )
        if not isinstance(publisher_jws, str):
            publisher_jws = None
    except Exception:
        publisher_jws = None

    # 클라이언트 서명이 있었다면 metadata 로 이동
    if not publisher_jws and original_sigs:
        # 기존 서명 배열을 metadata 필드에 그대로 보존
        publisher_jws = original_sigs

    # JWT 에서 등록자 정보 추출
    try:
        from flask import g
        registrant = getattr(g, 'jwt', {}).get('sub')
    except Exception:
        registrant = None

    record = {
        "agent_id": _derive_agent_id(card),
        "etag": etag,
        "versionID": version_id,
        "card": card,
        "status": 'Active',
        "tenants": tenants,
        "create_ts": now_local,
        "update_ts": now_local,
        "delete_ts": None,
        "publisher_jws": publisher_jws,
        "registrant": registrant,
    }

    agents.append(record)
    repo.save_agents(agents)
    append_log(f"에이전트 추가 성공 (201 Created): {name}", True)
    return jsonify({"agent": {"name": name, "status": 'Active', "card": card, "tenants": tenants}}), 201




