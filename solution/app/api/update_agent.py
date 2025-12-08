import os
import json
import secrets
from datetime import datetime, timezone, timedelta
import requests
from flask import request, jsonify

from . import api_bp
from ..core.auth import require_jwt, require_admin
from ..core.logging import append_log
from ..core import repo
from ..core.validators import (
    validate_card_basic_update,
    DEFAULT_MAX_AGENT_CARD_BYTES,
)
from ..core.policy import PolicyEvaluator
from ..core.tenants import extract_tenants
from ..core.signatures import verify_jws


# --- 외부 서명 서버 설정 (재서명) ---
JWS_SERVER_URL = os.environ.get('JWS_SERVER_URL', 'http://127.0.0.1:8001')
JWS_SIGN_URL = f"{JWS_SERVER_URL.rstrip('/')}/sign"
DEFAULT_JWS_KID = os.environ.get('JWS_KID', 'registry-hs256-key-1')


def _derive_agent_id(c: dict) -> str:
    """Generator used both for lookups and when clients omit agent_id."""
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


@api_bp.post('/update-agent')
def update_agent():
    """기존 에이전트 카드를 수정하고 재서명."""
    # --- 인증 ---
    err = require_jwt() or require_admin()
    if err:
        return err

    # --- 본문 크기 확인 및 JSON 파싱 (create_agent 와 동일 패턴) ---
    raw = request.get_data(as_text=True) or ''
    try:
        if len(raw.encode('utf-8')) > DEFAULT_MAX_AGENT_CARD_BYTES:
            append_log('스키마 검증 실패 : 에이전트 최대 바이트 넘김 (413 Payload Too Larg)', False, status=413)
            return jsonify({"error": 'PAYLOAD_TOO_LARGE', "message": f"payload exceeds {DEFAULT_MAX_AGENT_CARD_BYTES} bytes"}), 413
    except Exception:
        pass
    try:
        body = json.loads(raw)
    except Exception:
        append_log('스키마 검증 실패 : 잘못된 JSON 문법 (400 Bad Request)', False, status=400)
        return jsonify({"error": 'BAD_JSON', "message": 'Invalid JSON'}), 400

    # --- card 추출 ---
    card = None
    if isinstance(body, dict):
        card = body.get('card') if isinstance(body.get('card'), dict) else body
    if not isinstance(card, dict):
        append_log('스키마 검증 실패 :   card 필드 누락', False, status=422)
        return jsonify({"error": 'REQUIRED_FIELDS_MISSING', "errors": ['card is required']}), 422

    # --- 대상 레코드 식별 ---
    # 저장소 조회 후 수정할 agent_id 를 먼저 파악
    agents = repo.load_agents()
    target_id = body.get('agent_id') if isinstance(body.get('agent_id'), str) else _derive_agent_id(card)
    idx = -1
    for i, rec in enumerate(agents):
        rid = rec.get('agent_id') if isinstance(rec, dict) else None
        if isinstance(rid, str) and rid == target_id:
            idx = i
            break
    if idx < 0:
        append_log('리소스 없음 : 대상 에이전트를 찾을 수 없음 (404 Not Found)', False, status=404)
        return jsonify({"error": 'NOT_FOUND', "message": 'agent not found'}), 404

    # --- 기본 스키마 검증 ---
    ok, errors = validate_card_basic_update(card)
    if not ok:
        append_log('스키마 검증 실패 : 필수 필드 누락 (422 Unprocessable Entity)', False, status=422)
        return jsonify({"error": 'REQUIRED_FIELDS_MISSING', "errors": errors}), 422

    # --- signatures 구조 검증 (필요 시) ---
    sigs = card.get('signatures')
    if isinstance(sigs, list) and sigs:
        sig_ok, sig_reason = verify_jws(card)
        if not sig_ok:
            append_log('스키마 검증 실패 : 시그니처 필드의 JWS 불일치 (498 Invalid Token)', False, status=498)
            return jsonify({"error": 'INVALID_TOKEN', "message": sig_reason or 'Invalid JWS signature'}), 498

    # --- 화이트리스트 및 중복 name/url 검증 ---
    evaluator: PolicyEvaluator | None = None
    try:
        evaluator = PolicyEvaluator()
        wle = evaluator._check_whitelist(card)
    except Exception:
        wle = None
    if isinstance(wle, str) and wle:
        append_log('정책 검사 실패 : 도메인/IP 화이트리스트 불일치 (400 Bad Request)', False, status=400)
        return jsonify({"error": 'WHITELIST_REJECTED', "message": wle}), 400
    if evaluator:
        try:
            extension_error = evaluator._check_extension_limits(card.get('extension'))
        except Exception:
            extension_error = None
        if isinstance(extension_error, str) and extension_error:
            append_log('정책 검사 실패 : extension 제한 초과 (400 Bad Request)', False, status=400)
            return jsonify({"error": 'EXTENSION_LIMIT_EXCEEDED', "message": extension_error}), 400

    # 자기 자신을 제외한 중복 검사
    new_name = str(card.get('name') or '').strip().lower()
    new_url = str(card.get('url') or '').strip().lower()
    for j, rec in enumerate(agents):
        if j == idx or not isinstance(rec, dict):
            continue
        existing = rec.get('card') if isinstance(rec.get('card'), dict) else rec
        if not isinstance(existing, dict):
            continue
        en = str(existing.get('name') or '').strip().lower()
        eu = str(existing.get('url') or '').strip().lower()
        if new_name and en == new_name:
            append_log('정책 검사 실패 : 동일 name/url 이 존재 (409 Conflict)', False, status=409)
            return jsonify({"error": 'CONFLICT', "message": '동일한 name 을 가진 에이전트가 이미 존재합니다.'}), 409
        if new_url and eu == new_url:
            append_log('정책 검사 실패 : 동일 name/url 이 존재 (409 Conflict)', False, status=409)
            return jsonify({"error": 'CONFLICT', "message": '동일한 url 을 가진 에이전트가 이미 존재합니다.'}), 409

    # --- jws-server 재서명 (이전 서명은 metadata 로 이동하지 않음) ---
    sign_payload = {
        'sub': _derive_agent_id(card),
        'version_id': agents[idx].get('versionID', 1),
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
                card['signatures'] = [sig_entry]
                append_log('JWS 재서명 성공 : 시그니처 교체', True)
        else:
            append_log(f'JWS 재서명 실패 : 서버 오류({r.status_code})', False, status=r.status_code)
    except Exception:
        # 서명 서버 장애 시에도 업데이트 흐름은 계속 진행
        append_log('JWS 재서명 실패 : 서버 오류', False, status=500)

    # --- 레코드 갱신 ---
    now_local = datetime.now(timezone(timedelta(hours=9))).isoformat()
    rec = agents[idx]
    # 버전 및 ETag 갱신
    version_id = int(rec.get('versionID', 1)) + 1
    rec['versionID'] = version_id
    rec['etag'] = f"W/\"{version_id}-{secrets.token_hex(3)}\""
    rec['card'] = card
    tenants = []
    if isinstance(body, dict):
        tenants = extract_tenants(body.get('tenants'))
    if tenants:
        # 요청 본문에 tenants 가 있을 때만 덮어씀
        rec['tenants'] = tenants
    rec['update_ts'] = now_local
    # create_ts / delete_ts / publisher_jws 는 유지

    repo.save_agents(agents)
    append_log(f"에이전트 수정 성공 (200 OK): {card.get('name','')} ", True)
    return jsonify({"agent": rec}), 200
