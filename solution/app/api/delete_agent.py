import secrets
from datetime import datetime, timezone, timedelta

from flask import request, jsonify

from . import api_bp
from ..core.auth import require_jwt, require_admin
from ..core.logging import append_log
from ..core import repo


def _now_utc9_iso() -> str:
    """Return registry-local timestamp (UTC+9) for audit trails."""
    return datetime.now(timezone(timedelta(hours=9))).isoformat()


def _agent_id_from_card(card: dict) -> str | None:
    """Build agent_id string from a card payload."""
    try:
        org = ''
        if isinstance(card.get('provider'), dict):
            org = str(card['provider'].get('organization') or '').strip()
        name_v = str(card.get('name') or '').strip()
        ver_v = str(card.get('version') or '').strip()
        if org and name_v and ver_v:
            return f"{org}#agent:{name_v}.v{ver_v}"
        if name_v and ver_v:
            return f"agent:{name_v}.v{ver_v}"
    except Exception:
        pass
    return None


def _delete_agent_record(target_id: str):
    """Shared delete routine (soft delete)."""
    agents = repo.load_agents()
    idx = -1
    for i, rec in enumerate(agents):
        rid = rec.get('agent_id') if isinstance(rec, dict) else None
        if isinstance(rid, str) and rid == target_id:
            idx = i
            break
    if idx < 0:
        append_log('리소스 없음 : 요청한 에이전트를 찾을 수 없음 (404 Not Found)', False, status=404)
        return jsonify({"error": 'NOT_FOUND', "message": 'agent not found'}), 404

    rec = agents.pop(idx)
    name = (rec.get('card') or {}).get('name') if isinstance(rec.get('card'), dict) else ''

    now_local = _now_utc9_iso()
    version_id = int(rec.get('versionID', 1)) + 1
    rec['versionID'] = version_id
    rec['etag'] = f"W/\"{version_id}-{secrets.token_hex(3)}\""
    rec['status'] = 'Deleted'
    rec['update_ts'] = now_local
    rec['delete_ts'] = now_local

    # 실제 저장 목록에서는 삭제된 레코드를 제거
    repo.save_agents(agents)
    # 성공 로그는 남겨 두어 감사 추적을 가능하게 함
    append_log(f"에이전트 삭제 성공 (200 OK): {name}", True)
    return jsonify({"agent": rec}), 200


# --- 에이전트 삭제 (body: agent_id 또는 card) ---
@api_bp.post('/delete-agent')
def delete_agent():
    """Legacy delete endpoint that accepts agent_id or card in the body."""
    err = require_jwt() or require_admin()
    if err:
        return err

    body = request.get_json(silent=True) or {}
    target_id = body.get('agent_id') if isinstance(body.get('agent_id'), str) else None

    if not target_id and isinstance(body.get('card'), dict):
        target_id = _agent_id_from_card(body['card'])

    if not target_id:
        append_log('요청 오류 : agent_id 누락 (400 Bad Request)', False, status=400)
        return jsonify({"error": 'BAD_REQUEST', "message": 'agent_id is required'}), 400

    return _delete_agent_record(target_id)


@api_bp.delete('/agents/<path:agent_id>')
def delete_agent_by_id(agent_id):
    """RESTful delete endpoint used by the WebUI."""
    err = require_jwt() or require_admin()
    if err:
        return err

    target_id = agent_id.strip() if isinstance(agent_id, str) else None
    if not target_id:
        append_log('요청 오류 : agent_id 누락 (400 Bad Request)', False, status=400)
        return jsonify({"error": 'BAD_REQUEST', "message": 'agent_id is required'}), 400

    return _delete_agent_record(target_id)
