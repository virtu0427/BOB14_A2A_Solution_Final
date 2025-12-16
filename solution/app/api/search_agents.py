import json
import os
import urllib.request
from flask import jsonify, request, g

from . import api_bp
from ..core import repo
from ..core.auth import require_jwt
from ..core.logging import append_log
from ..core.tenants import matches_allowed_tenants

# 기본 페이지 범위
DEFAULT_LIMIT = 20
MAX_LIMIT = 200

# Tenant API 우선순위 (환경변수 → jwt-server → host.docker.internal → localhost)
TENANT_API_URLS: list[str] = []
for url in (
    os.getenv("TENANT_API_URL"),
    "http://jwt-server:8000",
    "http://host.docker.internal:8000",
    "http://localhost:8000",
):
    if url and url not in TENANT_API_URLS:
        TENANT_API_URLS.append(url)


def _tenant_fetch_json(path: str):
    """Tenant API를 순회하며 JSON을 반환."""
    last_err: Exception | None = None
    for base in TENANT_API_URLS:
        try:
            req = urllib.request.Request(
                f"{base}{path}",
                headers={"Accept": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = resp.read()
                if not data:
                    return None
                return json.loads(data.decode("utf-8"))
        except Exception as e:  # pragma: no cover - 외부 통신
            last_err = e
            continue
    if last_err:
        raise last_err
    raise RuntimeError("Tenant API URL not configured")


def _short_agent_id(agent_id: str) -> str:
    """provider 앞을 떼고 name.version만 남긴다."""
    if not isinstance(agent_id, str):
        return ""
    return agent_id.rsplit(":", 1)[-1].strip()


def _short_agent_id_no_version(agent_id: str) -> str:
    """버전(.v...)을 제거한 짧은 ID."""
    short = _short_agent_id(agent_id)
    if not short:
        return ""
    if ".v" in short:
        return short.split(".v", 1)[0].strip()
    return short


def _normalize_agent_candidates(agent: dict) -> set[str]:
    """에이전트 레코드에서 비교 가능한 여러 식별자 후보를 소문자로 반환."""
    candidates: set[str] = set()
    if not isinstance(agent, dict):
        return candidates
    for key in ("agent_id", "id"):
        val = agent.get(key)
        if isinstance(val, str) and val.strip():
            raw = val.strip()
            candidates.update({raw, _short_agent_id(raw), _short_agent_id_no_version(raw)})
    card = agent.get("card")
    if isinstance(card, dict):
        name = card.get("name")
        if isinstance(name, str) and name.strip():
            raw = name.strip()
            candidates.update({raw, _short_agent_id_no_version(raw)})
    return {c.lower() for c in candidates if c}


def _load_user_allowed_agents(user_email: str, tenant_ids: list[str]) -> set[str]:
    """
    사용자 그룹 멤버십을 확인해 해당 그룹 access_controls에 연결된 에이전트 ID 집합을 반환.
    다양한 표기(풀 ID, provider 제거, 버전 제거)를 모두 포함한다.
    """
    allowed_agents: set[str] = set()

    for tenant_id in tenant_ids:
        tenant = (tenant_id or "").strip().lower()
        if not tenant:
            continue
        try:
            payload = _tenant_fetch_json(f"/tenants/{tenant}/rulesets")
        except Exception:
            continue

        groups = payload.get("groups") if isinstance(payload, dict) else []
        member_group_ids: set[str] = set()
        if isinstance(groups, list):
            for g in groups:
                if not isinstance(g, dict):
                    continue
                members = g.get("members") or []
                if user_email in members:
                    gid = (g.get("id") or "").strip()
                    if gid:
                        member_group_ids.add(gid)
        if not member_group_ids:
            continue

        access_controls = payload.get("access_controls") if isinstance(payload, dict) else []
        if isinstance(access_controls, list):
            for ac in access_controls:
                if not isinstance(ac, dict):
                    continue
                if ac.get("group_id") not in member_group_ids:
                    continue
                if not ac.get("enabled", True):
                    continue
                agent_id = ac.get("target_agent") or ac.get("agent_id")
                if isinstance(agent_id, str) and agent_id.strip():
                    raw = agent_id.strip()
                    allowed_agents.update(
                        {
                            raw.lower(),
                            _short_agent_id(raw).lower(),
                            _short_agent_id_no_version(raw).lower(),
                        }
                    )

    return allowed_agents


# --- 에이전트 검색 ---
@api_bp.get('/agents/search')
def search_agents():
    """에이전트 검색 API (tenant 제한 + Active 상태, 그룹 기반 허용)."""
    auth_err = require_jwt()
    if auth_err:
        return auth_err

    jwt_info = getattr(g, "jwt", {}) or {}
    is_admin = jwt_info.get("role") == "admin"
    token_tenants = jwt_info.get("tenants") or []
    if not is_admin and not token_tenants:
        append_log('에이전트 조회 거부 : JWT tenant claim 없음 (403 Forbidden)', False, capture_client_ip=True, status=403)
        return jsonify({"error": "TENANT_REQUIRED", "message": "tenant claim missing in JWT"}), 403

    user_email = (jwt_info.get("sub") or "").strip().lower()
    allowed_agents_from_groups: set[str] | None = None
    if not is_admin and user_email:
        allowed_agents_from_groups = _load_user_allowed_agents(user_email, token_tenants)

    status_param = request.args.get('status')
    if status_param and status_param.strip().lower() != 'active':
        append_log('에이전트 조회 거부 : Active 상태만 허용 (403 Forbidden)', False, capture_client_ip=True, status=403)
        return jsonify({"error": "STATUS_FORBIDDEN", "message": "Only Active agents can be queried"}), 403

    try:
        limit = int(request.args.get('limit', DEFAULT_LIMIT))
        offset = int(request.args.get('offset', 0))
    except (TypeError, ValueError):
        append_log('에이전트 조회 실패 : 잘못된 pagination 파라미터 (400 Bad Request)', False, capture_client_ip=True, status=400)
        return jsonify({"error": "invalid query parameter", "message": "limit/offset must be integers"}), 400
    if limit < 1 or limit > MAX_LIMIT or offset < 0:
        append_log('에이전트 조회 실패 : pagination 범위 위반 (400 Bad Request)', False, capture_client_ip=True, status=400)
        return jsonify({"error": "invalid pagination", "message": f"1 <= limit <= {MAX_LIMIT}, offset >= 0"}), 400

    status_lower = 'active'
    allowed_tenants = {t.strip().lower() for t in token_tenants if isinstance(t, str)}

    agents = repo.load_agents()
    filtered: list[dict] = []
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        if status_lower:
            a_status = agent.get('status')
            if not isinstance(a_status, str) or a_status.lower() != status_lower:
                continue
        if not is_admin:
            if not matches_allowed_tenants(agent.get('tenants'), allowed_tenants):
                continue
            if allowed_agents_from_groups is not None:
                candidates = _normalize_agent_candidates(agent)
                if not any(c in allowed_agents_from_groups for c in candidates):
                    continue
        filtered.append(agent)

    total = len(filtered)
    slice_start = min(offset, total)
    slice_end = min(slice_start + limit, total)
    items = filtered[slice_start:slice_end]
    resp = {
        "items": items,
        "total": total,
        "limit": limit,
        "offset": slice_start,
    }
    return jsonify(resp)
