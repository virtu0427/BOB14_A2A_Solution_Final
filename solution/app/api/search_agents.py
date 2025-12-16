from flask import jsonify, request, g

from . import api_bp
from ..core import repo
from ..core.auth import require_jwt
from ..core.logging import append_log
from ..core.tenants import matches_allowed_tenants

# 페이지네이션 기본 범위
DEFAULT_LIMIT = 20
MAX_LIMIT = 200


# --- 에이전트 검색 ---
@api_bp.get('/agents/search')
def search_agents():
    """에이전트 검색 API (solution) - tenant 제한 + Active 상태만 노출."""
    auth_err = require_jwt()
    if auth_err:
        return auth_err

    # require_jwt 에서 검증한 컨텍스트를 한 번만 참조
    jwt_info = getattr(g, "jwt", {}) or {}
    is_admin = jwt_info.get("role") == "admin"
    token_tenants = jwt_info.get("tenants") or []
    if not is_admin and not token_tenants:
        append_log('에이전트 조회 거부 : JWT tenant claim 없음 (403 Forbidden)', False, capture_client_ip=True, status=403)
        return jsonify({"error": "TENANT_REQUIRED", "message": "tenant claim missing in JWT"}), 403

    # 현재 API 는 Active 상태만 노출
    status_param = request.args.get('status')
    if status_param and status_param.strip().lower() != 'active':
        append_log('에이전트 조회 거부 : Active 상태만 허용 (403 Forbidden)', False, capture_client_ip=True, status=403)
        return jsonify({"error": "STATUS_FORBIDDEN", "message": "Only Active agents can be queried"}), 403

    # 페이지네이션 파라미터 검증 (limit 로 전체 덤프 방지)
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

    # 파일 기반 저장소이므로 메모리에서 필터링
    agents = repo.load_agents()
    filtered: list[dict] = []
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        # 상태 필터 적용
        if status_lower:
            a_status = agent.get('status')
            if not isinstance(a_status, str) or a_status.lower() != status_lower:
                continue
        # 일반 사용자는 자신의 tenant 와 겹치는 에이전트만 조회 가능
        if not is_admin:
            if not matches_allowed_tenants(agent.get('tenants'), allowed_tenants):
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
    # 감사 로그: 어떤 범위로 조회했는지 남김
    return jsonify(resp)
