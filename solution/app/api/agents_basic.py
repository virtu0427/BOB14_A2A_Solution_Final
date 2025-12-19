import os
import urllib.request
import urllib.error
import json
from datetime import datetime, timezone, timedelta

def _get_kst_now():
    """현재 한국 표준시(UTC+9)를 반환."""
    kst = timezone(timedelta(hours=9))
    return datetime.now(kst)

from flask import jsonify, request, g

from . import api_bp
from ..core import repo
from ..core.logging import append_log
from ..core.auth import require_jwt
from ..core.tenants import matches_allowed_tenants

_POLICY_LIST_KEYS = [
    "prompt_validation_rulesets",
    "tool_validation_rulesets",
    "response_filtering_rulesets",
]

ENABLE_AGENT_ACCESS_LOGS = os.environ.get("ENABLE_AGENT_ACCESS_LOGS", "false").strip().lower() in (
    "1",
    "true",
    "yes",
)


def _ensure_list(value):
    if isinstance(value, list):
        return [str(item) for item in value if item is not None]
    if isinstance(value, str):
        trimmed = value.strip()
        return [trimmed] if trimmed else []
    return []


def _normalize_policy(source, fallback=None):
    fallback = fallback or {}
    policy = {
        "enabled": bool(source.get("enabled")) if source.get("enabled") is not None else bool(fallback.get("enabled", True)),
    }
    for key in _POLICY_LIST_KEYS:
        if key in source:
            policy[key] = _ensure_list(source.get(key))
        else:
            policy[key] = _ensure_list(fallback.get(key))
    return policy


def _build_plugins(agent, card):
    plugins = agent.get("plugins")
    if isinstance(plugins, list) and plugins:
        return plugins
    skills = card.get("skills")
    if isinstance(skills, list):
        derived = []
        for skill in skills:
            if not isinstance(skill, dict):
                continue
            name = skill.get("name") or skill.get("id") or "plugin"
            derived.append(
                {
                    "name": name,
                    "type": skill.get("type") or "skill",
                    "status": skill.get("status") or "Active",
                }
            )
        if derived:
            return derived
    return []


def _normalize_agent(agent):
    if not isinstance(agent, dict):
        return agent

    card = agent.get("card") if isinstance(agent.get("card"), dict) else {}
    name = card.get("name") or agent.get("name") or "Unknown"
    description = card.get("description") or agent.get("description") or ""
    status = agent.get("status") or "Active"
    policy = _normalize_policy(agent.get("policy", {}), agent.get("policy", {}))

    normalized = {
        "agent_id": agent.get("agent_id") or name,
        "etag": agent.get("etag"),
        "versionID": agent.get("versionID"),
        "card": card,
        "status": status,
        "name": name,
        "description": description,
        "tenants": agent.get("tenants") if isinstance(agent.get("tenants"), list) else [],
        "create_ts": agent.get("create_ts"),
        "update_ts": agent.get("update_ts"),
        "created_at": agent.get("created_at") or agent.get("create_ts"),
        "updated_at": agent.get("updated_at") or agent.get("update_ts"),
        "publisher_jws": agent.get("publisher_jws"),
        "registrant": agent.get("registrant"),
        "policy": policy,
        "plugins": _build_plugins(agent, card),
    }
    return normalized


def _find_agent_index(agent_id):
    agents = repo.load_agents()
    for index, agent in enumerate(agents):
        if agent.get("agent_id") == agent_id:
            return index, agent, agents
    return None, None, agents


@api_bp.get('/agents')
def list_agents():
    """등록된 에이전트 목록을 반환."""
    # JWT가 있을 때만 검증/필터; 없으면 전체 목록 반환
    jwt_info = {}
    client_ip = None
    auth_header = request.headers.get("Authorization")
    if auth_header:
        auth_err = require_jwt()
        if auth_err:
            return auth_err
        jwt_info = getattr(g, "jwt", {}) or {}
        forwarded = request.headers.get("X-Forwarded-For")
        client_ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
        if ENABLE_AGENT_ACCESS_LOGS:
            append_log(
                f"Agent card list requested (IP: {client_ip or 'unknown'})",
                ok=True,
                capture_client_ip=True,
                client_ip=client_ip,
            )

    is_admin = jwt_info.get("role") == "admin"
    token_tenants = jwt_info.get("tenants") or []
    allowed_tenants = {t.strip().lower() for t in token_tenants if isinstance(t, str)}
    agents = repo.load_agents()
    filtered = []
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        if auth_header and not is_admin:
            if not matches_allowed_tenants(agent.get("tenants"), allowed_tenants):
                continue
        filtered.append(agent)

    normalized = [_normalize_agent(agent) for agent in filtered]

    resp = jsonify(normalized)
    if auth_header and client_ip:
        resp.headers["X-Client-IP"] = client_ip
    return resp


@api_bp.get('/agents/agent-view')
def list_agents_agent_view():
    """에이전트 전용: JWT 필터 + 조회 로그 남김."""
    auth_err = require_jwt()
    if auth_err:
        return auth_err

    jwt_info = getattr(g, "jwt", {}) or {}
    forwarded = request.headers.get("X-Forwarded-For")
    client_ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr

    is_admin = jwt_info.get("role") == "admin"
    token_tenants = jwt_info.get("tenants") or []
    allowed_tenants = {t.strip().lower() for t in token_tenants if isinstance(t, str)}

    agents = repo.load_agents()
    filtered = []
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        if not is_admin:
            if not matches_allowed_tenants(agent.get("tenants"), allowed_tenants):
                continue
        filtered.append(agent)

    normalized = [_normalize_agent(agent) for agent in filtered]

    if ENABLE_AGENT_ACCESS_LOGS:
        append_log(
            f"Agent card list requested (IP: {client_ip or 'unknown'})",
            ok=True,
            capture_client_ip=True,
            client_ip=client_ip,
        )

    resp = jsonify(normalized)
    resp.headers["X-Client-IP"] = client_ip or ""
    return resp


@api_bp.get('/agents/<path:agent_id>')
def get_agent(agent_id):
    """특정 에이전트 메타데이터를 반환."""
    index, agent, agents = _find_agent_index(agent_id)
    if agent is None:
        return jsonify({"error": 'agent not found'}), 404

    # 에이전트(토큰 기반) 요청 시 모든 역할에 대해 조회 로그를 남긴다.
    auth_header = request.headers.get("Authorization")
    client_ip = None
    if auth_header:
        auth_err = require_jwt()
        if auth_err:
            return auth_err
        forwarded = request.headers.get("X-Forwarded-For")
        client_ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr
        if ENABLE_AGENT_ACCESS_LOGS:
            append_log(
                f"Agent card viewed: {agent_id} (IP: {client_ip or 'unknown'})",
                ok=True,
                capture_client_ip=True,
                client_ip=client_ip,
            )

    resp = jsonify(_normalize_agent(agent))
    if auth_header and client_ip:
        resp.headers["X-Client-IP"] = client_ip
    return resp


@api_bp.get('/agents/agent-view/<path:agent_id>')
def get_agent_agent_view(agent_id):
    """에이전트 전용 단건 조회: JWT 필터 + 조회 로그 남김."""
    auth_err = require_jwt()
    if auth_err:
        return auth_err

    jwt_info = getattr(g, "jwt", {}) or {}
    forwarded = request.headers.get("X-Forwarded-For")
    client_ip = forwarded.split(",")[0].strip() if forwarded else request.remote_addr

    is_admin = jwt_info.get("role") == "admin"
    token_tenants = jwt_info.get("tenants") or []
    allowed_tenants = {t.strip().lower() for t in token_tenants if isinstance(t, str)}

    index, agent, agents = _find_agent_index(agent_id)
    if agent is None:
        return jsonify({"error": 'agent not found'}), 404

    if not is_admin:
        if not matches_allowed_tenants(agent.get("tenants"), allowed_tenants):
            return jsonify({"error": "FORBIDDEN", "message": "tenant mismatch"}), 403

    if ENABLE_AGENT_ACCESS_LOGS:
        append_log(
            f"Agent card viewed: {agent_id} (IP: {client_ip or 'unknown'})",
            ok=True,
            capture_client_ip=True,
            client_ip=client_ip,
        )

    resp = jsonify(_normalize_agent(agent))
    resp.headers["X-Client-IP"] = client_ip or ""
    return resp

@api_bp.put('/agents/<path:agent_id>/policy')
def update_agent_policy(agent_id):
    """에이전트에 연결된 policy 룰셋을 업데이트합니다."""
    index, agent, agents = _find_agent_index(agent_id)
    if agent is None:
        return jsonify({"error": 'agent not found'}), 404

    body = request.get_json(silent=True) or {}
    existing_policy = agent.get("policy", {})
    policy = _normalize_policy(body, existing_policy)
    agent["policy"] = policy
    now = _get_kst_now().isoformat()
    agent["update_ts"] = now
    agent["updated_at"] = now

    agents[index] = agent
    repo.save_agents(agents)
    return jsonify({"policy": policy})


# ------------------------------------------------------------------
# 에이전트 정책 캐시 새로고침 API
# ------------------------------------------------------------------

# 에이전트 서비스명 매핑 (Docker Compose 환경용)
AGENT_SERVICE_NAMES = {
    "orchestrator": ["orchestrator", "orchestrator-agent"],
    "delivery": ["delivery-agent", "delivery_agent", "deliveryagent"],
    "item": ["item-agent", "item_agent", "itemagent"],
    "quality": ["quality-agent", "quality_agent", "qualityagent", "qulity-agent"],
    "vehicle": ["vehicle-agent", "vehicle_agent", "vehicleagent"],
}


def _get_alternative_urls(original_url: str) -> list[str]:
    """
    에이전트 URL에 대한 대체 URL 목록을 생성합니다.
    Docker 환경에서 localhost는 작동하지 않으므로 여러 대안을 시도합니다.
    """
    from urllib.parse import urlparse
    
    parsed = urlparse(original_url)
    port = parsed.port or 80
    
    urls = [original_url]  # 원본 URL 먼저 시도
    
    # localhost나 127.0.0.1인 경우 대체 URL 추가
    if parsed.hostname in ("localhost", "127.0.0.1"):
        # 1. host.docker.internal (Docker Desktop)
        urls.append(f"http://host.docker.internal:{port}")
        
        # 2. 포트 번호로 에이전트 유형 추론하여 Docker 서비스명 시도
        port_agent_map = {
            10000: "orchestrator",
            10001: "delivery",
            10002: "item",
            10003: "quality",
            10004: "vehicle",
        }
        agent_type = port_agent_map.get(port)
        if agent_type and agent_type in AGENT_SERVICE_NAMES:
            for service_name in AGENT_SERVICE_NAMES[agent_type]:
                urls.append(f"http://{service_name}:{port}")
        
        # 3. 호스트 네트워크 모드용 (172.17.0.1은 Docker 기본 브릿지 게이트웨이)
        urls.append(f"http://172.17.0.1:{port}")
    
    return urls


def _call_agent_refresh_policy(agent_url: str, tenant: str | None = None) -> dict:
    """
    에이전트 서버에 정책 캐시 새로고침 요청을 보냅니다.
    Docker 환경을 고려하여 여러 URL을 순차적으로 시도합니다.
    """
    alternative_urls = _get_alternative_urls(agent_url)
    
    body = {}
    if tenant:
        body["tenant"] = tenant
    
    req_data = json.dumps(body).encode("utf-8") if body else b"{}"
    last_error = None
    successful_url = None
    
    for url in alternative_urls:
        refresh_url = f"{url.rstrip('/')}/api/refresh-policy"
        
        req = urllib.request.Request(
            refresh_url,
            data=req_data,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                response_data = resp.read().decode("utf-8")
                result = json.loads(response_data) if response_data else {"success": True}
                result["connected_url"] = url
                return result
        except urllib.error.HTTPError as e:
            last_error = f"HTTP {e.code}: {e.reason}"
            # HTTP 에러는 연결은 된 것이므로 다른 URL 시도하지 않음
            return {"success": False, "error": last_error, "tried_url": url}
        except urllib.error.URLError as e:
            last_error = f"Connection failed: {e.reason}"
            # 연결 실패는 다음 URL 시도
            continue
        except Exception as e:
            last_error = str(e)
            continue
    
    return {
        "success": False, 
        "error": last_error or "All connection attempts failed",
        "tried_urls": alternative_urls,
    }


@api_bp.post('/agents/<path:agent_id>/refresh-policy')
def refresh_agent_policy(agent_id):
    """
    특정 에이전트의 정책 캐시를 새로고침합니다.
    에이전트 서버에 직접 요청을 보내 캐시를 비웁니다.
    """
    index, agent, agents = _find_agent_index(agent_id)
    if agent is None:
        return jsonify({"error": "agent not found"}), 404
    
    # 에이전트 URL 확인
    card = agent.get("card", {})
    agent_url = card.get("url") or agent.get("url")
    
    if not agent_url:
        return jsonify({
            "error": "agent URL not found",
            "message": "에이전트의 URL 정보가 없어 정책을 새로고침할 수 없습니다.",
        }), 400
    
    # 요청 바디에서 tenant 파라미터 확인
    body = request.get_json(silent=True) or {}
    tenant = body.get("tenant")
    
    # 에이전트 서버에 정책 캐시 새로고침 요청
    result = _call_agent_refresh_policy(agent_url, tenant)
    
    if result.get("success"):
        return jsonify({
            "success": True,
            "agent_id": agent_id,
            "agent_url": agent_url,
            "connected_url": result.get("connected_url"),
            "message": "에이전트 정책 캐시가 새로고침되었습니다.",
            "details": result.get("details"),
        })
    else:
        # 에이전트 서버가 실행 중인지 확인하는 힌트 제공
        error_msg = result.get("error", "Unknown error")
        tried_urls = result.get("tried_urls", [agent_url])
        
        hint = ""
        if "Connection" in error_msg or "refused" in error_msg.lower():
            hint = " 에이전트 서버가 실행 중인지 확인하세요."
        
        return jsonify({
            "success": False,
            "agent_id": agent_id,
            "agent_url": agent_url,
            "tried_urls": tried_urls,
            "error": error_msg,
            "message": f"에이전트 정책 캐시 새로고침에 실패했습니다.{hint}",
        }), 502


@api_bp.post('/agents/refresh-all-policies')
def refresh_all_agent_policies():
    """
    모든 활성 에이전트의 정책 캐시를 새로고침합니다.
    """
    body = request.get_json(silent=True) or {}
    tenant = body.get("tenant")
    
    agents = repo.load_agents()
    results = []
    success_count = 0
    fail_count = 0
    
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        
        status = (agent.get("status") or "").lower()
        if status == "deleted":
            continue
        
        agent_id = agent.get("agent_id")
        card = agent.get("card", {})
        agent_url = card.get("url") or agent.get("url")
        
        if not agent_url:
            results.append({
                "agent_id": agent_id,
                "success": False,
                "error": "URL not found",
            })
            fail_count += 1
            continue
        
        result = _call_agent_refresh_policy(agent_url, tenant)
        
        if result.get("success"):
            success_count += 1
            results.append({
                "agent_id": agent_id,
                "success": True,
                "details": result.get("details"),
            })
        else:
            fail_count += 1
            results.append({
                "agent_id": agent_id,
                "success": False,
                "error": result.get("error"),
            })
    
    append_log(
        f"Bulk policy cache refresh: {success_count} succeeded, {fail_count} failed",
        ok=fail_count == 0,
    )
    
    return jsonify({
        "success": fail_count == 0,
        "message": f"{success_count}개 에이전트 정책 새로고침 완료, {fail_count}개 실패",
        "total": len(results),
        "success_count": success_count,
        "fail_count": fail_count,
        "results": results,
    })
