import os
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
            record_tenants = agent.get("tenants")
            if not isinstance(record_tenants, list):
                record_tenants = []
            if not any(
                isinstance(t, str) and t.strip().lower() in allowed_tenants
                for t in record_tenants
            ):
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
            record_tenants = agent.get("tenants")
            if not isinstance(record_tenants, list):
                record_tenants = []
            if not any(
                isinstance(t, str) and t.strip().lower() in allowed_tenants
                for t in record_tenants
            ):
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
        record_tenants = agent.get("tenants")
        if not isinstance(record_tenants, list):
            record_tenants = []
        if not any(
            isinstance(t, str) and t.strip().lower() in allowed_tenants
            for t in record_tenants
        ):
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
