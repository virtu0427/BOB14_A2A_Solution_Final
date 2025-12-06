"""룰셋 CRUD 및 조회 API."""

import json
import os
import re
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

from flask import jsonify, request, g, Response

from . import api_bp
from ..core import repo
from ..core.tenants import TENANT_CHOICES
from ..core.auth import require_jwt
from ..core.user import list_users
from ..core import tools as tools_helper

_PRIMARY_TENANT_API = os.getenv("TENANT_API_URL", "http://localhost:8000")
TENANT_API_URLS: list[str] = []
for url in (
    _PRIMARY_TENANT_API,
    "http://host.docker.internal:8000",
    "http://localhost:8000",
):
    if url and url not in TENANT_API_URLS:
        TENANT_API_URLS.append(url)
# 호환성: 기존 코드에서 참조하는 상수 유지
TENANT_API_URL = TENANT_API_URLS[0] if TENANT_API_URLS else "http://localhost:8000"
USER_REDIS_URL = (
    os.getenv("JWT_REDIS_URL")
    or os.getenv("USER_REDIS_URL")
    or os.getenv("REDIS_URL")
)
from ..core.tenants import TENANT_CHOICES


def _append_registry_log(
    *,
    actor: str | None,
    method: str,
    status: int,
    fail_stage: str,
    message: str,
    extra: dict | None = None,
):
    """Append a registry-type log entry into data/redisDB/r-logs.json."""
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "actor": actor or "",
        "method": method,
        "status": status,
        "fail_stage": fail_stage,
        "message": message,
        "source": "registry",
    }
    if extra:
        entry["extra"] = extra
    try:
        repo.append_registry_log(entry)
    except Exception:
        # Logging failures should not block API flow
        pass


def _extract_tools_from_card(card: dict | None) -> list[str]:
    """카드 확장/스킬 정보에서 tool_id 목록을 추출."""
    if not isinstance(card, dict):
        return []
    tools: set[str] = set()
    extensions = card.get("extensions")
    if isinstance(extensions, list):
        for ext in extensions:
            if not isinstance(ext, dict):
                continue
            params = ext.get("params")
            if isinstance(params, dict):
                ext_tools = params.get("tools")
                if isinstance(ext_tools, list):
                    for t in ext_tools:
                        if isinstance(t, dict):
                            tool_id = t.get("tool_id") or t.get("id")
                            if isinstance(tool_id, str) and tool_id:
                                tools.add(tool_id)
    skills = card.get("skills")
    if isinstance(skills, list):
        for skill in skills:
            if isinstance(skill, dict):
                skill_id = skill.get("id")
                if isinstance(skill_id, str) and skill_id:
                    tools.add(skill_id)
    return sorted(tools)

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _find_ruleset(rulesets: list[dict], ruleset_id: str):
    for idx, ruleset in enumerate(rulesets):
        if ruleset.get('ruleset_id') == ruleset_id:
            return idx, ruleset
    return None, None


def _as_bool(value: Any, default: bool = True) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 't', 'yes', 'y', 'on'}
    return default


def _parse_rules(value: Any):
    """Allow rules payload to arrive as JSON string from form submit."""
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return {"raw": value}
    return {}

def _normalize_tool_names(payload: dict) -> list[str]:
    """tool_name/tool_names/tool 필드를 모두 리스트로 통합."""
    names: list[str] = []
    raw_list = payload.get("tool_names") or payload.get("tools")
    if isinstance(raw_list, str):
        raw_list = [raw_list]
    if isinstance(raw_list, list):
        for item in raw_list:
            if isinstance(item, str) and item.strip():
                names.append(item.strip())
    raw_single = payload.get("tool_name") or payload.get("tool")
    if isinstance(raw_single, str) and raw_single.strip():
        for part in raw_single.split(","):
            part = part.strip()
            if part:
                names.append(part)
    seen: set[str] = set()
    deduped: list[str] = []
    for name in names:
        if name not in seen:
            seen.add(name)
            deduped.append(name)
    return deduped


def _normalize_ruleset_payload(body: dict, existing: dict | None = None) -> dict:
    """프론트 폼 데이터와 파일 시드가 같은 형태로 저장되도록 가볍게 정규화한다."""
    existing = existing or {}
    merged = {**existing, **body}

    scope = merged.get('scope') or ('group' if merged.get('group_id') else 'global')
    rules = _parse_rules(merged.get('rules', existing.get('rules', {})))
    enabled = _as_bool(merged.get('enabled', existing.get('enabled', True)), default=True)
    tool_names = _normalize_tool_names(merged)
    primary_tool = tool_names[0] if tool_names else (merged.get('tool_name') or merged.get('tool'))

    normalized = {
        **merged,
        "ruleset_id": merged.get('ruleset_id') or existing.get('ruleset_id'),
        "name": merged.get('name') or merged.get('ruleset_id'),
        "description": merged.get('description') or "",
        "type": merged.get('type') or "tool_validation",
        "scope": scope,
        "group_id": merged.get('group_id') or None,
        "target_agent": merged.get('target_agent') or merged.get('agent_id'),
        "tool_name": primary_tool,
        "tool_names": tool_names,
        "rules": rules,
        "enabled": enabled,
    }
    return normalized


def _fetch_json(url: str, method: str = "GET", body: bytes | None = None, headers: dict | None = None):
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Accept": "application/json",
            **(headers or {}),
        },
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        if resp.status >= 400:
            raise RuntimeError(f"HTTP {resp.status}")
        data = resp.read()
        if not data:
            return None
        return json.loads(data.decode("utf-8"))


def _tenant_fetch_json(path: str, **kwargs):
    """Try tenant API endpoints with fallback URLs."""
    last_err: Exception | None = None
    for base in TENANT_API_URLS:
        try:
            return _fetch_json(f"{base}{path}", **kwargs)
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise RuntimeError("No tenant API URLs configured")


def _load_tenant_rulesets():
    """Tenants 서비스에서 그룹/룰셋을 불러와 ruleset 리스트로 정규화."""
    try:
        tenants = _fetch_json(f"{TENANT_API_URL}/tenants") or []
    except Exception:
        return None, None

    user_index = {
        u.get("email"): {
            "email": u.get("email"),
            "name": u.get("name") or u.get("email"),
            "title": u.get("title") or "",
            "tenants": u.get("tenants") or [],
        }
        for u in list_users(redis_url=USER_REDIS_URL)
        if u.get("email")
    }

    all_rulesets: list[dict] = []
    all_groups: list[dict] = []

    for tenant in tenants:
        tenant_id = tenant.get("id") or tenant.get("tenant_id")
        if not tenant_id:
            continue
        try:
            payload = _fetch_json(f"{TENANT_API_URL}/tenants/{tenant_id}/rulesets")
        except Exception:
            continue

        groups = payload.get("groups") if isinstance(payload, dict) else []
        if isinstance(groups, list):
            for g in groups:
                member_emails = g.get("members") or []
                members = []
                for email in member_emails:
                    info = user_index.get(email) or {"email": email, "tenants": []}
                    members.append(info)
                all_groups.append(
                    {
                        "id": g.get("id"),
                        "name": g.get("name") or g.get("id"),
                        "description": g.get("description") or "",
                        "members": members,
                        "tenant_id": tenant_id,
                    }
                )

        access_controls = payload.get("access_controls") if isinstance(payload, dict) else []
        if isinstance(access_controls, list):
            for item in access_controls:
                all_rulesets.append(
                    _normalize_ruleset_payload(
                        {
                            **item,
                            "tenant_id": tenant_id,
                            "scope": "group" if item.get("group_id") else "global",
                        }
                    )
                )

    return all_rulesets, all_groups


def _find_tenant_for_ruleset(ruleset_id: str) -> str | None:
    """Find tenant_id that owns the given ruleset_id by scanning tenant API."""
    tenant_rulesets, _ = _load_tenant_rulesets()
    if not tenant_rulesets:
        return None
    for item in tenant_rulesets:
        if item.get("ruleset_id") == ruleset_id:
            return item.get("tenant_id")
    return None


def _find_tenant_for_group(group_id: str) -> str | None:
    """Locate tenant_id for a given group_id by scanning tenant API groups."""
    if not group_id:
        return None
    _, groups = _load_tenant_rulesets()
    if not groups:
        return None
    for group in groups:
        if group.get("id") == group_id and group.get("tenant_id"):
            return group.get("tenant_id")
    return None





def _short_agent_id(agent_id: str) -> str:
    """Return a shortened, human-readable agent id."""
    if not isinstance(agent_id, str):
        return ""
    short = agent_id.rsplit(":", 1)[-1]
    short = re.sub(r"\.v\d.*$", "", short)
    return short or agent_id

def _get_tenant_rule(ruleset_id: str) -> tuple[str | None, dict | None]:
    """Return (tenant_id, rule) pair for the given ruleset_id from tenant API."""
    tenant_rulesets, _ = _load_tenant_rulesets()
    if not tenant_rulesets:
        return None, None
    for item in tenant_rulesets:
        if item.get("ruleset_id") == ruleset_id:
            return item.get("tenant_id"), item
    return None, None


@api_bp.get('/rulesets')
def list_rulesets():
    """모든 룰셋을 정규화하여 반환한다."""
    tenant_rulesets, _ = _load_tenant_rulesets()
    if tenant_rulesets is not None:
        data = tenant_rulesets
    else:
        raw = repo.load_rulesets()
        data = [_normalize_ruleset_payload(item) for item in raw]

    data.sort(
        key=lambda item: item.get('updated_at') or item.get('created_at') or '',
        reverse=True,
    )
    return jsonify(data)


@api_bp.post('/rulesets')
def create_ruleset():
    """새 룰셋 생성."""
    body = request.get_json(silent=True) or {}
    ruleset_id = body.get('ruleset_id')
    if not isinstance(ruleset_id, str) or not ruleset_id.strip():
        return jsonify({"error": 'ruleset_id is required'}), 400

    tenant_id = (body.get("tenant_id") or "").strip() or _find_tenant_for_group(
        body.get("group_id", "")
    )
    tenant_error: Exception | None = None
    if tenant_id:
        now = _now_iso()
        payload = _normalize_ruleset_payload(body)
        payload.update(
            {
                "ruleset_id": ruleset_id,
                "tenant_id": tenant_id,
                "created_at": payload.get("created_at") or now,
                "updated_at": now,
            }
        )
        try:
            created = _tenant_fetch_json(
                f"/tenants/{tenant_id}/access-controls",
                method="POST",
                body=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
        except Exception as e:
            tenant_error = e
        else:
            normalized = _normalize_ruleset_payload(
                {**payload, **(created or {}), "tenant_id": tenant_id}
            )
            normalized["created_at"] = normalized.get("created_at") or now
            normalized["updated_at"] = normalized.get("updated_at") or now
            return jsonify(normalized), 201

    rulesets = repo.load_rulesets()
    if any(r.get('ruleset_id') == ruleset_id for r in rulesets):
        return jsonify({"error": 'ruleset already exists'}), 409

    now = _now_iso()
    normalized = _normalize_ruleset_payload(body)
    normalized["ruleset_id"] = ruleset_id
    normalized["created_at"] = now
    normalized["updated_at"] = now

    rulesets.append(normalized)
    repo.save_rulesets(rulesets)
    resp = {"tenant_error": str(tenant_error)} if tenant_error else {}
    return jsonify({**normalized, **resp}), 201


@api_bp.put('/rulesets/<ruleset_id>')
def update_ruleset(ruleset_id):
    """기존 룰셋 수정."""
    body = request.get_json(silent=True) or {}
    if 'ruleset_id' in body and body['ruleset_id'] != ruleset_id:
        return jsonify({"error": 'ruleset_id cannot be changed'}), 400

    tenant_override = (body.get("tenant_id") or "").strip()
    tenant_id, tenant_rule = _get_tenant_rule(ruleset_id)
    tenant_id = tenant_override or tenant_id
    tenant_error: Exception | None = None
    if tenant_id:
        base_existing = tenant_rule or {"ruleset_id": ruleset_id, "tenant_id": tenant_id}
        updated_payload = _normalize_ruleset_payload(body, existing=base_existing)
        updated_payload["ruleset_id"] = ruleset_id
        updated_payload["tenant_id"] = tenant_id
        updated_payload["created_at"] = (
            base_existing.get("created_at")
            or base_existing.get("createdAt")
            or updated_payload.get("created_at")
        )
        updated_payload["updated_at"] = _now_iso()
        try:
            updated_remote = _tenant_fetch_json(
                f"/tenants/{tenant_id}/access-controls/{ruleset_id}",
                method="PUT",
                body=json.dumps(updated_payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
        except Exception as e:
            tenant_error = e
        else:
            merged = _normalize_ruleset_payload(
                {**base_existing, **updated_payload, **(updated_remote or {})},
                existing=updated_payload,
            )
            merged["tenant_id"] = tenant_id
            merged["created_at"] = merged.get("created_at") or updated_payload.get("created_at")
            merged["updated_at"] = merged.get("updated_at") or updated_payload.get("updated_at")
            return jsonify(merged)

    rulesets = repo.load_rulesets()
    index, ruleset = _find_ruleset(rulesets, ruleset_id)
    if ruleset is None:
        return jsonify({"error": 'ruleset not found'}), 404

    updated = _normalize_ruleset_payload(body, existing=ruleset)
    updated['ruleset_id'] = ruleset_id
    updated['created_at'] = ruleset.get('created_at') or ruleset.get('createdAt')
    updated['updated_at'] = _now_iso()

    rulesets[index] = updated
    repo.save_rulesets(rulesets)
    resp = {"tenant_error": str(tenant_error)} if tenant_error else {}
    return jsonify({**updated, **resp})


@api_bp.delete('/rulesets/<ruleset_id>')
def delete_ruleset(ruleset_id):
    """룰셋 삭제."""
    tenant_id, _ = _get_tenant_rule(ruleset_id)
    tenant_error: Exception | None = None
    if tenant_id:
        try:
            _tenant_fetch_json(
                f"/tenants/{tenant_id}/access-controls/{ruleset_id}",
                method="DELETE",
            )
            return jsonify({"deleted": ruleset_id, "tenant_id": tenant_id})
        except Exception as e:
            tenant_error = e

    rulesets = repo.load_rulesets()
    index, ruleset = _find_ruleset(rulesets, ruleset_id)
    if ruleset is None:
        return jsonify({"error": 'ruleset not found'}), 404

    rulesets.pop(index)
    repo.save_rulesets(rulesets)
    resp = {"tenant_error": str(tenant_error)} if tenant_error else {}
    return jsonify({**{"deleted": ruleset_id}, **resp})


@api_bp.get('/rulesets/groups')
def list_ruleset_groups():
    """룰셋 그룹(tenant) 목록을 반환한다."""
    tenant_rulesets, groups = _load_tenant_rulesets()
    if groups is not None:
        return jsonify(groups)

    # fallback: 환경 변수로 정의된 tenant 목록 사용
    fallback_groups = [
        {
            "id": item.get("value"),
            "name": item.get("label") or item.get("value"),
            "description": f"Tenant: {item.get('value')}",
        }
        for item in TENANT_CHOICES
    ]
    return jsonify(fallback_groups)


@api_bp.get('/rulesets/tenants')
def list_ruleset_tenants():
    """UI에서 테넌트 선택을 위해 테넌트 목록 반환."""
    try:
        tenants = _fetch_json(f"{TENANT_API_URL}/tenants") or []
        # tenants API는 id/name/description을 리턴
        return jsonify(
            [
                {
                    "value": t.get("id"),
                    "label": t.get("name") or t.get("id"),
                    "description": t.get("description") or "",
                }
                for t in tenants
                if t.get("id")
            ]
        )
    except Exception:
        return jsonify(TENANT_CHOICES)


@api_bp.get('/rulesets/users')
def list_ruleset_users():
    """jwt-server Redis에 저장된 사용자 목록을 반환한다."""
    users = list_users(redis_url=USER_REDIS_URL)
    # 안전하게 최소 필드만 반환
    sanitized = [
        {
            "email": u.get("email"),
            "name": u.get("name") or u.get("email"),
            "title": u.get("title") or "",
            "tenants": u.get("tenants") or [],
        }
        for u in users
        if u.get("email")
    ]
    return jsonify(sanitized)


@api_bp.put('/rulesets/groups/<tenant_id>/<group_id>/members')
def update_group_members(tenant_id: str, group_id: str):
    """선택한 그룹의 멤버 목록을 jwt-server에 반영."""
    body = request.get_json(silent=True) or {}
    members = body.get("members")
    if not isinstance(members, list) or any(not isinstance(m, str) for m in members):
        return jsonify({"error": "members must be list of strings"}), 400

    url = f"{TENANT_API_URL}/tenants/{tenant_id}/groups/{group_id}/members"
    try:
        _fetch_json(
            url,
            method="PUT",
            body=json.dumps({"members": members}).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
    except Exception as e:
        return jsonify({"error": f"failed to update members: {e}"}), 502

    return jsonify({"group_id": group_id, "members": members})


@api_bp.post('/rulesets/groups')
def create_group():
    """???? ?? ??? ????."""
    auth_resp = require_jwt()
    if auth_resp:
        return auth_resp

    body = request.get_json(silent=True) or {}
    tenant_id = (body.get("tenant_id") or "").strip()
    tenant_name = (body.get("tenant_name") or "").strip()
    tenant_desc = (body.get("tenant_description") or "").strip()
    group_id = (body.get("id") or "").strip()
    name = body.get("name")
    description = body.get("description")
    actor = getattr(g, "jwt", {}).get("sub") or ""

    if not tenant_id or not group_id:
        _append_registry_log(
            actor=actor,
            method="CreateGroup",
            status=400,
            fail_stage="validate",
            message="tenant_id and id are required",
            extra={"tenant_id": tenant_id, "group_id": group_id},
        )
        return jsonify({"error": "tenant_id and id are required"}), 400

    # ???? ??? ?? ??
    try:
        existing = _fetch_json(f"{TENANT_API_URL}/tenants") or []
        if not any(t.get("id") == tenant_id for t in existing):
            _fetch_json(
                f"{TENANT_API_URL}/tenants",
                method="POST",
                body=json.dumps(
                    {
                        "id": tenant_id,
                        "name": tenant_name or name or tenant_id,
                        "description": tenant_desc or description or "",
                    }
                ).encode("utf-8"),
                headers={"Content-Type": "application/json"},
            )
    except Exception as e:
        _append_registry_log(
            actor=actor,
            method="CreateGroup",
            status=502,
            fail_stage="tenant.ensure",
            message=f"failed to ensure tenant: {e}",
            extra={"tenant_id": tenant_id, "group_id": group_id},
        )
        return jsonify({"error": f"failed to ensure tenant: {e}"}), 502

    url = f"{TENANT_API_URL}/tenants/{tenant_id}/groups"
    try:
        created = _fetch_json(
            url,
            method="POST",
            body=json.dumps(
                {"id": group_id, "name": name or group_id, "description": description}
            ).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
    except Exception as e:
        _append_registry_log(
            actor=actor,
            method="CreateGroup",
            status=502,
            fail_stage="group.create",
            message=f"failed to create group: {e}",
            extra={"tenant_id": tenant_id, "group_id": group_id},
        )
        return jsonify({"error": f"failed to create group: {e}"}), 502

    created["tenant_id"] = tenant_id
    _append_registry_log(
        actor=actor,
        method="CreateGroup",
        status=201,
        fail_stage="Success",
        message="group created",
        extra={"tenant_id": tenant_id, "group_id": group_id},
    )
    return jsonify(created), 201


@api_bp.put('/rulesets/groups/<tenant_id>/<group_id>')
def update_group(tenant_id: str, group_id: str):
    """그룹 이름/설명을 수정한다."""
    body = request.get_json(silent=True) or {}
    payload = {
        "name": body.get("name"),
        "description": body.get("description"),
    }
    try:
        updated = _tenant_fetch_json(
            f"/tenants/{tenant_id}/groups/{group_id}",
            method="PUT",
            body=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
    except Exception as e:
        return jsonify({"error": f"failed to update group: {e}"}), 502
    return jsonify(updated)


@api_bp.delete('/rulesets/groups/<tenant_id>/<group_id>')
def delete_group(tenant_id: str, group_id: str):
    """그룹을 삭제한다."""
    try:
        resp = _tenant_fetch_json(
            f"/tenants/{tenant_id}/groups/{group_id}",
            method="DELETE",
        )
    except Exception as e:
        return (
            jsonify(
                {
                    "error": "failed to delete group",
                    "detail": str(e),
                    "tenant_id": tenant_id,
                    "group_id": group_id,
                }
            ),
            502,
        )
    return jsonify(resp)


@api_bp.get('/rulesets/agents/<path:agent_id>/tools')
def list_agent_tools(agent_id: str):
    """agent_id 기준으로 tool_id 목록을 반환한다."""
    agents = repo.load_agents()
    agent = next((a for a in agents if a.get("agent_id") == agent_id), None)
    if not agent:
        return jsonify({"error": "agent not found"}), 404
    tool_ids = tools_helper._extract_tool_ids(agent)
    return jsonify({"agent_id": agent_id, "tools": tool_ids})


@api_bp.get('/rulesets/allowed-template')
def get_allowed_template():
    """allowed_list 형태로 에이전트-툴 허용 목록을 반환한다."""
    author = request.args.get("author") or "security manager"
    tenant = request.args.get("tenant") or ""

    agents = repo.load_agents()
    allowed_list: list[dict] = []
    for agent in agents:
        if not isinstance(agent, dict):
            continue
        agent_id = agent.get("agent_id")
        card = agent.get("card")
        tools = _extract_tools_from_card(card)
        if agent_id and tools:
            allowed_list.append(
                {
                    "agent_id": agent_id,
                    "allowed_tools": tools,
                }
            )

    payload = {
        "template": "custom",
        "author": author,
        "tenant": tenant,
        "allowed_list": allowed_list,
    }
    return jsonify(payload)


@api_bp.get('/rulesets/tenant-template')
def get_tenant_allowed_template():
    """
    Tenants 서비스의 rulesets 응답(access_controls)을 변환해 allowed_list를 반환.

    - tenant 쿼리 필수
    - author 쿼리 선택(기본: security manager)
    - 기본적으로 action == 'deny' 인 룰도 포함(그룹 접근 허용 목록 관점으로 모두 수집)
    """
    tenant_id = (request.args.get("tenant") or "").strip()
    if not tenant_id:
        return jsonify({"error": "tenant is required"}), 400
    author = request.args.get("author") or "security manager"
    include_deny = True

    try:
        payload = _tenant_fetch_json(f"/tenants/{tenant_id}/rulesets")
    except Exception as e:
        return jsonify({"error": "failed to fetch tenant rulesets", "detail": str(e)}), 502

    access_controls = []
    if isinstance(payload, dict):
        ac = payload.get("access_controls")
        if isinstance(ac, list):
            access_controls = ac

    # Preserve the incoming order while de-duplicating per agent
    allowed_map: dict[str, list[str]] = {}
    for rule in access_controls:
        if not isinstance(rule, dict):
            continue
        if rule.get("type") != "tool_validation":
            continue
        if not rule.get("enabled", True):
            continue
        agent_id = rule.get("target_agent")
        agent_display = _short_agent_id(agent_id)
        tool_field = rule.get("tool_name")
        tools_field = rule.get("tool_names")
        tools: list[str] = []
        if isinstance(tools_field, list):
            tools = [t for t in tools_field if isinstance(t, str) and t.strip()]
        elif isinstance(tool_field, str) and tool_field.strip():
            parts = [p.strip() for p in tool_field.split(",") if p.strip()]
            tools = parts if parts else [tool_field.strip()]
        if not (isinstance(agent_id, str) and agent_id and tools):
            continue
        action = ""
        rules_block = rule.get("rules")
        if isinstance(rules_block, dict):
            action = str(rules_block.get("action") or "").strip().lower()
        if action == "deny" and not include_deny:
            continue
        key = agent_display or agent_id
        if key not in allowed_map:
            allowed_map[key] = []
        for tool_name in tools:
            if tool_name not in allowed_map[key]:
                allowed_map[key].append(tool_name)

    allowed_list = [
        {"agent_id": agent, "allowed_tools": tools}
        for agent, tools in allowed_map.items()
    ]

    payload = {
        "template": "custom",
        "author": author,
        "tenant": tenant_id,
        "allowed_list": allowed_list,
    }
    # Keep key order as declared above (Flask's JSON_SORT_KEYS defaults to True)
    return Response(json.dumps(payload, ensure_ascii=False), mimetype="application/json")
def _short_agent_id(agent_id: str) -> str:
    """Return a shortened, human-readable agent id."""
    if not isinstance(agent_id, str):
        return ""
    short = agent_id.rsplit(":", 1)[-1]
    short = re.sub(r"\.v\d.*$", "", short)
    return short or agent_id
