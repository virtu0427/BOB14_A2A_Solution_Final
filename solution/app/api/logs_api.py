"""레지스트리 로그 및 통계 API."""

from flask import jsonify, request

from . import api_bp
from ..core import repo
from ..core.tenants import TENANT_CHOICES


def _get_group_count() -> int:
    """UI와 동일한 로직으로 그룹 개수를 계산한다."""
    try:
        from .rulesets_api import _load_tenant_rulesets  # 지연 import로 순환 참조 회피
    except Exception:
        return 0

    try:
        _, groups = _load_tenant_rulesets()
        if groups is not None:
            return len(groups)
    except Exception:
        pass

    # 테넌트 API 실패 시 rulesets_api와 동일하게 TENANT_CHOICES를 fallback으로 사용
    try:
        return len(TENANT_CHOICES)
    except Exception:
        return 0


def _normalize_log_entry(entry):
    timestamp = entry.get('timestamp') or entry.get('timeIso') or entry.get('time_iso') or entry.get('time')
    agent_id = entry.get('agent_id') or entry.get('agent') or entry.get('source_agent') or ''
    verdict = entry.get('verdict')
    if not verdict:
        if entry.get('ok') is True:
            verdict = 'pass'
        elif entry.get('ok') is False:
            verdict = 'violation'
        else:
            verdict = ''
    policy_type = entry.get('policy_type') or entry.get('policy') or ''
    target_agent = entry.get('target_agent') or entry.get('destination_agent') or ''
    plugin = entry.get('plugin') or entry.get('plugin_name') or entry.get('tool') or ''
    source = entry.get('source')
    if not source:
        source = 'agent' if agent_id or policy_type or plugin or target_agent else 'registry'
    return {
        'timestamp': timestamp,
        'agent_id': agent_id,
        'message': entry.get('message') or entry.get('action') or '',
        'verdict': verdict,
        'policy_type': policy_type,
        'target_agent': target_agent,
        'plugin': plugin,
        'client_ip': entry.get('clientIp') or entry.get('client_ip') or entry.get('ip'),
        'source': source,
        # registry-specific fields
        'actor': entry.get('actor') or entry.get('user') or '',
        'method': entry.get('method') or entry.get('operation') or entry.get('op') or '',
        'status': entry.get('status'),
        'fail_stage': entry.get('fail_stage') or entry.get('stage') or '',
        'extra': entry,
    }


def _parse_limit():
    raw = request.args.get('limit')
    if raw is None:
        return None
    try:
        value = int(raw)
        if value <= 0:
            return None
        return value
    except (ValueError, TypeError):
        return None


@api_bp.get('/logs')
def get_logs():
    """정규화된 로그 배열을 반환하며 limit 쿼리를 지원합니다."""
    limit = _parse_limit()
    logs = repo.load_logs()
    normalized = [_normalize_log_entry(entry) for entry in logs]
    normalized.sort(
        key=lambda item: item.get('timestamp') or '',
        reverse=True,
    )
    if limit is not None:
        normalized = normalized[:limit]
    return jsonify(normalized)


@api_bp.post('/logs')
def append_log_entry():
    """로그 항목을 직접 추가(파일 append)."""
    body = request.get_json(silent=True) or {}
    message = body.get('message') if isinstance(body.get('message'), str) else ''
    if not message:
        return jsonify({"error": 'message is required'}), 400

    source = (body.get('source') or 'agent').lower()
    time_iso = body.get('timeIso') if isinstance(body.get('timeIso'), str) else None
    time_text = body.get('timeText') if isinstance(body.get('timeText'), str) else ''

    entry = dict(body)
    entry['message'] = message
    entry['source'] = 'registry' if source == 'registry' else 'agent'
    entry['timeIso'] = time_iso
    entry['timeText'] = time_text

    try:
        # 모든 로그를 r-logs.json에 기록
        repo.append_registry_log(entry)
    except Exception:
        return jsonify({"error": "failed to append log"}), 500
    return jsonify({"log": entry}), 201


@api_bp.get('/stats')
def get_stats():
    """대시보드용 간단한 통계 정보를 반환합니다."""
    agents = repo.load_agents()
    rulesets = repo.load_rulesets()
    logs = repo.load_logs()
    normalized_logs = [_normalize_log_entry(entry) for entry in logs]
    violation_verdicts = {'violation', 'blocked'}
    recent_violations = sum(
        1
        for entry in normalized_logs
        if (entry.get('verdict') or '').lower() in violation_verdicts
    )
    return jsonify(
        {
            "total_agents": len(agents),
            "total_rulesets": len(rulesets),
            "total_groups": _get_group_count(),
            "total_events": len(logs),
            "recent_violations": recent_violations,
        }
    )
