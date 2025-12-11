import copy
import os
import json
from datetime import datetime, timezone, timedelta

try:
    import redis as _redis_module  # type: ignore
except Exception:  # pragma: no cover - redis is optional
    _redis_module = None

_REDIS_CLIENT = None
_REDIS_CLIENT_FAILED = False

def _get_kst_now():
    """현재 한국 표준시(UTC+9)를 반환."""
    kst = timezone(timedelta(hours=9))
    return datetime.now(kst)

# --- 프로젝트 루트의 solution/data 디렉터리 경로 (SOLUTION_DATA_ROOT 지원) ---
DATA_ROOT_OVERRIDE = os.environ.get('SOLUTION_DATA_ROOT')
_ROOT_DIR = (
    os.path.abspath(DATA_ROOT_OVERRIDE)
    if DATA_ROOT_OVERRIDE
    else os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
)
_DATA_DIR = os.path.join(_ROOT_DIR, 'data')
_AGENTS_DIR = os.path.join(_DATA_DIR, 'redisDB')
AGENTS_FILE = os.path.join(_AGENTS_DIR, 'agents.json')
REGISTRY_LOG_FILE = os.path.join(_AGENTS_DIR, 'r-logs.json')
RULESETS_FILE = os.path.join(_AGENTS_DIR, 'rulesets.json')
_OLD_RULESETS_FILE = os.path.join(_DATA_DIR, 'rulesets.json')
REGISTRY_MAX_LOG_ENTRIES = int(os.environ.get('SOLUTION_MAX_LOG_ENTRIES', '500'))
_AGENTS_REDIS_KEY = os.environ.get('AGENTS_REDIS_KEY', 'agents')
_REGISTRY_LOGS_REDIS_KEY = os.environ.get('REGISTRY_LOGS_REDIS_KEY', 'r-logs')
_CRUD_MAP = {'c': 'Create', 'r': 'Read', 'u': 'Update', 'd': 'Delete'}
_CRUD_KEYWORDS = {
    'c': ['create', '생성', '등록', '추가'],
    'd': ['delete', 'remove', '삭제'],
    'u': ['update', 'modify', '수정'],
    'r': ['read', '조회', '검색', 'list', 'get'],
}

DEFAULT_RULESETS = [
    {
        "ruleset_id": "prompt_validation_customer",
        "name": "고객 정보 프롬프트 검증",
        "type": "prompt_validation",
        "description": "고객 요청 프롬프트가 기밀 정보를 포함하지 않도록 검증합니다.",
        "enabled": True,
        "system_prompt": "당신은 고객 정보 검색을 담당하는 에이전트입니다. 민감한 고객 데이터를 외부에 노출하지 마세요.",
        "model": "gemini-2.0-flash",
        "created_at": "2025-11-18T10:30:00Z",
        "updated_at": "2025-11-18T10:30:00Z",
    },
    {
        "ruleset_id": "prompt_validation_delivery",
        "name": "배송 검증 프롬프트",
        "type": "prompt_validation",
        "description": "배송 업데이트 관련 질문만 처리하도록 프롬프트를 제한합니다.",
        "enabled": True,
        "system_prompt": "당신은 배송 현황을 요약하는 에이전트입니다. 주문 번호 외의 개인 정보는 요청하지 마세요.",
        "model": "gemini-2.0",
        "created_at": "2025-11-18T10:45:00Z",
        "updated_at": "2025-11-18T10:45:00Z",
    },
    {
        "ruleset_id": "tool_validation_integration",
        "name": "툴 호출 검증",
        "type": "tool_validation",
        "description": "허용된 에이전트와 파라미터인지 확인합니다.",
        "enabled": True,
        "tool_name": "call_remote_agent",
        "rules": {
            "allowed_agents": [
                "oneth.ai#agent:CustomerAgent.v1.0.0",
                "oneth.ai#agent:Delivery Agent.v1.0.0"
            ],
            "max_calls_per_minute": 20
        },
        "created_at": "2025-11-18T11:00:00Z",
        "updated_at": "2025-11-18T11:00:00Z",
    },
    {
        "ruleset_id": "response_filtering_default",
        "name": "응답 필터링 기본룰",
        "type": "response_filtering",
        "description": "비밀번호나 토큰같이 민감한 단어를 검출하여 마스킹합니다.",
        "enabled": True,
        "blocked_keywords": ["secret", "password", "jwt", "credentials"],
        "created_at": "2025-11-18T11:05:00Z",
        "updated_at": "2025-11-18T11:05:00Z",
    },
]


def _get_redis_client():
    global _REDIS_CLIENT, _REDIS_CLIENT_FAILED
    if _REDIS_CLIENT_FAILED:
        return None
    if _REDIS_CLIENT is not None:
        return _REDIS_CLIENT
    if _redis_module is None:
        return None
    redis_url = os.environ.get('REDIS_URL')
    if not redis_url:
        return None
    try:
        client = _redis_module.from_url(redis_url, decode_responses=True)
    except Exception:
        _REDIS_CLIENT_FAILED = True
        return None
    _REDIS_CLIENT = client
    return _REDIS_CLIENT


def _load_list_from_redis(key):
    client = _get_redis_client()
    if not client:
        return None
    try:
        raw = client.get(key)
        if raw is None:
            return None
        payload = json.loads(raw)
        if isinstance(payload, list):
            return payload
    except Exception:
        return None
    return None


def _save_list_to_redis(key, data):
    client = _get_redis_client()
    if not client:
        return
    if isinstance(data, list):
        payload = data
    else:
        try:
            payload = list(data)
        except Exception:
            payload = [data]
    try:
        client.set(key, json.dumps(payload, ensure_ascii=False))
    except Exception:
        pass


def _filter_deleted_agents(data):
    if not isinstance(data, list):
        return []
    return [a for a in data if not (isinstance(a, dict) and a.get("status") == "Deleted")]


def _ensure_data_dir():
    os.makedirs(_DATA_DIR, exist_ok=True)
    os.makedirs(_AGENTS_DIR, exist_ok=True)  # data/redisDB 경로에 에이전트 저장


def ensure_seed():
    """data 디렉터리 경로를 만든 뒤 룰셋 파일을 생성."""
    _ensure_data_dir()
    if not os.path.exists(RULESETS_FILE):
        try:
            if os.path.exists(_OLD_RULESETS_FILE):
                with open(_OLD_RULESETS_FILE, 'r', encoding='utf-8') as src:
                    data = json.load(src)
                with open(RULESETS_FILE, 'w', encoding='utf-8') as dst:
                    json.dump(data, dst, ensure_ascii=False, indent=2)
            else:
                # 기본 시드 대신 빈 리스트로 생성해 초기 상태에서는 아무것도 노출하지 않는다.
                with open(RULESETS_FILE, 'w', encoding='utf-8') as f:
                    json.dump([], f, ensure_ascii=False, indent=2)
        except Exception:
            with open(RULESETS_FILE, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)


def load_json(path: str, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: str, data):
    _ensure_data_dir()
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def load_agents():
    ensure_seed()
    redis_data = _load_list_from_redis(_AGENTS_REDIS_KEY)
    if redis_data is not None:
        return _filter_deleted_agents(redis_data)
    data = load_json(AGENTS_FILE, [])
    return _filter_deleted_agents(data)


def save_agents(data):
    if isinstance(data, list):
        _save_list_to_redis(_AGENTS_REDIS_KEY, data)


def load_logs():
    """기존 호환성용: 레지스트리 로그만 반환."""
    ensure_seed()
    registry_logs = load_registry_logs()
    return registry_logs


def save_logs(data):
    """기존 호환성용: data를 AGENT 로그 파일에만 기록."""
    save_agent_logs(data)


def load_agent_logs():
    """에이전트 로그 사용 중지: 항상 빈 배열 반환."""
    ensure_seed()
    return []


def save_agent_logs(data):
    """에이전트 로그 사용 중지: 기록하지 않음."""
    return None


def _normalize_registry_logs(raw):
    return [_normalize_registry_log_entry(entry) for entry in raw if isinstance(entry, dict)]


def load_registry_logs():
    ensure_seed()
    redis_raw = _load_list_from_redis(_REGISTRY_LOGS_REDIS_KEY)
    from_redis = redis_raw is not None
    raw = redis_raw if from_redis else load_json(REGISTRY_LOG_FILE, [])
    normalized = _normalize_registry_logs(raw)
    if from_redis:
        if normalized != raw:
            _save_list_to_redis(_REGISTRY_LOGS_REDIS_KEY, normalized)
        return normalized
    return normalized


def save_registry_logs(data):
    normalized = _normalize_registry_logs(data)
    _save_list_to_redis(_REGISTRY_LOGS_REDIS_KEY, normalized)

def _infer_method(entry: dict) -> str:
    """method가 비어있을 때 메시지/동작 힌트로 CRUD 코드를 추론."""
    def _from_text(text: str) -> str:
        lower = text.lower()
        for code, keywords in _CRUD_KEYWORDS.items():
            if any(word in lower for word in keywords):
                return code
        return ''

    texts: list[str] = []
    for key in ('method', 'operation', 'op', 'action', 'message'):
        val = entry.get(key)
        if val:
            texts.append(str(val))
    extra = entry.get('extra')
    if isinstance(extra, dict):
        for key in ('method', 'operation', 'op', 'action', 'message'):
            val = extra.get(key)
            if val:
                texts.append(str(val))
    for t in texts:
        code = _from_text(t)
        if code:
            return code
    return ''


def _normalize_registry_log_entry(entry: dict) -> dict:
    """레지스트리/에이전트 로그 필드를 UI가 기대하는 스키마로 정규화."""
    if not isinstance(entry, dict):
        return {}
    try:
        now_iso = _get_kst_now().isoformat()
    except Exception:
        now_iso = datetime.now().isoformat()

    # source 판별: 명시적으로 지정되었거나 에이전트 관련 필드가 있으면 agent
    source = entry.get('source', '')
    if not source:
        # policy_enforcement.py에서 오는 로그 판별
        if entry.get('agent_id') or entry.get('policy_type') or entry.get('verdict'):
            source = 'agent'
        else:
            source = 'registry'

    raw_status = entry.get('status')
    try:
        status = int(raw_status)
    except Exception:
        # verdict 기반 상태 추론 (에이전트 로그용)
        verdict = str(entry.get('verdict') or '').upper()
        if verdict in ('PASS', 'SAFE', 'ALLOWED'):
            status = 200
        elif verdict in ('VIOLATION', 'BLOCKED', 'DENIED'):
            status = 403
        elif entry.get('ok') is True:
            status = 200
        elif entry.get('ok') is False:
            status = 500
        else:
            status = raw_status if raw_status is not None else None

    method_raw = (
        entry.get('method')
        or entry.get('operation')
        or entry.get('op')
        or _infer_method(entry)
        or ''
    )
    method_norm = _CRUD_MAP.get(str(method_raw).strip().lower(), method_raw)
    
    # 메시지 구성: reason이 있으면 reason 사용 (policy_enforcement.py 호환)
    message = entry.get('message') or entry.get('reason') or entry.get('detail') or ''
    
    normalized = {
        'timestamp': (
            entry.get('timestamp')
            or entry.get('timeIso')
            or entry.get('time_iso')
            or entry.get('time')
            or now_iso
        ),
        'actor': str(entry.get('actor') or entry.get('user') or ''),
        'method': str(method_norm),
        'status': status,
        'fail_stage': str(entry.get('fail_stage') or entry.get('stage') or ''),
        'message': str(message),
        'source': source,
    }
    
    # 공통 필드
    for key in ('tenant_id', 'group_id', 'client_ip', 'clientIp', 'ip'):
        if key in entry and entry.get(key) is not None:
            normalized[key] = entry.get(key)
    
    # 에이전트 로그 전용 필드 (policy_enforcement.py 스키마)
    if source == 'agent':
        normalized['agent_id'] = str(entry.get('agent_id') or '')
        normalized['policy_type'] = str(entry.get('policy_type') or '')
        normalized['verdict'] = str(entry.get('verdict') or '')
        normalized['tool_name'] = str(entry.get('tool_name') or '')
        normalized['target_agent'] = str(entry.get('target_agent') or entry.get('destination_agent') or '')
        # tool_args는 dict일 수 있음
        if entry.get('tool_args'):
            normalized['tool_args'] = entry.get('tool_args')
        # prompt (prompt_validation용)
        if entry.get('prompt'):
            normalized['prompt'] = str(entry.get('prompt'))
    
    if 'extra' in entry and entry.get('extra') is not None:
        normalized['extra'] = entry.get('extra')
    return normalized


def _normalize_agent_log_entry(entry: dict) -> dict:
    """에이전트/플랫폼 로그도 공통 스키마 필드를 보강한다."""
    if not isinstance(entry, dict):
        return {}
    try:
        now_iso = _get_kst_now().isoformat()
    except Exception:
        now_iso = datetime.now().isoformat()

    raw_status = entry.get('status')
    try:
        status = int(raw_status)
    except Exception:
        # ok -> 200, False -> 500 정도의 기본값을 부여
        if entry.get('ok') is True:
            status = 200
        elif entry.get('ok') is False:
            status = 500
        else:
            status = None

    normalized = dict(entry)
    normalized['timestamp'] = (
        entry.get('timestamp')
        or entry.get('timeIso')
        or entry.get('time_iso')
        or entry.get('time')
        or now_iso
    )
    normalized['actor'] = str(entry.get('actor') or entry.get('user') or '')
    method_raw = (
        entry.get('method')
        or entry.get('policy')
        or entry.get('action')
        or _infer_method(entry)
        or ''
    )
    normalized['method'] = str(_CRUD_MAP.get(str(method_raw).strip().lower(), method_raw))
    normalized['status'] = status
    normalized['fail_stage'] = str(entry.get('fail_stage') or entry.get('stage') or '')
    normalized['message'] = str(entry.get('message') or entry.get('detail') or '')
    normalized['source'] = entry.get('source') or 'agent'
    return normalized


def append_registry_log(entry: dict):
    """data/redisDB/r-logs.json에 스키마를 맞춰 append."""
    normalized = _normalize_registry_log_entry(entry)
    if not normalized:
        return
    logs = load_registry_logs()
    logs.insert(0, normalized)
    if isinstance(logs, list) and len(logs) > REGISTRY_MAX_LOG_ENTRIES:
        del logs[REGISTRY_MAX_LOG_ENTRIES:]
    save_registry_logs(logs)


def load_rulesets():
    ensure_seed()
    return load_json(RULESETS_FILE, copy.deepcopy(DEFAULT_RULESETS))


def save_rulesets(data):
    save_json(RULESETS_FILE, data)
