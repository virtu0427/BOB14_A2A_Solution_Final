import os
import json
from datetime import datetime
from typing import Optional
from zoneinfo import ZoneInfo

# --- 프로젝트 데이터/로그 파일 경로 ---
DATA_ROOT_OVERRIDE = os.environ.get("SOLUTION_DATA_ROOT")
_ROOT_DIR = (
    os.path.abspath(DATA_ROOT_OVERRIDE)
    if DATA_ROOT_OVERRIDE
    else os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
)
_DATA_DIR = os.path.join(_ROOT_DIR, 'data')
_LOG_DIR = os.path.join(_DATA_DIR, 'redisDB')
# 에이전트 로그 전용 파일명 (레거시, 레지스트리 로그는 repo.append_registry_log 사용)
_LOG_FILE = os.path.join(_LOG_DIR, 'a-logs.json')
_OLD_LOG_FILE = os.path.join(_DATA_DIR, 'log.json')
_OLD_LOG_FILE_LEGACY = os.path.join(_LOG_DIR, 'logs.json')
MAX_LOG_ENTRIES = int(os.environ.get("SOLUTION_MAX_LOG_ENTRIES", "500"))


def _infer_fail_stage(message: str, ok: bool) -> str:
    """메시지/상태를 기반으로 검증 단계를 추론."""
    msg = (message or "").lower()
    if ok:
        return "Success"
    if any(code in msg for code in ["401", "403", "token", "토큰", "authorization"]):
        if "403" in msg or "권한" in msg:
            return "토큰 권한 확인"
        return "JWT 토큰 여부"
    if any(code in msg for code in ["413", "422", "400", "498", "json", "스키마", "schema", "필수", "시그니처"]):
        if "413" in msg or "바이트" in msg:
            return "스키마 검증(전체 바이트)"
        if "498" in msg or "signature" in msg or "시그니처" in msg:
            return "스키마 검증(시그니처)"
        return "스키마 검증"
    if any(keyword in msg for keyword in ["정책", "policy", "도메인", "domain", "url", "중복", "duplicate", "409"]):
        return "정책 검사"
    if any(keyword in msg for keyword in ["extension", "노드 개수", "node", "422"]):
        return "Extension 필드 검사"
    return ""


def _normalize_method(method: str | None):
    crud_map = {'c': 'Create', 'r': 'Read', 'u': 'Update', 'd': 'Delete'}
    if method is None:
        return ''
    key = str(method).strip().lower()
    return crud_map.get(key, method)


def _infer_method_from_message(message: str | None) -> str:
    """메시지에서 CRUD 단축(c/r/u/d)을 추론."""
    if not message:
        return ''
    msg = str(message).lower()
    if any(k in msg for k in ["삭제", "delete", "remove"]):
        return 'd'
    if any(k in msg for k in ["수정", "update", "modify"]):
        return 'u'
    if any(k in msg for k in ["조회", "검색", "read", "list", "get"]):
        return 'r'
    if any(k in msg for k in ["등록", "추가", "생성", "create", "add"]):
        return 'c'
    return ''


def _ensure_log_file():
    """data/redisDB/logs.json 파일을 생성 (기존 data/log.json 있으면 가져옴)."""
    os.makedirs(_LOG_DIR, exist_ok=True)
    if not os.path.exists(_LOG_FILE):
        # migrate from old location if present
        if os.path.exists(_OLD_LOG_FILE_LEGACY):
            try:
                with open(_OLD_LOG_FILE_LEGACY, 'r', encoding='utf-8') as src:
                    content = src.read()
                with open(_LOG_FILE, 'w', encoding='utf-8') as dst:
                    dst.write(content)
                return
            except Exception:
                pass
        if os.path.exists(_OLD_LOG_FILE):
            try:
                with open(_OLD_LOG_FILE, 'r', encoding='utf-8') as src:
                    content = src.read()
                with open(_LOG_FILE, 'w', encoding='utf-8') as dst:
                    dst.write(content)
                return
            except Exception:
                pass
        with open(_LOG_FILE, 'w', encoding='utf-8') as f:
            f.write('[]')


def _k_time_label(dt: datetime) -> str:
    return f"{dt.hour:02d}시 {dt.minute:02d}분 {dt.second:02d}초"


def _now_kst() -> datetime:
    """현재 한국 표준시(UTC+9)로 시간을 반환."""
    try:
        return datetime.now(ZoneInfo("Asia/Seoul"))
    except Exception:
        # zoneinfo 가 없거나 실패하면 서버 로컬 시간으로 대체
        return datetime.now()


def _request_ip() -> Optional[str]:
    """Flask request 컨텍스트에서 클라이언트 IP 추출 (가능한 경우)."""
    try:
        from flask import request  # type: ignore

        if not request:
            return None
        forwarded = request.headers.get('X-Forwarded-For')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return request.remote_addr
    except Exception:
        return None


def append_log(
    message: str,
    ok: bool,
    when: datetime | None = None,
    *,
    capture_client_ip: bool = False,
    client_ip: str | None = None,
    fail_stage: str | None = None,
    status: int | None = None,
):
    """플랫폼/공용 로그를 레지스트리 로그(r-logs.json)에 추가."""
    try:
        when = when or _now_kst()
        if when.tzinfo is None:
            try:
                when = when.replace(tzinfo=ZoneInfo("Asia/Seoul"))
            except Exception:
                pass
        ip = client_ip or (_request_ip() if capture_client_ip else None)
        entry = {
            'message': str(message or ''),
            'ok': bool(ok),
            'timeIso': when.isoformat(),
            'timeText': _k_time_label(when),
        }
        if ip:
            entry['clientIp'] = ip
        # 공통 스키마 필드 보강 (요청자/동작/상태/검증단계/메시지)
        try:
            from flask import g  # type: ignore

            actor = getattr(g, "jwt", {}).get("sub") if g else None
        except Exception:
            actor = None
        entry['timestamp'] = entry.get('timeIso') or when.isoformat()
        entry['actor'] = actor or ''
        method_code = entry.get('method') or _infer_method_from_message(message)
        entry['method'] = _normalize_method(method_code)
        if status is None:
            entry['status'] = 200 if ok else 500
        else:
            entry['status'] = int(status)
        stage = fail_stage or entry.get('fail_stage') or _infer_fail_stage(message, ok)
        entry['fail_stage'] = stage
        entry['source'] = 'registry'

        # r-logs.json에 기록
        try:
            from . import repo  # type: ignore

            repo.append_registry_log(entry)
        except Exception:
            # 로깅 실패가 주 흐름을 막지 않도록 함
            pass
    except Exception:
        # 로깅 중 오류가 발생해도 앱 흐름은 유지
        pass
