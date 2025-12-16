"""Tenant helper: env-based choices + remote tenant API (list/create/delete)."""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Iterable, List, Dict, Any, Set

_DEFAULT_CHOICES = [
    {"value": "customer-service", "label": "Customer Service"},
    {"value": "logistics", "label": "Logistics"},
]


def _load_env_tenants() -> List[dict]:
    raw_json = os.getenv("SOLUTION_TENANTS_JSON")
    if raw_json:
        try:
            data = json.loads(raw_json)
            choices = []
            for value in data:
                if isinstance(value, str) and value.strip():
                    slug = value.strip().lower()
                    choices.append({"value": slug, "label": slug})
            if choices:
                return choices
        except json.JSONDecodeError:
            pass

    raw = os.getenv("SOLUTION_TENANTS", "")
    items = []
    if isinstance(raw, str):
        for entry in raw.split(","):
            entry = entry.strip()
            if entry:
                items.append(entry)
    if items:
        return [{"value": item.lower(), "label": item} for item in items]

    return _DEFAULT_CHOICES


TENANT_CHOICES = _load_env_tenants()
_VALID_TENANTS = {item["value"] for item in TENANT_CHOICES}


def normalize_tenants(values: object, strict: bool = False) -> List[str]:
    """입력 데이터를 문자열 리스트로 정규화.
    
    Args:
        values: 정규화할 tenant 값 (str, list, 또는 기타)
        strict: True면 _VALID_TENANTS에 있는 것만 허용, False면 모든 유효한 문자열 허용
    """
    if isinstance(values, str):
        candidates: Iterable[object] = [values]
    elif isinstance(values, Iterable):
        candidates = values
    else:
        candidates = []

    normalized: List[str] = []
    seen = set()
    for value in candidates:
        if not isinstance(value, str):
            continue
        slug = value.strip().lower()
        if not slug:
            continue
        # strict=False면 모든 tenant 허용 (동적으로 생성된 tenant 지원)
        if strict and slug not in _VALID_TENANTS:
            continue
        if slug not in seen:
            normalized.append(slug)
            seen.add(slug)
    return normalized


def matches_allowed_tenants(record_tenants: object, allowed_tenants: Set[str]) -> bool:
    """Return True when the record can be seen by a caller with `allowed_tenants`."""
    normalized = normalize_tenants(record_tenants)
    if not normalized:
        # No tenant restriction means the agent is public
        return True
    if not allowed_tenants:
        # Caller has no tenant so they cannot see tenant-specific agents
        return False
    return any(tenant in allowed_tenants for tenant in normalized)


def extract_tenants(raw: object) -> List[str]:
    """payload 어디에 있든 tenant 정보를 찾아 정규화."""
    if isinstance(raw, dict):
        return normalize_tenants(raw.get("tenants"))
    if raw is None:
        return []
    return normalize_tenants(raw)


# --- Remote tenant API helpers (merged from tenant_add.py) ---

def _tenant_api_urls() -> List[str]:
    candidates = [
        os.getenv("TENANT_API_URL"),
        "http://jwt-server:8000",
        "http://host.docker.internal:8000",
        "http://localhost:8000",
    ]
    urls: List[str] = []
    for url in candidates:
        if url and url not in urls:
            urls.append(url)
    return urls


def _fetch_json(url: str, method: str = "GET", body: bytes | None = None, headers: Dict[str, str] | None = None):
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


def list_remote_tenants() -> List[Dict[str, Any]]:
    """TENANT_API_URL 후보들을 돌며 테넌트 목록을 반환."""
    last_err: Exception | None = None
    for base in _tenant_api_urls():
        try:
            tenants = _fetch_json(f"{base}/tenants") or []
            if isinstance(tenants, list):
                return tenants
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    return []


def create_remote_tenant(tenant_id: str, name: str | None = None, description: str | None = None) -> Dict[str, Any]:
    """테넌트를 생성한다. 이미 존재하면 RuntimeError를 던진다."""
    payload = {
        "id": tenant_id,
        "name": name or tenant_id,
        "description": description or "",
    }
    body = json.dumps(payload).encode("utf-8")
    last_err: Exception | None = None
    for base in _tenant_api_urls():
        try:
            return _fetch_json(
                f"{base}/tenants",
                method="POST",
                body=body,
                headers={"Content-Type": "application/json"},
            )
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise RuntimeError("No tenant API URL reachable")


def update_remote_tenant(tenant_id: str, name: str | None = None, description: str | None = None) -> Dict[str, Any]:
    """테넌트 이름/설명을 수정한다(tenant API가 PUT을 지원한다고 가정)."""
    payload = {}
    if name is not None:
        payload["name"] = name
    if description is not None:
        payload["description"] = description
    if not payload:
        raise ValueError("nothing to update")

    body = json.dumps(payload).encode("utf-8")
    last_err: Exception | None = None
    for base in _tenant_api_urls():
        try:
            return _fetch_json(
                f"{base}/tenants/{tenant_id}",
                method="PUT",
                body=body,
                headers={"Content-Type": "application/json"},
            )
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise RuntimeError("No tenant API URL reachable")


def delete_remote_tenant(tenant_id: str) -> Dict[str, Any]:
    """테넌트를 삭제한다(tenant API가 DELETE를 지원하는 경우)."""
    last_err: Exception | None = None
    for base in _tenant_api_urls():
        try:
            return _fetch_json(
                f"{base}/tenants/{tenant_id}",
                method="DELETE",
            )
        except Exception as e:
            last_err = e
            continue
    if last_err:
        raise last_err
    raise RuntimeError("No tenant API URL reachable")


if __name__ == "__main__":
    import sys

    args = sys.argv[1:]
    if args:
        cmd = args[0]
        if cmd == "create" and len(args) >= 2:
            tid = args[1]
            tname = args[2] if len(args) >= 3 else None
            tdesc = args[3] if len(args) >= 4 else None
            try:
                created = create_remote_tenant(tid, tname, tdesc)
                print(f"[OK] created tenant: {created}")
            except Exception as e:
                print(f"[ERR] failed to create tenant '{tid}': {e}")
        elif cmd == "update" and len(args) >= 2:
            tid = args[1]
            tname = args[2] if len(args) >= 3 else None
            tdesc = args[3] if len(args) >= 4 else None
            try:
                updated = update_remote_tenant(tid, tname, tdesc)
                print(f"[OK] updated tenant: {updated}")
            except Exception as e:
                print(f"[ERR] failed to update tenant '{tid}': {e}")
        elif cmd == "delete" and len(args) >= 2:
            tid = args[1]
            try:
                resp = delete_remote_tenant(tid)
                print(f"[OK] deleted tenant '{tid}': {resp}")
            except Exception as e:
                print(f"[ERR] failed to delete tenant '{tid}': {e}")
        else:
            print("Usage:")
            print("  python -m app.core.tenants            # list tenants")
            print("  python -m app.core.tenants create <id> [name] [description]")
            print("  python -m app.core.tenants update <id> [name] [description]")
            print("  python -m app.core.tenants delete <id>")
    else:
        try:
            tenants = list_remote_tenants()
            print(f"[INFO] tenant count: {len(tenants)}")
            for t in tenants:
                print(f" - {t.get('id')}: {t.get('name')} ({t.get('description')})")
        except Exception as e:
            print("Failed to list tenants:", e)
