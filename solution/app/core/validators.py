"""
AgentCard 전용 스키마 검증 도구.

1. 입력 크기 검사 (비정상적으로 큰 Agent Card 차단)
2. a2a.json + AgentCard-policy.json 기반 JSON Schema 검증
3. 정책 모듈 / 서명 모듈에서 사용할 핵심 필드 추출
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Optional, Union

try:
    # --- 선택적 환경 로더 (env_loader 사용 시) ---
    from env_loader import load_env  # type: ignore
    load_env()
except Exception:
    # --- 간단한 .env 로더 (solution/.env 우선) ---
    import pathlib

    def _load_dotenv_fallback() -> None:
        try:
            here = pathlib.Path(__file__).resolve()
            dot_env = here.parents[2] / ".env"  # solution/.env
            if not dot_env.exists():
                return
            for line in dot_env.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if "=" not in line:
                    continue
                k, v = line.split("=", 1)
                k = k.strip()
                v = v.strip().strip('"').strip("'")
                if k and v and k not in os.environ:
                    os.environ[k] = v
        except Exception:
            pass

    _load_dotenv_fallback()

    try: 
        from jsonschema import Draft7Validator, RefResolver, ValidationError 
    except Exception: 
        Draft7Validator = object # type: ignore 
        RefResolver = object # type: ignore 
        class ValidationError(Exception): # type: ignore 
            pass


# --- 스키마 파일 및 크기 제한 설정 ---
# 기본 최대 바이트(환경변수로 조정 가능)
DEFAULT_MAX_AGENT_CARD_BYTES = int(os.environ.get("AGENT_CARD_MAX_BYTES", "262144"))  # 256 KiB

# 현재 파일과 같은 디렉터리에 위치한 스키마 파일 경로
A2A_SCHEMA_PATH = Path(__file__).with_name("a2a.json")
POLICY_SCHEMA_PATH = Path(__file__).with_name("AgentCard-policy.json")


@dataclass(frozen=True)
class AgentCardParseResult:
    """스키마 검증 이후 추출한 핵심 필드."""

    card: Dict[str, Any]
    name: Optional[str]
    url: Optional[str]
    extensions: Any
    signatures: Any


class AgentCardSchemaError(Exception):
    """스키마 검증 실패를 표현하는 공통 예외."""


class AgentCardSchema:
    """Agent Card 스키마 검증 및 필드 추출기."""

    def __init__(
        self,
        base_schema_path: Path = A2A_SCHEMA_PATH,
        policy_schema_path: Path = POLICY_SCHEMA_PATH,
        max_bytes: int = DEFAULT_MAX_AGENT_CARD_BYTES,
    ) -> None:
        self.base_schema_path = base_schema_path
        self.policy_schema_path = policy_schema_path
        self.max_bytes = max_bytes
        self._validator = self._build_validator()

    @staticmethod
    @lru_cache(maxsize=1)
    def _load_schemas(base_path: str, policy_path: str) -> Dict[str, Any]:
        base = Path(base_path)
        policy = Path(policy_path)
        if not policy.exists():
            raise FileNotFoundError(f"Policy schema not found: {policy}")
        if not base.exists():
            raise FileNotFoundError(f"A2A schema not found: {base}")
        with base.open("r", encoding="utf-8") as fp:
            base_schema = json.load(fp)
        with policy.open("r", encoding="utf-8") as fp:
            policy_schema = json.load(fp)
        return {
            "base": base_schema,
            "policy": policy_schema,
            "base_uri": policy.resolve().as_uri(),
            "store": {
                base.resolve().as_uri(): base_schema,
                policy.resolve().as_uri(): policy_schema,
            },
        }

    def _build_validator(self) -> Draft7Validator:
        """JSON Schema Validator 인스턴스를 초기화."""
        payload = self._load_schemas(
            str(self.base_schema_path.resolve()),
            str(self.policy_schema_path.resolve()),
        )
        resolver = RefResolver(
            base_uri=payload["base_uri"],
            referrer=payload["policy"],
            store=payload["store"],
        )
        return Draft7Validator(payload["policy"], resolver=resolver)  # type: ignore[arg-type]

    def ensure_size_limit(self, payload: Union[int, bytes, bytearray]) -> None:
        """Agent Card 원본 크기가 제한을 초과하지 않는지 확인."""
        if isinstance(payload, int):
            size = payload
        else:
            size = len(payload)
        if size > self.max_bytes:
            raise AgentCardSchemaError(
                f"Agent Card payload exceeds allowed size ({size} bytes > {self.max_bytes} bytes)"
            )

    def validate(self, card: Dict[str, Any]) -> None:
        """스키마 검증 수행."""
        try:
            self._validator.validate(card)  # type: ignore[attr-defined]
        except ValidationError as exc:  # type: ignore[name-defined]
            raise AgentCardSchemaError(f"Agent Card schema validation failed: {exc.message}") from exc

    def parse_fields(self, card: Dict[str, Any]) -> AgentCardParseResult:
        """
        정책 검사 / 서명 모듈에서 사용할 필드만 정리해서 반환.

        - name, url, extensions: policy.py 로 전달
        - signatures: 추후 JWS 검증/재서명용
        """
        capabilities = card.get("capabilities") or {}
        return AgentCardParseResult(
            card=card,
            name=card.get("name"),
            url=card.get("url"),
            extensions=card.get("extensions"),
            signatures=card.get("signatures"),
        )

    def load_and_validate_from_file(self, path: Path) -> AgentCardParseResult:
        """파일에서 Agent Card 를 읽어 전체 검증 흐름 수행."""
        try:
            self.ensure_size_limit(path.stat().st_size)
        except FileNotFoundError as exc:
            raise AgentCardSchemaError(f"Agent Card file not found: {path}") from exc
        text = path.read_text(encoding="utf-8")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise AgentCardSchemaError(f"Invalid JSON payload: {exc}") from exc

        self.validate(data)
        return self.parse_fields(data)


# 레거시/간단 검증기를 그대로 유지(기존 코드 호환용)
def validate_card_basic(card: dict):
    errors = []
    if not isinstance(card, dict):
        return False, ["card must be an object"]

    required_string = ['protocolVersion', 'name', 'description', 'url', 'preferredTransport', 'version']
    for f in required_string:
        v = card.get(f)
        if not isinstance(v, str) or v.strip() == '':
            errors.append(f"{f} is required and must be a non-empty string")

    prov = card.get('provider')
    if not isinstance(prov, dict):
        errors.append('provider is required and must be an object')
    else:
        if not isinstance(prov.get('organization'), str) or prov.get('organization', '').strip() == '':
            errors.append('provider.organization is required and must be a non-empty string')
        if not isinstance(prov.get('url'), str) or prov.get('url', '').strip() == '':
            errors.append('provider.url is required and must be a non-empty string')

    if not isinstance(card.get('capabilities'), dict):
        errors.append('capabilities is required and must be an object')

    if not isinstance(card.get('defaultInputModes'), list) or not all(isinstance(x, str) for x in card.get('defaultInputModes')):
        errors.append('defaultInputModes is required and must be an array of strings')
    if not isinstance(card.get('defaultOutputModes'), list) or not all(isinstance(x, str) for x in card.get('defaultOutputModes')):
        errors.append('defaultOutputModes is required and must be an array of strings')

    sec_schemes = card.get('securitySchemes')
    if not isinstance(sec_schemes, dict) or 'bearerAuth' not in sec_schemes:
        errors.append('securitySchemes.bearerAuth is required')

    top_sec = card.get('security')
    has_bearer_req = False
    if isinstance(top_sec, list):
        for req in top_sec:
            if isinstance(req, dict) and 'bearerAuth' in req:
                has_bearer_req = True
                break
    if not has_bearer_req:
        errors.append('security with bearerAuth requirement is required at top level')

    skills = card.get('skills')
    if not isinstance(skills, list) or len(skills) == 0:
        errors.append('skills is required and must be a non-empty array')
    else:
        for i, s in enumerate(skills):
            if not isinstance(s, dict):
                errors.append(f'skills[{i}] must be an object')
                continue
            sec = s.get('security')
            if not sec:
                errors.append(f'skills[{i}].security is required')

    sigs = card.get('signatures')
    if not isinstance(sigs, list) or len(sigs) == 0:
        errors.append('signatures is required and must be a non-empty array')
    else:
        for i, sig in enumerate(sigs):
            if not isinstance(sig, dict):
                errors.append(f'signatures[{i}] must be an object')
                continue
            if not isinstance(sig.get('protected'), str) or sig.get('protected', '').strip() == '':
                errors.append(f'signatures[{i}].protected is required and must be a non-empty string')
            if not isinstance(sig.get('signature'), str) or sig.get('signature', '').strip() == '':
                errors.append(f'signatures[{i}].signature is required and must be a non-empty string')
            hdr = sig.get('header')
            if not isinstance(hdr, dict) or not isinstance(hdr.get('kid'), str) or hdr.get('kid', '').strip() == '':
                errors.append(f'signatures[{i}].header.kid is required and must be a non-empty string')

    return len(errors) == 0, errors


def validate_card_basic_update(card: dict):
    """Update 용 간소 검증: signatures 없이도 통과.

    필수 필드, provider, capabilities, defaultInput/Output, security, skills 등은 동일하게 검사하되
    signatures 존재 검사는 생략한다. 재서명 단계에서 signatures를 채운다.
    """
    errors = []
    if not isinstance(card, dict):
        return False, ["card must be an object"]

    required_string = ['protocolVersion', 'name', 'description', 'url', 'preferredTransport', 'version']
    for f in required_string:
        v = card.get(f)
        if not isinstance(v, str) or v.strip() == '':
            errors.append(f"{f} is required and must be a non-empty string")

    prov = card.get('provider')
    if not isinstance(prov, dict):
        errors.append('provider is required and must be an object')
    else:
        if not isinstance(prov.get('organization'), str) or prov.get('organization', '').strip() == '':
            errors.append('provider.organization is required and must be a non-empty string')
        if not isinstance(prov.get('url'), str) or prov.get('url', '').strip() == '':
            errors.append('provider.url is required and must be a non-empty string')

    if not isinstance(card.get('capabilities'), dict):
        errors.append('capabilities is required and must be an object')

    if not isinstance(card.get('defaultInputModes'), list) or not all(isinstance(x, str) for x in card.get('defaultInputModes')):
        errors.append('defaultInputModes is required and must be an array of strings')
    if not isinstance(card.get('defaultOutputModes'), list) or not all(isinstance(x, str) for x in card.get('defaultOutputModes')):
        errors.append('defaultOutputModes is required and must be an array of strings')

    sec_schemes = card.get('securitySchemes')
    if not isinstance(sec_schemes, dict) or 'bearerAuth' not in sec_schemes:
        errors.append('securitySchemes.bearerAuth is required')

    top_sec = card.get('security')
    has_bearer_req = False
    if isinstance(top_sec, list):
        for req in top_sec:
            if isinstance(req, dict) and 'bearerAuth' in req:
                has_bearer_req = True
                break
    if not has_bearer_req:
        errors.append('security with bearerAuth requirement is required at top level')

    skills = card.get('skills')
    if not isinstance(skills, list) or len(skills) == 0:
        errors.append('skills is required and must be a non-empty array')
    else:
        for i, s in enumerate(skills):
            if not isinstance(s, dict):
                errors.append(f'skills[{i}] must be an object')
                continue
            sec = s.get('security')
            if not sec:
                errors.append(f'skills[{i}].security is required')

    return len(errors) == 0, errors




__all__ = [
    "AgentCardSchema",
    "AgentCardParseResult",
    "AgentCardSchemaError",
    "validate_card_basic",
    "validate_card_basic_update",
]
