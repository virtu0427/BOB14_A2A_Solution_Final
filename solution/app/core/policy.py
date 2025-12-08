import json
import os
import sys
import ipaddress
from collections import deque
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple
from urllib.parse import urlparse

try:
    # --- 선택적 환경 로더 (env_loader 모듈 사용 시) ---
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

# --- 문자열/URL/네트워크 보조 함수 ---


def _to_key(value):
    """비교용 문자열을 소문자/trim 형태로 변환."""
    return value.strip().lower() if isinstance(value, str) else ""


def _host_from_url(url_string):
    """URL 문자열에서 hostname 을 추출(실패 시 None)."""
    try:
        parsed = urlparse(url_string)
    except ValueError:
        return None
    hostname = (parsed.hostname or "").strip().lower()
    return hostname or None


def _parse_ip_range(entry: str) -> Optional[ipaddress.IPv4Network]:
    target = entry.strip()
    if not target:
        return None
    if "/" not in target:
        target = f"{target}/32"
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return None
    return network if isinstance(network, ipaddress.IPv4Network) else None


# --- 정책 제한치/구성 정의 ---


@dataclass(frozen=True)
class ExtensionLimits:
    max_depth: int
    max_array_length: int
    max_nodes: int


@dataclass(frozen=True)
class PolicyConfig:
    domains: Tuple[str, ...]
    ip_networks: Tuple[ipaddress.IPv4Network, ...]
    limits: ExtensionLimits

    @classmethod
    def from_env(cls) -> "PolicyConfig":
        domains_list = [
            entry.strip().lower()
            for entry in os.environ.get("AGENT_DOMAIN_WHITELIST", "").split(",")
            if entry.strip()
        ]
        # 로컬 개발 편의를 위해 localhost 는 무조건 허용
        if "localhost" not in domains_list:
            domains_list.append("localhost")
        domains = tuple(domains_list)
        ip_ranges = tuple(
            network
            for network in (
                _parse_ip_range(entry)
                for entry in os.environ.get("AGENT_IP_WHITELIST", "").split(",")
            )
            if network is not None
        )
        limits = ExtensionLimits(
            max_depth=int(os.environ.get("EXTENSION_MAX_DEPTH", "10")),
            max_array_length=int(os.environ.get("EXTENSION_MAX_ARRAY_LENGTH", "64")),
            max_nodes=int(os.environ.get("EXTENSION_MAX_NODES", "2000")),
        )
        return cls(domains=domains, ip_networks=ip_ranges, limits=limits)


# --- 기본 환경 구성 및 파생 상수 ---
_CONFIG = PolicyConfig.from_env()
DOMAIN_WHITELIST: Tuple[str, ...] = _CONFIG.domains
IP_WHITELIST: Tuple[ipaddress.IPv4Network, ...] = _CONFIG.ip_networks
DEFAULT_EXTENSION_LIMITS = {
    "maxDepth": _CONFIG.limits.max_depth,
    "maxArrayLength": _CONFIG.limits.max_array_length,
    "maxNodes": _CONFIG.limits.max_nodes,
}


class PolicyEvaluator:
    """Agent Card 정책 검증기."""

    def __init__(self, config: Optional[PolicyConfig] = None) -> None:
        self.config = config or PolicyConfig.from_env()

    def evaluate(self, card: Dict[str, Any], agents: Optional[Iterable[Dict[str, Any]]] = None) -> Dict[str, Any]:
        duplicate_error = self._check_duplicate_card(card, agents)
        if duplicate_error:
            return {"status": "error", "code": 409, "message": duplicate_error}

        whitelist_error = self._check_whitelist(card)
        if whitelist_error:
            return {"status": "error", "code": 400, "message": whitelist_error}

        capabilities = card.get("capabilities") or {}
        extensions = capabilities.get("extensions")
        extension_error = self._check_extension_limits(extensions)
        if extension_error:
            return {"status": "error", "code": 400, "message": extension_error}

        return {"status": "ok"}

    def _check_duplicate_card(
        self, card: Dict[str, Any], agents: Optional[Iterable[Dict[str, Any]]]
    ) -> Optional[str]:
        if not card or not isinstance(card, dict):
            return "잘못된 에이전트 카드입니다."
        agents = list(agents or [])
        target_name = _to_key(card.get("name"))
        target_url = _to_key(card.get("url"))

        for agent in agents:
            if not isinstance(agent, dict):
                continue
            status = str(agent.get("status") or "").strip().lower()
            existing = agent.get("card") if isinstance(agent.get("card"), dict) else agent
            if not isinstance(existing, dict):
                continue
            name = _to_key(existing.get("name"))
            url = _to_key(existing.get("url"))
            # already-deleted agents are ignored for duplicate check
            if status == "deleted":
                continue
            if target_name and name and name == target_name:
                return "동일한 name을 가진 에이전트 카드가 이미 존재합니다."
            if target_url and url and url == target_url:
                return "동일한 url을 가진 에이전트 카드가 이미 존재합니다."
        return None

    def _check_whitelist(self, card: Dict[str, Any]) -> Optional[str]:
        uris = []
        card_url = card.get("url")
        if card_url:
            uris.append(card_url)

        capabilities = card.get("capabilities") or {}
        extensions = capabilities.get("extensions")
        uris.extend(self._iter_extension_uris(extensions))
        seen = set()
        for uri in uris:
            if not uri or uri in seen:
                continue
            seen.add(uri)
            error = self._validate_uri(uri)
            if error:
                return error
        return None

    def _validate_uri(self, uri: str) -> Optional[str]:
        hostname = _host_from_url(uri)
        if not hostname:
            return "유효한 URL 형식이 아닙니다."

        if not self.config.domains and not self.config.ip_networks:
            return None

        try:
            ip_obj = ipaddress.ip_address(hostname)
        except ValueError:
            ip_obj = None

        if ip_obj:
            if isinstance(ip_obj, ipaddress.IPv6Address):
                return "IPv6 주소는 현재 등록이 허용되지 않습니다."
            allowed = any(ip_obj in network for network in self.config.ip_networks)
            return None if allowed else "허용되지 않은 IP 대역입니다."

        allowed = any(self._matches_domain(hostname, pattern) for pattern in self.config.domains)
        return None if allowed else "허용되지 않은 도메인입니다."

    @staticmethod
    def _matches_domain(hostname: str, pattern: str) -> bool:
        if pattern.startswith("*."):
            suffix = pattern[2:]
            return hostname == suffix or hostname.endswith(f".{suffix}")
        return hostname == pattern or hostname.endswith(f".{pattern}")

    def _check_extension_limits(self, extension: Any) -> Optional[str]:
        limits = self.config.limits
        if extension is None:
            return None
        stack = [(extension, 1)]
        seen_ids = set()
        node_count = 0

        while stack:
            value, depth = stack.pop()
            node_count += 1

            if node_count > limits.max_nodes:
                return "extension 크기가 허용된 노드 수를 초과했습니다."
            if depth > limits.max_depth:
                return f"extension 중첩 깊이({depth})가 허용치를 넘었습니다."

            if isinstance(value, list):
                obj_id = id(value)
                if obj_id in seen_ids:
                    continue
                seen_ids.add(obj_id)
                if len(value) > limits.max_array_length:
                    return f"extension 배열 길이({len(value)})가 허용치를 넘었습니다."
                for item in value:
                    stack.append((item, depth + 1))
                continue

            if isinstance(value, dict):
                obj_id = id(value)
                if obj_id in seen_ids:
                    continue
                seen_ids.add(obj_id)
                for child in value.values():
                    stack.append((child, depth + 1))
                continue

        return None

    @staticmethod
    def _iter_extension_uris(extension) -> Iterable[str]:
        if extension is None:
            return []
        queue = deque([extension])
        visited = set()
        while queue:
            node = queue.popleft()
            if isinstance(node, dict):
                node_id = id(node)
                if node_id in visited:
                    continue
                visited.add(node_id)
                uri_value = node.get("uri")
                if isinstance(uri_value, str):
                    yield uri_value
                queue.extend(node.values())
            elif isinstance(node, list):
                node_id = id(node)
                if node_id in visited:
                    continue
                visited.add(node_id)
                queue.extend(node)


def check_whitelist(url_string):
    """URL 이 허용된 도메인 또는 IP 대역에 속하는지 확인."""
    if not url_string:
        return "에이전트 URL 정보가 필요합니다."
    if not DOMAIN_WHITELIST and not IP_WHITELIST:
        return None

    hostname = _host_from_url(url_string)
    if not hostname:
        return "유효한 URL 형식이 아닙니다."

    try:
        ip_obj = ipaddress.ip_address(hostname)
    except ValueError:
        ip_obj = None

    if ip_obj:
        if isinstance(ip_obj, ipaddress.IPv6Address):
            return "IPv6 주소는 현재 등록이 허용되지 않습니다."
        allowed = any(ip_obj in network for network in IP_WHITELIST)
        return None if allowed else "허용되지 않은 IP 대역입니다."

    allowed = any(_matches_domain(hostname, pattern) for pattern in DOMAIN_WHITELIST)
    return None if allowed else "허용되지 않은 도메인입니다."


_DEFAULT_EVALUATOR = PolicyEvaluator(_CONFIG)


def run_policy_checks(card, agents=None):
    """이전 API 호환을 위한 래퍼."""
    return _DEFAULT_EVALUATOR.evaluate(card, agents)


def check_duplicate_card(card, agents=None):
    return _DEFAULT_EVALUATOR._check_duplicate_card(card, agents)


def check_whitelist(url_string):
    return _DEFAULT_EVALUATOR._validate_uri(url_string)


def check_extension_limits(extension, limits=None):
    if limits:
        # dict 기반 입력을 ExtensionLimits 로 변환
        ext_limits = ExtensionLimits(
            max_depth=limits.get("maxDepth", _CONFIG.limits.max_depth),
            max_array_length=limits.get("maxArrayLength", _CONFIG.limits.max_array_length),
            max_nodes=limits.get("maxNodes", _CONFIG.limits.max_nodes),
        )
        custom_evaluator = PolicyEvaluator(
            PolicyConfig(domains=_CONFIG.domains, ip_networks=_CONFIG.ip_networks, limits=ext_limits)
        )
        return custom_evaluator._check_extension_limits(extension)
    return _DEFAULT_EVALUATOR._check_extension_limits(extension)


def _main():
    """표준입력 JSON(payload) → 정책 검사 결과 JSON 으로 반환하는 CLI 엔트리."""
    try:
        payload = json.load(sys.stdin)
    except json.JSONDecodeError:
        json.dump({"status": "fatal", "message": "INPUT_PARSE_ERROR"}, sys.stdout)
        return 1
    except Exception:
        json.dump({"status": "fatal", "message": "INPUT_READ_ERROR"}, sys.stdout)
        return 1

    card = payload.get("card")
    agents = payload.get("agents", [])

    try:
        result = run_policy_checks(card, agents)
    except Exception as exc:  # 방어적: 예기치 못한 오류 로그
        json.dump({"status": "fatal", "message": f"POLICY_EXCEPTION:{exc}"}, sys.stdout)
        return 1

    json.dump(result, sys.stdout)
    return 0 if result.get("status") != "fatal" else 1


if __name__ == "__main__":
    sys.exit(_main())
