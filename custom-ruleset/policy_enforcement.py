"""Reusable IAM policy enforcement plugin for ADK-based agents."""

from __future__ import annotations

import contextlib
from contextvars import ContextVar
import hashlib
import json
import os
import re
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Iterable, Optional, Sequence, Tuple

import jwt
import google.generativeai as genai
import requests
from google.adk.plugins.base_plugin import BasePlugin

try:
    from google.genai.types import Content, Part
    from google.adk.models.llm_response import LlmResponse
except ImportError:
    Content = None
    Part = None
    LlmResponse = None


GLOBAL_REQUEST_TOKEN: ContextVar[str | None] = ContextVar(
    "global_request_token", default=None
)


class PolicyEnforcementPlugin(BasePlugin):
    """IAM 기반 정책 집행 플러그인."""

    _DEFAULT_MODEL = "gemini-2.0-flash"
    _DEFAULT_REPLAY_TTL_SECONDS = 5.0
    _DEFAULT_USER_ERROR_MESSAGE = "요청을 처리하는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요."
    _SECRET_PATTERNS = [
        (re.compile(r"(Authorization\s*:\s*Bearer\s+)[A-Za-z0-9\-\._~+/=]+", re.IGNORECASE), r"\1***"),
        (re.compile(r"(Bearer\s+)[A-Za-z0-9\-\._~+/=]+", re.IGNORECASE), r"\1***"),
        (re.compile(r"(api[_-]?key\s*[=:]\s*)([^\s]+)", re.IGNORECASE), r"\1***"),
        (re.compile(r"(token\s*[=:]\s*)([^\s]+)", re.IGNORECASE), r"\1***"),
        (re.compile(r"(secret\s*[=:]\s*)([^\s]+)", re.IGNORECASE), r"\1***"),
    ]
    _PATH_PATTERN = re.compile(r"((?:[A-Za-z]:)?[\\/][^\s]+)")

    def __init__(
        self,
        *,
        agent_id: str,
        gemini_api_key: Optional[str],
        policy_server_url: str,
        log_server_url: str,
        initial_auth_token: Optional[str] = None,
        initial_context: Optional[Any] = None,
    ) -> None:
        super().__init__(name=f"policy_enforcement_{agent_id}")
        self.agent_id = agent_id
        self.policy_server_url = policy_server_url.rstrip("/")
        self.log_server_url = log_server_url.rstrip("/")
        self.gemini_api_key = gemini_api_key
        self._models: Dict[str, Any] = {}
        
        # [Stateless] 전역 self.policy 대신 캐시만 유지
        self._policy_cache: Dict[str, Dict[str, Any]] = {}
        
        # [필수] 레거시 호환성 및 에러 방지를 위한 빈 객체
        self.policy: Dict[str, Any] = {}

        self._jwt_secret = os.getenv("JWT_SECRET") or os.getenv("SECRET_KEY")
        self._jwt_public_key = os.getenv("JWT_PUBLIC_KEY")
        self._jwt_algorithm = os.getenv("JWT_ALGORITHM") or os.getenv("ALGORITHM") or "HS256"
        self._jwt_audience = os.getenv("JWT_AUDIENCE")
        self._last_auth_token: str | None = None
        self._last_actor: str | None = None  # JWT subject/email 캐시 (로그 actor용)
        self._captured_token_hint: str | None = None
        self._last_policy_fetch_token: str | None = None
        self._replay_cache: "OrderedDict[str, float]" = OrderedDict()
        self._replay_lock = threading.Lock()
        ttl_env = os.getenv("POLICY_PLUGIN_REPLAY_TTL")
        try:
            self._replay_ttl = float(ttl_env) if ttl_env else self._DEFAULT_REPLAY_TTL_SECONDS
        except ValueError:
            self._replay_ttl = self._DEFAULT_REPLAY_TTL_SECONDS

        self._ingest_initial_auth(initial_auth_token, initial_context)

        if gemini_api_key:
            genai.configure(api_key=gemini_api_key)
            self._models[self._DEFAULT_MODEL] = genai.GenerativeModel(self._DEFAULT_MODEL)

    # ------------------------------------------------------------------
    # [안전장치] agent_executor가 호출하더라도 죽지 않게 빈 메서드 유지
    # ------------------------------------------------------------------
    def fetch_policy(
        self,
        *,
        tool_context: Any = None,
        tool_args: Optional[Dict[str, Any]] = None,
        force: bool = False,
    ) -> None:
        pass

    # ------------------------------------------------------------------
    # Policy Cache Management (런타임 정책 새로고침)
    # ------------------------------------------------------------------
    def clear_policy_cache(self, tenant: Optional[str] = None) -> Dict[str, Any]:
        """
        정책 캐시를 비웁니다. 다음 요청 시 새로운 정책을 API에서 가져옵니다.
        
        Args:
            tenant: 특정 테넌트만 캐시를 비우려면 지정. None이면 전체 캐시 비움.
        
        Returns:
            캐시 비우기 결과 정보
        """
        if tenant:
            # 특정 테넌트만 캐시 비우기
            removed = []
            keys_to_remove = [k for k in self._policy_cache.keys() if tenant in k]
            for key in keys_to_remove:
                del self._policy_cache[key]
                removed.append(key)
            print(f"[PolicyPlugin][{self.agent_id}] 정책 캐시 비움 (tenant: {tenant}): {removed}")
            return {
                "agent_id": self.agent_id,
                "cleared": removed,
                "remaining_cache_size": len(self._policy_cache),
            }
        else:
            # 전체 캐시 비우기
            cache_size = len(self._policy_cache)
            cleared_keys = list(self._policy_cache.keys())
            self._policy_cache.clear()
            print(f"[PolicyPlugin][{self.agent_id}] 전체 정책 캐시 비움: {cache_size}개 항목")
            return {
                "agent_id": self.agent_id,
                "cleared": cleared_keys,
                "cleared_count": cache_size,
            }

    def get_cache_status(self) -> Dict[str, Any]:
        """현재 정책 캐시 상태를 반환합니다."""
        return {
            "agent_id": self.agent_id,
            "cache_size": len(self._policy_cache),
            "cached_tenants": list(self._policy_cache.keys()),
        }

    # ------------------------------------------------------------------
    # Policy retrieval helpers
    # ------------------------------------------------------------------
    def _get_policy_for_tenant(self, tenant_str: str, user_email: str = "") -> Dict[str, Any]:
        """
        [HTTP API 모드] 테넌트 정책을 HTTP API로 요청하여 로드
        Docker 환경을 고려하여 여러 URL을 시도
        user_email이 제공되면 그룹 멤버십을 확인하여 권한 없는 경우 빈 정책 반환
        """
        # 1. 캐시 키에 user_email 포함 (사용자별 정책 캐싱)
        cache_key = f"{tenant_str}:{user_email}" if user_email else tenant_str
        if cache_key in self._policy_cache:
            return self._policy_cache[cache_key]

        merged_policy = {
            "template": "merged_policy",
            "tenant": tenant_str,
            "allowed_list": [] 
        }
        
        valid_targets = set()
        merged_agent_map = {}
        policy_found = False

        for tenant_read in tenant_str.split(","):
            tenant_clean = tenant_read.strip()
            if not tenant_clean: continue
            
            # API URL 설정 (환경 변수로 제어 가능, Docker 환경 고려)
            # 우선순위: 환경변수 > Docker 서비스명 > host.docker.internal > localhost
            base_urls = [
                os.environ.get("POLICY_API_URL", "").rstrip("/"),  # 환경 변수
                "http://solution:3000",                            # Docker Compose 서비스명
                "http://attager-solution:3000",                    # Docker 컨테이너명
                "http://host.docker.internal:3000",                # Docker Desktop
                "http://localhost:3000"                             # 로컬 환경
            ]
            
            # 빈 문자열 제거
            base_urls = [url for url in base_urls if url]
            
            params = {
                "tenant": tenant_clean,
                "author": "security manager"
            }
            
            # 사용자 이메일 전달하여 그룹 멤버십 확인
            if user_email:
                params["user"] = user_email
            
            data = None
            successful_url = None
            
            # 여러 URL을 순차적으로 시도
            for base_url in base_urls:
                api_url = f"{base_url}/api/rulesets/tenant-template"
                try:
                    print(f"[DEBUG] 정책 API 요청 시도: {api_url}?tenant={tenant_clean}&author=security+manager")
                    response = requests.get(api_url, params=params, timeout=5)
                    
                    if response.status_code == 200:
                        data = response.json()
                        successful_url = api_url
                        print(f"[DEBUG] ✓ API 응답 성공: {successful_url}")
                        break
                    else:
                        print(f"[DEBUG] ✗ HTTP {response.status_code} from {api_url}")
                        
                except requests.exceptions.Timeout:
                    print(f"[DEBUG] ✗ 타임아웃: {api_url}")
                    continue
                except requests.exceptions.ConnectionError:
                    print(f"[DEBUG] ✗ 연결 실패: {api_url}")
                    continue
                except Exception as e:
                    print(f"[DEBUG] ✗ 오류 ({api_url}): {e}")
                    continue
            
            # 데이터 처리
            if data:
                policy_found = True
                raw_list = data.get("allowed_list", [])
                print(f"[DEBUG] API 응답 수신 성공. 항목 수: {len(raw_list)}")
                
                for rule in raw_list:
                    raw_aid = rule.get("agent_id")
                    
                    if raw_aid:
                        # [Strict Mode] agent_id를 있는 그대로 저장 + 변형된 별칭도 함께 저장
                        clean_aid = str(raw_aid).strip()
                        variants = self._id_variants(clean_aid)
                        valid_targets.update(variants)

                        tools = rule.get("allowed_tools", [])
                        if clean_aid in merged_agent_map:
                            existing_tools = set(merged_agent_map[clean_aid]["allowed_tools"])
                            existing_tools.update(tools)
                            merged_agent_map[clean_aid]["allowed_tools"] = list(existing_tools)
                        else:
                            merged_agent_map[clean_aid] = {
                                "agent_id": clean_aid,
                                "allowed_tools": list(set(tools))
                            }
            else:
                print(f"[ERROR] 모든 API URL 시도 실패 (tenant: {tenant_clean}). 시도한 URL: {base_urls}")

        if policy_found:
            merged_policy["allowed_list"] = list(merged_agent_map.values())
            merged_policy["_valid_targets"] = valid_targets 
            
            self._policy_cache[cache_key] = merged_policy
            
            print(f"[DEBUG] 최종 승인된 에이전트 목록: {valid_targets}")
            return merged_policy
        
        return {}

    # ------------------------------------------------------------------
    # ADK callbacks
    # ------------------------------------------------------------------
    def _check_allowlist_rule(
        self,
        tool_name: str,
        policy: Dict[str, Any],
        tenant_id: str,
        tool_args: Dict[str, Any]
    ) -> Optional[str]:
        
        if not policy:
            return f"No policy defined for tenant '{tenant_id}'."

        allowed_list = policy.get("allowed_list", [])
        
        # 1. [자기 식별] Strict Match (대소문자 구분)
        my_id_strict = self.agent_id.strip()

        def _find_rule():
            for item in allowed_list:
                aid = str(item.get("agent_id", "")).strip()
                if not aid:
                    continue
                variants = self._id_variants(aid)  # 다양한 별칭(풀 id, #agent 이후, 끝 토큰)으로 허용 체크
                if my_id_strict in variants:
                    return item
            return None

        my_rule = _find_rule()

        if not my_rule:
            return f"Access Denied: Agent '{self.agent_id}' is not defined in the policy."

        # 2. [도구 권한 확인]
        my_allowed_tools = my_rule.get("allowed_tools", [])
        
        if tool_name not in my_allowed_tools:
            return f"Tool '{tool_name}' is NOT allowed for agent '{self.agent_id}'."

        # 3. [오케스트레이터 전용] call_remote_agent 타겟 검증
        if tool_name == "call_remote_agent":
            target_agent = tool_args.get("agent_name")
            if not target_agent:
                return "Missing 'agent_name' argument."
            
            # [수정됨] 입력된 타겟 이름 그대로 + 별칭 비교
            target_strict = str(target_agent).strip()
            variants = self._id_variants(target_strict)

            valid_targets = policy.get("_valid_targets", set())
            
            if variants.isdisjoint(valid_targets):
                return f"Access Denied: Target '{target_agent}' is not a valid agent in this tenant."

        return None

    @staticmethod
    def _id_variants(agent_id: str) -> set[str]:
        """에이전트 식별자 매칭을 위해 가능한 별칭 집합을 만든다."""
        variants = set()
        aid = (agent_id or "").strip()
        if not aid:
            return variants
        variants.add(aid)
        # '#agent:' 이후만 추출
        if "#agent:" in aid:
            variants.add(aid.split("#agent:", 1)[-1])
        # ':' 기준 마지막 토큰
        if ":" in aid:
            variants.add(aid.split(":")[-1])
        return variants
    
    async def before_model_callback(
        self,
        *,
        callback_context: Any,
        llm_request: Any,
        **kwargs: Any,
    ) -> Optional[Any]:
        """Validate user prompts before the LLM is invoked."""
        self._capture_auth_from_context(callback_context)
        replay_block = await self._guard_soft_replay(callback_context or {}, llm_request)
        if replay_block is not None:
            return replay_block
        self.fetch_policy(tool_context=callback_context)
        if not self._policy_enabled():
            return None

        prompt_rules = self._get_prompt_rules()
        if not prompt_rules:
            return None

        user_prompt = self._extract_user_message(llm_request)
        if not user_prompt:
            return None

        rule = prompt_rules[0]
        system_prompt = rule.get("system_prompt", "")
        model_name = rule.get("model")

        verdict = await self._inspect_with_llm(system_prompt, user_prompt, model_name)
        print(f"[PolicyPlugin][{self.agent_id}] 프롬프트 판정: {verdict}")

        if verdict != "SAFE":
            self._send_log(
                {
                    "source": "agent",
                    "agent_id": self.agent_id,
                    "policy_type": "prompt_validation",
                    "prompt": user_prompt,
                    "verdict": "VIOLATION",
                    "message": f"[{self.agent_id}] 프롬프트 정책 위반: 사용자 프롬프트가 IAM 정책을 위반했습니다.",
                }
            )
            
            # LLM을 사용하여 유동적인 위반 응답 생성
            violation_message = await self._generate_violation_response(
                violation_type="prompt_violation",
                violation_reason="사용자 프롬프트가 시스템 보안 정책을 위반",
                user_request=user_prompt,
                additional_context={"agent_id": self.agent_id},
                model_name=model_name,
            )
            
            return self._create_llm_response(violation_message)
        
        # 정상 통과 로그 기록
        self._send_log(
            {
                "source": "agent",
                "agent_id": self.agent_id,
                "policy_type": "prompt_validation",
                "prompt": user_prompt[:100] + "..." if len(user_prompt) > 100 else user_prompt,
                "verdict": "PASS",
                "message": f"[{self.agent_id}] 프롬프트 검증 통과",
            }
        )

        
        incoming_token = self._extract_auth_token(callback_context, {})
        
        if incoming_token:
            if hasattr(callback_context, "state") and isinstance(callback_context.state, dict):
                callback_context.state["auth_token"] = incoming_token
            elif hasattr(callback_context, "session") and hasattr(callback_context.session, "state"):
                 callback_context.session.state["auth_token"] = incoming_token
        
        return None

    async def before_tool_callback(
        self,
        *,
        tool: Any,
        tool_args: Dict[str, Any],
        tool_context: Any,
        callback_context: Any = None,
        **kwargs: Any,
    ) -> Optional[Dict[str, Any]]:
        
        ctx = callback_context or tool_context
        
        claims = self._get_auth_claims(ctx, tool_args)
        current_tenant = self._extract_tenant_from_claims(claims)
        # JWT 클레임에서 사용자 이메일 추출 (그룹 멤버십 확인용)
        user_email = claims.get("sub") or claims.get("email") or claims.get("user") or ""

        if not current_tenant or current_tenant.startswith("<"):
            # LLM을 사용하여 유동적인 접근 거부 응답 생성
            access_denied_message = await self._generate_violation_response(
                violation_type="access_denied",
                violation_reason="유효한 테넌트 정보 없음",
                additional_context={"tenant": current_tenant},
            )
            return {"error": access_denied_message}

        request_policy = self._get_policy_for_tenant(current_tenant, user_email=user_email)
        
        if not request_policy:
            # LLM을 사용하여 유동적인 정책 없음 응답 생성
            no_policy_message = await self._generate_violation_response(
                violation_type="access_denied",
                violation_reason=f"테넌트 '{current_tenant}'에 대한 정책 없음",
                additional_context={"tenant": current_tenant},
            )
            return {"error": no_policy_message}

        tool_name = getattr(tool, "name", str(tool))
        
        violation = self._check_allowlist_rule(
            tool_name, 
            request_policy, 
            current_tenant, 
            tool_args
        )

        if violation:
            log_safe_violation = self.sanitize_error_message(violation, audience="log")
            self._send_log(
                {
                    "source": "agent",
                    "agent_id": self.agent_id,
                    "policy_type": "tool_validation",
                    "tool_name": tool_name,
                    "tool_args": tool_args,
                    "verdict": "BLOCKED",
                    "message": f"[{self.agent_id}] 툴 차단: {log_safe_violation}",
                    "target_agent": tool_args.get("agent_name", ""),
                }
            )
            print(f"[PolicyPlugin][{self.agent_id}] 툴 차단: {log_safe_violation}")
            
            # 위반 유형 판별
            target_agent = tool_args.get("agent_name", "")
            if "not a valid agent" in violation.lower() or "target" in violation.lower():
                violation_type = "target_not_allowed"
            elif "not allowed" in violation.lower() or "not defined" in violation.lower():
                violation_type = "tool_blocked"
            else:
                violation_type = "tool_blocked"
            
            # LLM을 사용하여 유동적인 위반 응답 생성
            user_safe_message = await self._generate_violation_response(
                violation_type=violation_type,
                violation_reason=log_safe_violation,
                additional_context={
                    "tool_name": tool_name,
                    "target_agent": target_agent,
                    "tenant": current_tenant,
                    "agent_id": self.agent_id,
                },
            )
            
            return {"error": user_safe_message}

        # 정상 통과 로그 기록
        self._send_log(
            {
                "source": "agent",
                "agent_id": self.agent_id,
                "policy_type": "tool_validation",
                "tool_name": tool_name,
                "verdict": "PASS",
                "message": f"[{self.agent_id}] 툴 검증 통과: {tool_name}",
                "target_agent": tool_args.get("agent_name", ""),
            }
        )
        print(f"[PolicyPlugin] ✅ 승인됨({current_tenant}): {tool_name}")
        return None

    async def _guard_soft_replay(self, callback_context: Any, llm_request: Any) -> Optional[Any]:
        payload_hash = self._hash_llm_request(llm_request)
        if not payload_hash:
            return None

        email = self._extract_replay_subject(callback_context)
        if not email:
            return None

        key = self._build_replay_key(email, payload_hash)
        now = time.monotonic()
        replay_detected = False

        with self._replay_lock:
            self._cleanup_replay_cache(now)
            last_seen = self._replay_cache.get(key)
            if last_seen is None:
                self._replay_cache[key] = now
            else:
                if now - last_seen <= self._replay_ttl:
                    replay_detected = True
                else:
                    self._replay_cache[key] = now
            self._replay_cache.move_to_end(key)

        if not replay_detected:
            return None

        reason = "Repeated message payload detected within replay TTL"
        self._send_log(
            {
                "source": "agent",
                "agent_id": self.agent_id,
                "policy_type": "replay_protection",
                "verdict": "BLOCKED",
                "message": f"[{self.agent_id}] 리플레이 차단: {reason}",
                "tool_name": "",
            }
        )
        
        # LLM을 사용하여 유동적인 리플레이 차단 응답 생성
        user_prompt = self._extract_user_message(llm_request)
        violation_message = await self._generate_violation_response(
            violation_type="replay_blocked",
            violation_reason=reason,
            user_request=user_prompt,
            additional_context={"agent_id": self.agent_id, "email": email},
        )
        
        return self._create_llm_response(violation_message)

    # ... (나머지 helper 함수들은 그대로 두세요) ...
    # _policy_enabled, _get_prompt_rules, _get_tool_rules
    # _extract_user_message, _inspect_with_llm, _resolve_model
    # _check_tool_rule, _create_llm_response, _send_log
    # _ingest_initial_auth, _log_policy_fetch, _capture_auth_from_context
    # _extract_auth_token, _extract_token_from_container, _get_auth_claims
    # _decode_jwt, _log_token_inspection, _log_policy_binding
    # _normalize_required_roles, _extract_roles_from_claims
    # _extract_tenant_from_claims, _roles_satisfied, _sanitize_bearer

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    def _policy_enabled(self) -> bool:
        if not self.policy:
            return False
        enabled = self.policy.get("enabled", True)
        if isinstance(enabled, str):
            enabled = enabled.lower() not in {"false", "0", "off"}
        return bool(enabled)

    def _get_prompt_rules(self) -> Sequence[Dict[str, Any]]:
        rules = self.policy.get("prompt_validation_rules", []) or []
        if not rules:
            policies = self.policy.get("policies")
            if isinstance(policies, dict):
                prompt_validation = policies.get("prompt_validation") or {}
                system_prompt = prompt_validation.get("system_prompt", "")
                model = prompt_validation.get("model")
                enabled = prompt_validation.get("enabled", True)
                if system_prompt:
                    rules = [
                        {
                            "system_prompt": system_prompt,
                            "model": model,
                            "enabled": enabled,
                        }
                    ]

        enabled_rules = []
        for rule in rules:
            enabled = rule.get("enabled", True)
            if isinstance(enabled, str):
                enabled = enabled.lower() not in {"false", "0", "off"}
            if enabled and rule.get("system_prompt"):
                enabled_rules.append(rule)
        return enabled_rules

    def _get_tool_rules(self) -> Dict[str, Dict[str, Any]]:
        rules = self.policy.get("tool_validation_rules")

        if not rules:
            policies = self.policy.get("policies")
            if isinstance(policies, dict):
                tool_validation = policies.get("tool_validation") or {}
                enabled = tool_validation.get("enabled", True)
                if isinstance(enabled, str):
                    enabled = enabled.lower() not in {"false", "0", "off"}
                if not enabled:
                    return {}
                rules = tool_validation.get("rules")

        if isinstance(rules, dict):
            return rules
        return {}

    def _extract_user_message(self, llm_request: Any) -> str:
        message = ""
        if hasattr(llm_request, "contents") and llm_request.contents:
            for content in reversed(llm_request.contents):
                role = getattr(content, "role", None)
                if role == "user" and getattr(content, "parts", None):
                    for part in content.parts:
                        text = getattr(part, "text", None)
                        if text:
                            message += text
                    break
        return message

    async def _inspect_with_llm(
        self,
        system_prompt: str,
        user_prompt: str,
        model_name: Optional[str],
    ) -> str:
        if not system_prompt or not self.gemini_api_key:
            return "SAFE"

        model = self._resolve_model(model_name)
        if model is None:
            return "SAFE"

        try:
            inspect_prompt = (
                f"{system_prompt}\n\n"
                f"검사 대상 프롬프트:\n\"{user_prompt}\"\n\n"
                "응답은 SAFE 또는 VIOLATION 둘 중 하나로만 해주세요."
            )
            response = model.generate_content([inspect_prompt])
            verdict = (response.text or "").strip().split()[0].upper()
            return verdict if verdict in {"SAFE", "VIOLATION"} else "SAFE"
        except Exception as exc:  # pragma: no cover - runtime LLM failures
            print(f"[PolicyPlugin] LLM 검증 실패: {exc}")
            return "SAFE"

    def _resolve_model(self, model_name: Optional[str]):
        name = model_name or self._DEFAULT_MODEL
        if name in self._models:
            return self._models[name]
        if not self.gemini_api_key:
            return None
        try:
            model = genai.GenerativeModel(name)
            self._models[name] = model
            return model
        except Exception as exc:  # pragma: no cover - runtime model resolution issues
            print(f"[PolicyPlugin] 모델 로드 실패({name}): {exc}")
            return self._models.get(self._DEFAULT_MODEL)

    async def _generate_violation_response(
        self,
        violation_type: str,
        violation_reason: str,
        user_request: str = "",
        additional_context: Optional[Dict[str, Any]] = None,
        model_name: Optional[str] = None,
    ) -> str:
        """
        LLM을 사용하여 정책 위반 상황에 맞는 유동적인 응답을 생성합니다.
        
        Args:
            violation_type: 위반 유형 (prompt_violation, tool_blocked, replay_blocked, access_denied 등)
            violation_reason: 위반 사유 (내부용, 사용자에게 직접 노출하지 않음)
            user_request: 사용자의 원래 요청 (있는 경우)
            additional_context: 추가 컨텍스트 정보 (tool_name, target_agent 등)
            model_name: 사용할 모델명 (기본값: DEFAULT_MODEL)
        
        Returns:
            사용자 친화적인 위반 응답 메시지
        """
        # 기본 폴백 메시지들 (LLM 호출 실패 시 사용)
        fallback_messages = {
            "prompt_violation": (
                "죄송합니다. 요청하신 내용이 시스템 보안 정책에 부합하지 않아 처리할 수 없습니다. "
                "다른 방식으로 질문해 주시거나, 정책에 맞는 요청을 시도해 주세요."
            ),
            "tool_blocked": (
                "죄송합니다. 요청하신 작업을 수행할 권한이 없습니다. "
                "필요한 권한이 있는지 확인하시거나, 관리자에게 문의해 주세요."
            ),
            "replay_blocked": (
                "동일한 요청이 너무 빠르게 반복되어 처리가 제한되었습니다. "
                "잠시 후 다시 시도해 주세요."
            ),
            "access_denied": (
                "접근이 거부되었습니다. 유효한 인증 정보가 필요합니다. "
                "로그인 상태를 확인해 주세요."
            ),
            "target_not_allowed": (
                "요청하신 대상 에이전트에 접근할 권한이 없습니다. "
                "허용된 에이전트 목록을 확인해 주세요."
            ),
        }
        
        default_fallback = (
            "죄송합니다. 요청을 처리하는 중 정책 제한으로 인해 진행할 수 없습니다. "
            "다른 방식으로 시도하시거나 관리자에게 문의해 주세요."
        )
        
        fallback = fallback_messages.get(violation_type, default_fallback)
        
        # Gemini API가 없으면 폴백 메시지 반환
        if not self.gemini_api_key:
            return fallback
        
        model = self._resolve_model(model_name)
        if model is None:
            return fallback
        
        # 추가 컨텍스트 정리
        ctx = additional_context or {}
        tool_name = ctx.get("tool_name", "")
        target_agent = ctx.get("target_agent", "")
        tenant = ctx.get("tenant", "")
        
        # LLM에게 전달할 프롬프트 구성
        system_instruction = """당신은 AI 에이전트 시스템의 정책 안내 도우미입니다.
사용자의 요청이 시스템 정책에 의해 제한되었을 때, 친절하고 이해하기 쉽게 상황을 설명해야 합니다.

응답 작성 가이드라인:
1. 정중하고 공감적인 어조를 유지하세요
2. 왜 요청이 제한되었는지 간단히 설명하세요 (기술적 세부사항은 피하세요)
3. 사용자가 다음에 어떻게 할 수 있는지 대안을 제시하세요
4. 응답은 2-4문장으로 간결하게 작성하세요
5. 보안에 민감한 정보(토큰, 내부 오류, 시스템 경로 등)는 절대 포함하지 마세요
6. 한국어로 응답하세요"""

        context_parts = []
        context_parts.append(f"위반 유형: {violation_type}")
        
        if violation_type == "prompt_violation":
            context_parts.append("상황: 사용자의 프롬프트가 시스템 보안 정책을 위반했습니다.")
        elif violation_type == "tool_blocked":
            context_parts.append(f"상황: '{tool_name}' 도구 사용이 현재 정책에서 허용되지 않았습니다.")
        elif violation_type == "replay_blocked":
            context_parts.append("상황: 동일한 요청이 짧은 시간 내에 반복 감지되어 차단되었습니다.")
        elif violation_type == "access_denied":
            context_parts.append("상황: 사용자의 인증 정보가 유효하지 않거나 누락되었습니다.")
        elif violation_type == "target_not_allowed":
            context_parts.append(f"상황: '{target_agent}' 에이전트에 대한 접근 권한이 없습니다.")
        
        if user_request:
            # 사용자 요청은 처음 100자만 포함 (개인정보 보호)
            truncated_request = user_request[:100] + "..." if len(user_request) > 100 else user_request
            context_parts.append(f"사용자 요청 요약: {truncated_request}")
        
        context_str = "\n".join(context_parts)
        
        generation_prompt = f"""{system_instruction}

---
{context_str}
---

위 상황에 대해 사용자에게 전달할 친절한 안내 메시지를 작성해 주세요.
응답은 안내 메시지만 포함하고, 다른 설명이나 메타 정보는 포함하지 마세요."""

        try:
            response = model.generate_content([generation_prompt])
            generated_text = (response.text or "").strip()
            
            if generated_text and len(generated_text) > 10:
                # 생성된 응답 검증 (민감 정보 포함 여부 체크)
                sanitized = self._apply_secret_filters(generated_text)
                print(f"[PolicyPlugin] LLM 위반 응답 생성 완료 ({violation_type})")
                return sanitized
            else:
                print(f"[PolicyPlugin] LLM 응답이 너무 짧음, 폴백 사용")
                return fallback
                
        except Exception as exc:
            print(f"[PolicyPlugin] LLM 위반 응답 생성 실패: {exc}")
            return fallback

    def _check_tool_rule(
        self,
        tool_name: str,
        tool_args: Dict[str, Any],
        rule: Dict[str, Any],
        tool_context: Any,
    ) -> Optional[str]:
        allowed_agents = rule.get("allowed_agents")
        if allowed_agents:
            agent_name = tool_args.get("agent_name") or tool_args.get("agent")
            if agent_name and agent_name not in allowed_agents:
                return f"Agent '{agent_name}' is not allowed for {tool_name}"

        max_task_length = rule.get("max_task_length")
        if isinstance(max_task_length, int):
            task = tool_args.get("task", "") or ""
            if len(task) > max_task_length:
                return f"Task length ({len(task)}) exceeds maximum ({max_task_length})"

        requires_auth = rule.get("requires_auth")
        if isinstance(requires_auth, str):
            requires_auth = requires_auth.lower() not in {"false", "0", "off"}
        if requires_auth and not self._extract_auth_token(tool_context, tool_args):
            return "Authentication required for this tool"

        required_roles = rule.get("required_roles") or rule.get("required_role")
        normalized_roles = self._normalize_required_roles(required_roles)
        if normalized_roles:
            claims = self._get_auth_claims(tool_context, tool_args)
            user_roles = self._extract_roles_from_claims(claims)
            if not user_roles:
                return "Role information missing from JWT token"
            if not self._roles_satisfied(user_roles, normalized_roles):
                return f"Tool '{tool_name}' requires role(s): {', '.join(normalized_roles)}"

        max_results = rule.get("max_results")
        if isinstance(max_results, int):
            limit = tool_args.get("limit")
            if isinstance(limit, int) and limit > max_results:
                return f"Requested limit ({limit}) exceeds maximum ({max_results})"

        return None

    def _create_llm_response(self, message: str):
        if Content and Part and LlmResponse:
            try:
                response_content = Content(role="model", parts=[Part(text=message)])
                return LlmResponse(content=response_content)
            except Exception as exc:  # pragma: no cover
                print(f"[PolicyPlugin] LlmResponse 생성 실패: {exc}")
        raise RuntimeError(message)

    def _send_log(self, payload: Dict[str, Any]) -> None:
        payload = self._sanitize_payload(dict(payload))
        if not payload.get("actor"):
            payload["actor"] = self._last_actor or ""
        log_url = f"{self.log_server_url}/api/logs"
        print(f"[PolicyPlugin] 📤 로그 전송 시도: {log_url}")
        print(f"[PolicyPlugin] 📦 페이로드: {payload}")
        try:
            response = requests.post(
                log_url,
                json=payload,
                timeout=2,
            )
            print(f"[PolicyPlugin] ✅ 로그 전송 결과: HTTP {response.status_code}")
            if response.status_code >= 400:
                print(f"[PolicyPlugin] ⚠️ 로그 서버 응답: {response.text[:200]}")
        except requests.exceptions.ConnectionError as e:
            print(f"[PolicyPlugin] ❌ 로그 서버 연결 실패 ({log_url}): {e}")
        except requests.exceptions.Timeout:
            print(f"[PolicyPlugin] ⏱️ 로그 서버 타임아웃 ({log_url})")
        except Exception as e:
            print(f"[PolicyPlugin] ❌ 로그 전송 예외: {type(e).__name__}: {e}")

    # ------------------------------------------------------------------
    # Authentication helpers
    # ------------------------------------------------------------------
    def _ingest_initial_auth(self, token_hint: Optional[str], context: Optional[Any]) -> None:
        env_token = (
            os.getenv("IAM_BOOTSTRAP_AUTH_TOKEN")
            or os.getenv("POLICY_BOOTSTRAP_TOKEN")
            or os.getenv("AUTH_TOKEN")
        )

        candidates = [token_hint, env_token, self._extract_token_from_container(context)]

        for candidate in candidates:
            cleaned = self._sanitize_bearer(candidate)
            if cleaned:
                self._captured_token_hint = cleaned
                self._last_auth_token = cleaned
                break

    def _log_policy_fetch(self, token: str) -> None:
        base_message = f"[PolicyPlugin] {self.agent_id} 정책 로드 완료"

        if not token:
            print(f"{base_message} (auth_token=<none>)")
            return

        claims = self._decode_jwt(token)
        roles = self._extract_roles_from_claims(claims)
        tenant = self._extract_tenant_from_claims(claims)
        subject = claims.get("sub") or claims.get("email") or claims.get("user") or "<unknown>"
        token_preview = token if len(token) <= 18 else f"{token[:10]}...{token[-6:]}"
        print(f"{base_message} (subject={subject}, roles={roles or []}, tenant={tenant}, token={token_preview})")

    def _capture_auth_from_context(self, callback_context: Any) -> None:
        token = self._extract_token_from_container(callback_context)
        if token:
            self._captured_token_hint = token

    def _extract_auth_token(self, tool_context: Any, tool_args: Dict[str, Any]) -> str:
        # [지뢰 3] 플러그인 동작 확인용 로그 (객체 내부 구조 공개)
        direct_token = GLOBAL_REQUEST_TOKEN.get()
        
        if direct_token:
            print(f"[3. Plugin] ContextVar 직통 터널에서 토큰 발견 ({direct_token[:10]}...)", flush=True)
            return self._sanitize_bearer(direct_token)
        # [디버깅] 도대체 tool_context 안에 뭐가 들었는지 속성을 다 찍어봅니다.
        try:
            attributes = dir(tool_context)
            # 너무 많으니 _로 시작하는 거 빼고 출력
            public_attrs = [a for a in attributes if not a.startswith('_')]
            print(f"[3. Plugin] Context 속성 목록: {public_attrs}", flush=True)
        except:
            pass

        # ---------------------------------------------------------
        # [탐색 1] Executor가 넣어둔 세션 State 찾기 (강력한 탐색)
        # ---------------------------------------------------------
        possible_states = []

        # 1. tool_context.state
        if hasattr(tool_context, "state"):
            possible_states.append(tool_context.state)
        
        # 2. tool_context.session.state
        if hasattr(tool_context, "session"):
            session = getattr(tool_context, "session", None)
            if session and hasattr(session, "state"):
                possible_states.append(session.state)

        # 3. tool_context.context.state (중첩된 경우)
        if hasattr(tool_context, "context"):
            inner_ctx = getattr(tool_context, "context", None)
            if inner_ctx:
                if hasattr(inner_ctx, "state"):
                    possible_states.append(inner_ctx.state)
                if hasattr(inner_ctx, "session") and hasattr(inner_ctx.session, "state"):
                    possible_states.append(inner_ctx.session.state)

        # 4. (추가) attributes 딕셔너리 확인
        if hasattr(tool_context, "attributes") and isinstance(tool_context.attributes, dict):
             possible_states.append(tool_context.attributes)

        # 수집된 모든 state 후보군을 뒤져서 토큰 찾기
        for state in possible_states:
            if not state: continue
            
            # dict인 경우
            if isinstance(state, dict):
                token = state.get("auth_token")
                if token:
                    print(f"[3. Plugin] ⭕ (Dict State) 토큰: {token[:10]}...", flush=True)
                    return self._sanitize_bearer(token)
            # object인 경우
            elif hasattr(state, "auth_token"):
                token = getattr(state, "auth_token")
                if token:
                    print(f"[3. Plugin] ⭕ 찾았다! (Obj State) 토큰: {token[:10]}...", flush=True)
                    return self._sanitize_bearer(token)

        # ---------------------------------------------------------
        # [탐색 2] 도구 인자(Arguments)에서 찾기
        # ---------------------------------------------------------
        tool_args = tool_args or {}
        candidates = [
            tool_args.get("auth_token"),
            tool_args.get("token"),
            tool_args.get("Authorization"),
            tool_args.get("authorization"),
        ]

        # ---------------------------------------------------------
        # [탐색 3] 기타 컨테이너 재귀 탐색 (헤더 등)
        # ---------------------------------------------------------
        candidates.append(self._extract_token_from_container(tool_context))
        candidates.append(self._extract_token_from_container(getattr(tool_context, "metadata", None)))

        if self._captured_token_hint:
            candidates.append(self._captured_token_hint)

        if self._last_auth_token:
            candidates.append(self._last_auth_token)

        for candidate in candidates:
            cleaned = self._sanitize_bearer(candidate)
            if cleaned:
                print(f"[3. Plugin] ⭕ (Container/Args) 토큰: {cleaned[:10]}...", flush=True)
                return cleaned
        
        print(f"[3. Plugin] ❌ 실패: 토큰이 없습니다.", flush=True)
        return ""

    def _extract_token_from_container(self, container: Any, _visited: Optional[set[int]] = None) -> str:
        # [디버깅] 들어오는 요청의 헤더를 훔쳐보자
        if isinstance(container, dict) and "auth_token" in container:
             print(f"[3. Plugin] 컨테이너 안에 auth_token 있음: {str(container.get('auth_token'))[:10]}...", flush=True)
        if not container:
            return ""

        if _visited is None:
            _visited = set()

        ident = id(container)
        if ident in _visited:
            return ""
        _visited.add(ident)

        if isinstance(container, dict):
            headers = container.get("headers") or container
            for key in ("Authorization", "authorization", "auth_token", "token"):
                if key in headers:
                    return self._sanitize_bearer(headers.get(key))

            for nested_key in (
                "headers",
                "metadata",
                "context",
                "raw_request",
                "request",
                "envelope",
            ):
                nested = headers.get(nested_key)
                cleaned = self._extract_token_from_container(nested, _visited)
                if cleaned:
                    return cleaned

            for value in headers.values():
                cleaned = self._extract_token_from_container(value, _visited)
                if cleaned:
                    return cleaned

        if isinstance(container, (list, tuple, set)):
            for item in container:
                cleaned = self._extract_token_from_container(item, _visited)
                if cleaned:
                    return cleaned

        for attr in ("headers", "metadata", "context", "raw_request", "request"):
            candidate = getattr(container, attr, None)
            cleaned = self._extract_token_from_container(candidate, _visited)
            if cleaned:
                return cleaned

        return ""

    def _get_auth_claims(self, tool_context: Any, tool_args: Dict[str, Any]) -> Dict[str, Any]:
        token = self._extract_auth_token(tool_context, tool_args)
        if not token:
            self._last_actor = None
            return {}
        claims = self._decode_jwt(token)
        if claims:
            actor = self._extract_actor_from_claims(claims)
            self._last_actor = actor or None
            repeated_token = token == self._last_auth_token
            self._log_token_inspection(token, claims, repeated=repeated_token)
            self._log_policy_binding(token, claims)
            self._last_auth_token = token
        else:
            self._last_actor = None
        return claims

    def _decode_jwt(self, token: str) -> Dict[str, Any]:
        options = {"verify_signature": bool(self._jwt_secret or self._jwt_public_key)}
        verify_args: Dict[str, Any] = {"algorithms": [self._jwt_algorithm]}

        if self._jwt_audience:
            verify_args["audience"] = self._jwt_audience

        key = self._jwt_public_key or self._jwt_secret
        try:
            if key:
                return jwt.decode(token, key=key, options=options, **verify_args)
            return jwt.decode(token, options={"verify_signature": False})
        except Exception as exc:  # pragma: no cover - runtime token parsing
            print(f"[PolicyPlugin] JWT decode 실패: {exc}")
            return {}

    def _log_token_inspection(self, token: str, claims: Dict[str, Any], *, repeated: bool = False) -> None:
        roles = self._extract_roles_from_claims(claims)
        subject = claims.get("sub") or claims.get("email") or claims.get("user")
        token_preview = token if len(token) <= 18 else f"{token[:10]}...{token[-6:]}"
        event = "JWT 재사용" if repeated else "JWT 로드"
        print(
            "[PolicyPlugin][{}] {}: sub={}, roles={}, token={}".format(
                self.agent_id, event, subject or "<unknown>", roles or [], token_preview
            )
        )

    def _log_policy_binding(self, token: str, claims: Dict[str, Any]) -> None:
        roles = self._extract_roles_from_claims(claims)
        subject = claims.get("sub") or claims.get("email") or claims.get("user") or "<unknown>"
        token_preview = token if len(token) <= 18 else f"{token[:10]}...{token[-6:]}"
        rule_keys = sorted(self._get_tool_rules().keys())
        rule_summary = ", ".join(rule_keys) if rule_keys else "<no tool rules>"
        print(
            "[PolicyPlugin][{}] 정책 적용: subject={}, roles={}, token={}, rules={}".format(
                self.agent_id, subject, roles or [], token_preview, rule_summary
            )
        )

    def _normalize_required_roles(self, required_roles: Any) -> list[str]:
        if not required_roles:
            return []
        if isinstance(required_roles, str):
            required_roles = [required_roles]
        if isinstance(required_roles, Iterable):
            return [str(role).strip().lower() for role in required_roles if str(role).strip()]
        return []

    def _extract_roles_from_claims(self, claims: Dict[str, Any]) -> list[str]:
        if not isinstance(claims, dict):
            return []
        roles: list[str] = []
        for key in ("roles", "role", "permissions", "scopes", "scope"):
            value = claims.get(key)
            if isinstance(value, str):
                roles.extend(item.strip().lower() for item in value.split() if item.strip())
            elif isinstance(value, Iterable):
                roles.extend(str(item).strip().lower() for item in value if str(item).strip())
        return roles

    @staticmethod
    def _extract_actor_from_claims(claims: Dict[str, Any]) -> str:
        if not isinstance(claims, dict):
            return ""
        for key in ("sub", "email", "user", "principal"):
            value = claims.get(key)
            if value:
                return str(value)
        return ""

    def _extract_tenant_from_claims(self, claims: Dict[str, Any]) -> str:
        """
        Pydantic 스키마(TenantValue)에 맞춰 테넌트 정보를 추출합니다.
        Target Key: "tenant"
        Type: str | List[str]
        """
        if not isinstance(claims, dict):
            return "<unknown_tenant>"

        # 1. 스키마에 정의된 정확한 키 'tenant'를 우선 확인
        # 서버 스키마: class TokenData(BaseModel): tenant: TenantValue | None
        val = claims.get("tenant")

        # 2. 값이 없는 경우, 관례적인 다른 키들도 확인 (혹시 모르니)
        if val is None:
            for fallback_key in ["tid", "tenant_id", "org_id"]:
                val = claims.get(fallback_key)
                if val: break
        
        if val is None:
            return "<no_tenant>"

        def _clean_tenant_value(v: Any) -> str:
            """tenant 값에서 불필요한 따옴표와 공백을 제거합니다."""
            s = str(v).strip()
            # 양쪽 따옴표 제거 (JSON 직렬화 문제 대응)
            if (s.startswith('"') and s.endswith('"')) or (s.startswith("'") and s.endswith("'")):
                s = s[1:-1].strip()
            return s

        # 3. TenantValue = Union[str, List[str]] 처리
        if isinstance(val, list):
            # 리스트인 경우: 각 값을 정리하고 콤마로 연결
            cleaned = [_clean_tenant_value(v) for v in val if v]
            return ",".join(cleaned)
        
        return _clean_tenant_value(val)

    def _roles_satisfied(self, user_roles: list[str], required_roles: list[str]) -> bool:
        user_role_set = {role.lower() for role in user_roles}
        return any(role.lower() in user_role_set for role in required_roles)

    @staticmethod
    def _sanitize_bearer(token: Any) -> str:
        if not token:
            return ""
        token_str = str(token).strip()
        if token_str.lower().startswith("bearer "):
            return token_str[7:].strip()
        return token_str

    # ------------------------------------------------------------------
    # Soft replay helpers
    # ------------------------------------------------------------------
    def _hash_llm_request(self, llm_request: Any) -> str:
        contents = getattr(llm_request, "contents", None)
        if not contents:
            return ""

        target_contents: list[Any] = []
        for content in reversed(contents):
            if getattr(content, "role", None) == "user":
                target_contents = [content]
                break
        if not target_contents:
            target_contents = list(contents)

        segments: list[str] = []
        for content in target_contents:
            role = getattr(content, "role", None) or "unknown"
            parts = getattr(content, "parts", None) or []
            for part in parts:
                entry = [role]
                text = getattr(part, "text", None)
                if text:
                    entry.append(text)

                func = getattr(part, "function_call", None)
                if func:
                    name = getattr(func, "name", "")
                    args = getattr(func, "args", {}) or {}
                    serialized_args = self._safe_json_dump(args)
                    entry.append(f"FUNC:{name}:{serialized_args}")

                file_data = getattr(part, "file_data", None)
                if file_data:
                    uri = getattr(file_data, "file_uri", "")
                    mime = getattr(file_data, "mime_type", "")
                    entry.append(f"FILE:{uri}:{mime}")

                if len(entry) > 1:
                    segments.append("|".join(entry))

        if not segments:
            return ""

        serialized = "\n".join(segments)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @staticmethod
    def _safe_json_dump(data: Any) -> str:
        try:
            return json.dumps(data, sort_keys=True, ensure_ascii=False)
        except TypeError:
            return json.dumps(str(data))

    def _extract_replay_subject(self, callback_context: Any) -> Tuple[str, str]:
        claims = self._get_auth_claims(callback_context, {}) if callback_context else {}
        email = str(
            claims.get("email")
            or claims.get("sub")
            or claims.get("user")
            or claims.get("principal")
            or ""
        ).strip()

        return email

    def _build_replay_key(self, email: str, payload_hash: str) -> str:
        return f"{email}|{payload_hash}"

    def _cleanup_replay_cache(self, now: float) -> None:
        expire_before = now - self._replay_ttl
        keys_to_delete = []
        for key, timestamp in self._replay_cache.items():
            if timestamp < expire_before:
                keys_to_delete.append(key)
            else:
                break
        for key in keys_to_delete:
            self._replay_cache.pop(key, None)

    # ------------------------------------------------------------------
    # Error sanitization helpers
    # ------------------------------------------------------------------
    def sanitize_error_message(self, message: str, *, audience: str = "user") -> str:
        sanitized = self._apply_secret_filters(message or "")
        if audience == "log":
            return sanitized

        condensed = sanitized.strip()
        if not condensed:
            return self._DEFAULT_USER_ERROR_MESSAGE

        if len(condensed) > 200:
            condensed = condensed[:200] + "..."

        return f"{self._DEFAULT_USER_ERROR_MESSAGE}\n세부 정보: {condensed}"

    def _apply_secret_filters(self, text: str) -> str:
        sanitized = text or ""
        for pattern, replacement in self._SECRET_PATTERNS:
            sanitized = pattern.sub(replacement, sanitized)
        sanitized = self._PATH_PATTERN.sub("<path>", sanitized)
        return sanitized

    def _sanitize_payload(self, payload: Any):
        if isinstance(payload, dict):
            return {key: self._sanitize_payload(value) for key, value in payload.items()}
        if isinstance(payload, list):
            return [self._sanitize_payload(item) for item in payload]
        if isinstance(payload, str):
            return self._apply_secret_filters(payload)
        return payload
