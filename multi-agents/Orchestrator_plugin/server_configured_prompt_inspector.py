from google.adk.plugins.base_plugin import BasePlugin
from typing import Optional
import google.generativeai as genai
import requests
import os

# LLM 응답을 생성하기 위한 import
try:
    from google.genai.types import Content, Part
    from google.adk.models.llm_response import LlmResponse
except ImportError:
    # fallback
    Content = None
    Part = None
    LlmResponse = None

class ServerConfiguredPromptInspectorPlugin(BasePlugin):
    def __init__(self, gemini_api_key, log_server_url, sys_prompt_server_url):
        super().__init__(name="server_configured_prompt_inspector")
        genai.configure(api_key=gemini_api_key)
        # gemini-pro는 더 이상 지원되지 않으므로 gemini-1.5-flash 사용
        self.model = genai.GenerativeModel('gemini-2.0-flash')
        self.log_server_url = log_server_url
        self.sys_prompt_server_url = sys_prompt_server_url

    async def before_model_callback(
        self,
        *,
        callback_context,
        llm_request,
        **kwargs
    ):
        # 외부 서버에서 시스템 프롬프트 설정 실시간 fetch
        sys_prompt = self.fetch_system_prompt()
        
        # llm_request에서 사용자 메시지 추출 (최신 사용자 메시지만)
        user_prompt = ""
        if hasattr(llm_request, 'contents') and llm_request.contents:
            # contents를 역순으로 검사하여 가장 최근의 user 역할 메시지만 추출
            for content in reversed(llm_request.contents):
                # user 역할의 메시지만 검사 (model 역할은 제외)
                if hasattr(content, 'role') and content.role == 'user':
                    if hasattr(content, 'parts') and content.parts:
                        for part in content.parts:
                            # text 속성이 있고, None이 아닌 경우만 추가
                            if hasattr(part, 'text') and part.text is not None:
                                user_prompt += part.text
                            # function_call 등 다른 타입의 파트는 무시
                    # 첫 번째 user 메시지만 추출하고 종료
                    break
        
        # 디버깅: 추출된 사용자 프롬프트 로깅
        print(f"[PromptInspector] 검사할 사용자 프롬프트: {user_prompt[:100]}..." if len(user_prompt) > 100 else f"[PromptInspector] 검사할 사용자 프롬프트: {user_prompt}")
        
        verdict = await self.inspect_prompt_with_system(sys_prompt, user_prompt)
        print(f"[PromptInspector] 판정 결과: {verdict}")
        
        if verdict != "SAFE":
            # 위반 로그 전송
            self.send_violation_log(user_prompt, sys_prompt, verdict)
            
            # 사용자에게 친절한 거부 메시지를 응답으로 반환
            violation_message = (
                "죄송합니다. 귀하의 요청이 시스템 정책 및 규정에 위반되어 처리할 수 없습니다.\n\n"
                "위반 사유: 시스템 프롬프트에서 정의한 보안 및 사용 정책을 준수하지 않는 요청입니다.\n"
                "정책에 부합하는 요청을 다시 시도해주시기 바랍니다."
            )
            
            # LlmResponse 객체를 생성하여 반환 (실제 LLM 호출을 건너뛰고 이 메시지 반환)
            try:
                if Content is not None and Part is not None and LlmResponse is not None:
                    response_content = Content(
                        role="model",
                        parts=[Part(text=violation_message)]
                    )
                    # LlmResponse 객체 생성 - content (단수형) 사용
                    llm_response = LlmResponse(content=response_content)
                    return llm_response
                else:
                    # import 실패 시 - RuntimeError로 거부 (에러 메시지로 전달)
                    raise RuntimeError(violation_message)
            except Exception as e:
                # LlmResponse 생성 실패 시 - 최후의 수단으로 RuntimeError
                if "시스템 정책" not in str(e):
                    print(f"LlmResponse 생성 실패: {e}, 에러로 메시지 전달")
                raise RuntimeError(violation_message)
        
        # None을 반환하면 정상적으로 LLM 호출 진행
        return None

    def fetch_system_prompt(self):
        # 외부 서버(REST API 등)에서 시스템 프롬프트 받아오기
        try:
            resp = requests.get(self.sys_prompt_server_url, timeout=2)
            resp.raise_for_status()
            sys_prompt = resp.json().get("system_prompt", "")
            return sys_prompt
        except Exception:
            return ""

    async def inspect_prompt_with_system(self, sys_prompt, user_prompt):
        # 서버에서 받아온 시스템 프롬프트 기반 평가
        inspect_prompt = (
            "아래 시스템 프롬프트(정책/설정 기준)를 참고해서 사용자 입력 프롬프트가 위배되는지 평가하세요.\n"
            f"시스템 프롬프트:\n\"{sys_prompt}\"\n"
            f"검사 대상 프롬프트:\n\"{user_prompt}\"\n"
            "응답은 SAFE 또는 VIOLATION 둘 중 하나로만 해주세요."
        )
        response = self.model.generate_content([inspect_prompt])
        result = response.text.strip().split()[0].upper()
        return result

    def send_violation_log(self, user_prompt, sys_prompt, verdict):
        try:
            payload = {
                "event": "agent_prompt_llm_violation",
                "system_prompt": sys_prompt,
                "user_prompt": user_prompt,
                "verdict": verdict,
            }
            requests.post(self.log_server_url, json=payload, timeout=2)
        except Exception:
            pass