import os
import sys
import uuid
import logging
import httpx
import asyncio
from typing import List
from urllib.parse import urlsplit, urlunsplit

from google.adk.agents import LlmAgent
from google.adk.models.lite_llm import LiteLlm
from google.adk.tools import FunctionTool
from google.adk.tools.tool_context import ToolContext
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai.types import Content, Part as GenaiPart

from a2a.types import (
    AgentCard,
    Message,
    Role,
    Part,
    TextPart,
    MessageSendParams,
    SendMessageRequest,
)

# 프로젝트 루트 디렉토리를 PYTHONPATH에 추가
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, project_root)

from utils.model_config import get_model_with_fallback
from iam.policy_enforcement import GLOBAL_REQUEST_TOKEN, PolicyEnforcementPlugin

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# --- 1. AgentCard 로더 ---

AGENT_REGISTRY_URL = os.getenv("AGENT_REGISTRY_URL", "http://localhost:8000")
POLICY_SERVER_URL = os.getenv("POLICY_SERVER_URL", "http://localhost:8005")
LOG_SERVER_URL = os.getenv("LOG_SERVER_URL", POLICY_SERVER_URL)

# 도커 내부에서 localhost로 등록된 카드 URL을 서비스 명으로 치환하기 위한 호스트 매핑
AGENT_INTERNAL_HOST = os.getenv("AGENT_INTERNAL_HOST")
PORT_HOST_MAP = {
    "10001": os.getenv("DELIVERY_AGENT_HOST", "delivery-agent"),
    "10002": os.getenv("ITEM_AGENT_HOST", "item-agent"),
    "10003": os.getenv("QUALITY_AGENT_HOST", "quality-agent"),
    "10004": os.getenv("VEHICLE_AGENT_HOST", "vehicle-agent"),
}
LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal"}


def _rewrite_card_url_if_needed(card: AgentCard) -> AgentCard:
    """Container 환경에서 localhost 카드 URL을 서비스 접근용으로 보정한다."""

    card_url = getattr(card, "url", None)
    if not card_url:
        return card

    parsed = urlsplit(card_url)
    host = parsed.hostname
    port = parsed.port

    if host not in LOOPBACK_HOSTS:
        return card

    replacement_host = AGENT_INTERNAL_HOST or PORT_HOST_MAP.get(str(port))
    if not replacement_host:
        return card

    new_netloc = f"{replacement_host}:{port}" if port else replacement_host
    rewritten_url = urlunsplit((parsed.scheme, new_netloc, parsed.path, parsed.query, parsed.fragment))

    logger.info("카드 URL을 컨테이너 접근용으로 교체: %s -> %s", card_url, rewritten_url)

    if hasattr(card, "model_copy"):
        return card.model_copy(update={"url": rewritten_url})
    if hasattr(card, "copy"):
        return card.copy(update={"url": rewritten_url})

    # pydantic 외 객체 대비: 속성 대입 후 반환
    card.url = rewritten_url
    return card

from .jwt_client import jwt_token_manager

def _build_auth_headers(tool_context=None) -> dict[str, str]:
    """
    여러 소스에서 JWT 토큰을 찾아 Authorization 헤더를 구성
    우선순위: tool_context.state > GLOBAL_REQUEST_TOKEN > jwt_token_manager
    """
    headers = {}
    token = None
    token_source = None
    
    # 1. tool_context.state에서 토큰 확인
    if tool_context and hasattr(tool_context, 'state'):
        token = tool_context.state.get("auth_token", "")
        if token:
            token_source = "tool_context.state"
    
    # 2. GLOBAL_REQUEST_TOKEN에서 토큰 확인
    if not token:
        token = GLOBAL_REQUEST_TOKEN.get("")
        if token:
            token_source = "GLOBAL_REQUEST_TOKEN"
    
    # 3. jwt_token_manager에서 토큰 확인
    if not token:
        token = jwt_token_manager.get_token()
        if token:
            token_source = "jwt_token_manager"
    
    if token:
        headers["Authorization"] = f"Bearer {token}"
        print(f"[_build_auth_headers] ✓ 토큰 발견 (소스: {token_source})")
    else:
        logger.warning("JWT token unavailable for agent-card request")
        print("[_build_auth_headers] ⚠ 토큰을 찾을 수 없음")
    
    return headers

def load_agent_cards(tool_context) -> List[str]:
    """
    레지스트리 서버에서 에이전트 카드 목록을 조회해서 state에 저장,
    에이전트 이름 리스트 반환
    Docker 환경을 고려하여 여러 URL을 시도
    """
    # Docker 환경을 고려한 URL 리스트 (우선순위 순)
    base_urls = [
        os.getenv("AGENT_REGISTRY_URL", "").rstrip("/"),  # 환경 변수 우선
        "http://solution:3000",                            # Docker Compose 서비스명
        "http://attager-solution:3000",                    # Docker 컨테이너명
        "http://host.docker.internal:3000",                # Docker Desktop
        "http://localhost:3000"                             # 로컬 환경
    ]
    # 빈 문자열 제거 및 중복 제거
    seen = set()
    unique_urls = []
    for url in base_urls:
        if url and url not in seen:
            seen.add(url)
            unique_urls.append(url)
    base_urls = unique_urls
    
    headers = _build_auth_headers(tool_context)
    print(f"[load_agent_cards] 시작 - 시도할 URL 목록: {base_urls}")
    print(f"[load_agent_cards] Authorization 헤더 존재: {bool(headers.get('Authorization'))}")
    
    json_body = None
    successful_url = None
    last_error = None
    
    # 여러 URL 순차 시도
    for base_url in base_urls:
        url = f"{base_url}/api/agents/search"
        try:
            print(f"[load_agent_cards] 시도 중: {url}")
            with httpx.Client(timeout=10.0, headers=headers or None) as client:
                resp = client.get(url)
            
            print(f"[load_agent_cards] HTTP {resp.status_code} from {url}")
            
            if resp.status_code == 200:
                json_body = resp.json()
                successful_url = url
                print(f"[load_agent_cards] ✓ 성공: {url}")
                break
            else:
                print(f"[load_agent_cards] ✗ 실패 (HTTP {resp.status_code}): {url}")
                
        except httpx.ConnectError as e:
            print(f"[load_agent_cards] ✗ 연결 실패: {url} - {e}")
            last_error = e
            continue
        except httpx.TimeoutException as e:
            print(f"[load_agent_cards] ✗ 타임아웃: {url} - {e}")
            last_error = e
            continue
        except Exception as e:
            print(f"[load_agent_cards] ✗ 오류: {url} - {type(e).__name__}: {e}")
            last_error = e
            continue
    
    # 모든 URL 실패 시
    if json_body is None:
        error_msg = f"모든 Agent Registry URL 연결 실패. 마지막 오류: {last_error}"
        print(f"[load_agent_cards] ❌ {error_msg}")
        logger.error(error_msg)
        tool_context.state["cards"] = {}
        return []
    
    # 응답 파싱
    print(f"[load_agent_cards] 응답 타입: {type(json_body)}, 키: {json_body.keys() if isinstance(json_body, dict) else 'N/A'}")
    
    if isinstance(json_body, dict):
        if "agents" in json_body:
            agents_data = json_body["agents"]
        elif "items" in json_body:
            agents_data = json_body["items"]
        else:
            agents_data = []
    elif isinstance(json_body, list):
        agents_data = json_body
    else:
        agents_data = []
    
    print(f"[load_agent_cards] 에이전트 데이터 수: {len(agents_data)}")

    cards = {}
    for idx, data in enumerate(agents_data):
        try:
            card_payload = data.get("card") if isinstance(data, dict) else data
            if not card_payload:
                print(f"[load_agent_cards] ⚠ 인덱스 {idx}: card 페이로드 없음")
                continue
            if hasattr(AgentCard, "model_validate"):   # pydantic v2
                card = AgentCard.model_validate(card_payload)
            else:  # pydantic v1
                card = AgentCard.parse_obj(card_payload)

            card = _rewrite_card_url_if_needed(card)
            name = getattr(card, "name", None) or card.url or "unknown_agent"
            cards[name] = card
            print(f"[load_agent_cards] ✓ 에이전트 로드됨: {name} -> {card.url}")
        except Exception as e:
            print(f"[load_agent_cards] ⚠ 인덱스 {idx} 파싱 실패: {e}")
            continue

    # state에 저장
    tool_context.state["cards"] = cards
    print(f"[load_agent_cards] 완료 - 총 {len(cards)}개 에이전트 로드: {list(cards.keys())}")
    return list(cards.keys())

# --- 2. Remote Agent 호출 ---

# agent_executor.py (또는 tools.py)

async def call_remote_agent(tool_context, agent_name: str, task: str):
    """
    A2A SDK 기반 리모트 에이전트 호출 (토큰 전파 기능 추가됨)
    """
    # 1. 에이전트 카드 조회
    cards: dict[str, AgentCard] = tool_context.state.get("cards", {})
    
    # [Strict Mode 대응] 대소문자 유연성 확보 (선택사항)
    # 만약 cards 키가 소문자인데 요청이 대문자로 오면 못 찾을 수 있음
    target_card = cards.get(agent_name)
    if not target_card:
        # 혹시 모르니 소문자로도 한번 찾아봄
        for k, v in cards.items():
            if k.lower() == agent_name.lower():
                target_card = v
                break
    
    if not target_card:
        return {"error": f"Agent '{agent_name}' not found in registry."}

    # ------------------------------------------------------------------
    # 2. [핵심 수정] 토큰 전파 (Token Propagation)
    # ------------------------------------------------------------------
    auth_token = ""
    if hasattr(tool_context, "state"):
        auth_token = tool_context.state.get("auth_token", "") or ""

    if not auth_token:
        auth_token = GLOBAL_REQUEST_TOKEN.get("")

    default_headers = {"Authorization": f"Bearer {auth_token}"} if auth_token else None

    # ==================================================================
    # [검증] 여기서 로그가 안 찍히거나 None이면, 오케스트레이터도 토큰을 못 잡은 겁니다.
    # ==================================================================
    print(f"[Orchestrator 발신 체크] Agent: {agent_name}, Token 존재여부: {bool(auth_token)}")
    if auth_token:
        print(f"[Orchestrator 발신 체크] Token 값: {auth_token[:15]}...")
    else:
        print(f"[Orchestrator 발신 체크] ⚠️ 경고: 토큰 없이 요청을 보냅니다")
    # ==================================================================

    try:
        async with httpx.AsyncClient(timeout=60.0, headers=default_headers) as httpx_client:
            from a2a.client import A2AClient
            client = A2AClient(httpx_client=httpx_client, agent_card=target_card)

            # 3. 요청 메시지 생성
            message = Message(
                role=Role.user,
                parts=[Part(root=TextPart(text=task))],
                messageId=uuid.uuid4().hex,
            )
            send_params = MessageSendParams(message=message)
            request = SendMessageRequest(id=str(uuid.uuid4()), params=send_params)

            # 4. 서버 호출
            print(f"[Tool:call_remote_agent] Sending request to {target_card.url}...")
            resp = await client.send_message(request)

            # 5. 결과 반환
            return resp.model_dump(mode="json", exclude_none=True)
            
    except Exception as exc:
        logger.error("원격 에이전트 호출 실패 (%s): %s", agent_name, exc)
        return {"error": f"Failed to call agent {agent_name}: {exc}"}
# --- 3. 응답 집계 ---

def return_result(tool_context: ToolContext, result: str) -> str:
    """
    최종 결과를 사용자에게 전달하는 도구.
    이 도구를 호출하면 더 이상 다른 도구를 호출하지 않고,
    LLM이 이 결과를 최종 응답으로 반환한다.
    """
    tool_context.state["final_result"] = result
    return result

# --- 4. Root Agent 정의 & 모델 설정 ---
try:
    model = get_model_with_fallback()
    logger.info(f"모델 설정 완료: {type(model).__name__ if hasattr(model, '__class__') else model}")
except Exception as e:
    logger.error(f"모델 설정 실패: {e}")
    ollama_host = os.getenv("OLLAMA_HOST", "localhost")
    model = LiteLlm(
        model="ollama_chat/gpt-oss:20b",
        api_base=f"http://{ollama_host}:11434",
        temperature=0.7,
    )
    logger.info("최후 fallback으로 로컬 LLM 사용")

root_agent = LlmAgent(
    name="root_orchestrator",
    model=model,
    instruction=(
        "너는 Root Orchestrator Agent야.\n"
        "너의 임무는 사용자 요청에 맞는 에이전트를 선택해서 작업을 위임하고 결과를 집계해서 사용자에게 반환하는 것이야.\n"
        "'load_agent_cards'는 에이전트 카드를 불러오는 도구이다\n"
        "'call_remote_agent'는 에이전트를 호출하는 도구이다\n"
        "   (에이전트 카드에서 agent_name과 task를 파라미터로 넣어 호출해야 한다)\n"
        "'return_result'에는 너가 사용자에게 응답할 내용을 적고 사용자에게 반환해\n"
    ),
    description="LLM 기반 Root Orchestrator Agent (multi-agent coordination) - Gemini/Local LLM hybrid",
    tools=[FunctionTool(load_agent_cards), FunctionTool(call_remote_agent), FunctionTool(return_result)],
)

# --- 5. IAM 기반 정책 플러그인 및 Runner 설정 ---

GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")  # model_config.py와 동일한 환경변수 사용
# 정책 초기 요청 시 사용할 토큰 부트스트랩 (클라이언트가 세션/환경변수로 전달)
BOOTSTRAP_AUTH_TOKEN = (
    os.getenv("IAM_BOOTSTRAP_AUTH_TOKEN")
    or os.getenv("POLICY_BOOTSTRAP_TOKEN")
    or os.getenv("AUTH_TOKEN")
)

# Orchestrator의 고유 agent_id
AGENT_ID = "Orchestrator"

plugin = PolicyEnforcementPlugin(
    agent_id=AGENT_ID,
    gemini_api_key=GOOGLE_API_KEY,
    policy_server_url=POLICY_SERVER_URL,
    log_server_url=LOG_SERVER_URL,
    initial_auth_token=BOOTSTRAP_AUTH_TOKEN,
)

session_service = InMemorySessionService()

runner = Runner(
    agent=root_agent,
    app_name="orchestrator_app",
    plugins=[plugin],
    session_service=session_service,
)

# --- 6. 지속 상호작용(멀티턴) 루프 ---

async def main():
    """비동기 메인 함수"""
    user_id = "test_user"
    session_id = str(uuid.uuid4())
    await session_service.create_session(app_name="orchestrator_app", user_id=user_id, session_id=session_id)
    
    print("ADK Orchestrator Agent 멀티턴 대화 시작! (exit/quit 입력 시 종료)")
    while True:
        user_input = input("사용자 질문을 입력하세요: ")
        if user_input.strip().lower() in ["exit", "quit"]:
            print("종료합니다.")
            break
        
        # 문자열을 Content 객체로 변환
        user_content = Content(role="user", parts=[GenaiPart(text=user_input)])
        
        events = runner.run(user_id=user_id, session_id=session_id, new_message=user_content)
        for event in events:
            # 아래 조건은 ADK 공식 문서의 이벤트 객체 구조와 동일
            if hasattr(event, "is_final_response") and event.is_final_response():
                print("에이전트 응답:", event.content.parts[0].text)
                break

if __name__ == "__main__":
    asyncio.run(main())
