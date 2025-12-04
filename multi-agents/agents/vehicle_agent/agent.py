# vehicle_agent.py
import asyncio
import os
import logging
import sys

# 프로젝트 루트 디렉토리를 PYTHONPATH에 추가 (로컬 실행용)
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
sys.path.insert(0, project_root)

from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.adk.models.lite_llm import LiteLlm
from google.genai import types
from google.adk.tools import FunctionTool

# 현재 폴더의 .env 파일 로드
load_dotenv()

# Docker와 로컬 환경 모두 지원하는 import
try:
    # Docker 환경 (현재 디렉토리가 /app)
    from tools.redis_vehicle_tools import (
        get_fleet_availability,
        get_vehicle_status,
        filter_available_vehicles,
        get_vehicles_on_maintenance,
        get_assigned_recall_vehicles,
        get_vehicle_capacity,
        recommend_optimal_vehicles,
    )
except ImportError:
    # 로컬 환경 (agents/vehicle_agent/)
    from agents.vehicle_agent.tools.redis_vehicle_tools import (
        get_fleet_availability,
        get_vehicle_status,
        filter_available_vehicles,
        get_vehicles_on_maintenance,
        get_assigned_recall_vehicles,
        get_vehicle_capacity,
        recommend_optimal_vehicles,
    )

from iam.policy_enforcement import PolicyEnforcementPlugin

# utils는 프로젝트 루트에 있으므로 별도 처리
try:
    from utils.model_config import get_model_with_fallback
except ImportError:
    # Docker에서 utils가 없으면 직접 fallback
    get_model_with_fallback = None

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# --- 1. Agent 정의 ---
# Gemini 우선, 실패시 로컬 LLM 사용
try:
    if get_model_with_fallback:
        model = get_model_with_fallback()
        logger.info(f"VehicleAgent 모델 설정 완료: {type(model).__name__ if hasattr(model, '__class__') else model}")
    else:
        raise ImportError("utils.model_config not available in Docker")
except Exception as e:
    logger.error(f"VehicleAgent 모델 설정 실패: {e}")
    # 최후의 fallback
    ollama_host = os.getenv("OLLAMA_HOST", "localhost")
    model = LiteLlm(
        model="ollama_chat/gpt-oss:20b",
        api_base=f"http://{ollama_host}:11434"
    )
    logger.info("VehicleAgent 최후 fallback으로 로컬 LLM 사용")

root_agent = LlmAgent(
    model=model,
    name="VehicleAgent",
    description="Redis에 저장된 차량 정보를 관리하는 에이전트 - Gemini/Local LLM hybrid",
    instruction="""너는 배차/차량 운영 에이전트다.
    - '전체 가용 현황'을 요청하면 get_fleet_availability 툴을 호출해야 한다.
    - '차량 상태 조회'를 요청하면 get_vehicle_status 툴을 호출해야 한다.
    - '운행 가능 차량 필터링'을 요청하면 filter_available_vehicles 툴을 호출해야 한다.
    - '현재 정비 중인 차량'을 요청하면 get_vehicles_on_maintenance 툴을 호출해야 한다.
    - '리콜에 배정된 차량 리스트'를 요청하면 get_assigned_recall_vehicles 툴을 호출해야 한다.
    - '차량 적재 용량'을 조회하려면 get_vehicle_capacity 툴을 호출해야 한다.
    - '최적 차량 추천'을 요청하면 recommend_optimal_vehicles 툴을 호출해야 한다.
    """,
        tools=[
        FunctionTool(get_fleet_availability),
        FunctionTool(get_vehicle_status),
        FunctionTool(filter_available_vehicles),
        FunctionTool(get_vehicles_on_maintenance),
        FunctionTool(get_assigned_recall_vehicles),
        FunctionTool(get_vehicle_capacity),
        FunctionTool(recommend_optimal_vehicles),
    ],
)

# --- 2. IAM 기반 정책 플러그인 설정 ---
GOOGLE_API_KEY = os.getenv("GOOGLE_API_KEY")  # model_config.py와 동일한 환경변수 사용
# Docker 환경에서는 host.docker.internal, 로컬에서는 localhost
POLICY_SERVER_URL = os.getenv("POLICY_SERVER_URL", "http://localhost:8005")
LOG_SERVER_URL = os.getenv("LOG_SERVER_URL", "http://localhost:8005")
BOOTSTRAP_AUTH_TOKEN = (
    os.getenv("IAM_BOOTSTRAP_AUTH_TOKEN")
    or os.getenv("POLICY_BOOTSTRAP_TOKEN")
    or os.getenv("AUTH_TOKEN")
)

# VehicleAgent의 고유 agent_id (Orchestrator와 다른 정책 적용)
AGENT_ID = "VehicleAgent"

plugin = PolicyEnforcementPlugin(
    agent_id=AGENT_ID,
    gemini_api_key=GOOGLE_API_KEY,
    policy_server_url=POLICY_SERVER_URL,
    log_server_url=LOG_SERVER_URL,
    initial_auth_token=BOOTSTRAP_AUTH_TOKEN,
)

# --- 3. Runner + 세션 서비스 (플러그인 포함) ---
APP_NAME = "simple_vehicle_app"
USER_ID = "user1"
SESSION_ID = "sess1"

session_service = InMemorySessionService()
runner = Runner(
    agent=root_agent,
    app_name=APP_NAME,
    session_service=session_service,
    plugins=[plugin]
)

# --- 4. 실행 ---
async def main():
    await session_service.create_session(
        app_name=APP_NAME, user_id=USER_ID, session_id=SESSION_ID
    )

    print(">>> User Input: 전체 차량 가용 현황 알려줘")
    final_response = "응답 없음"
    user_message = types.Content(
        role="user",
        parts=[types.Part(text="전체 차량 가용 현황 알려줘")]
    )

    async for event in runner.run_async(
        user_id=USER_ID,
        session_id=SESSION_ID,
        new_message=user_message,
    ):
        print(f"[DEBUG EVENT] {event}")  # 이벤트 구조 확인

        if event.content and event.content.parts:
            for part in event.content.parts:
                if hasattr(part, "text") and part.text:
                    final_response = part.text
    
    if not final_response.strip():
        final_response = "응답 없음"

    print(f"<<< Agent Response: {final_response}")


if __name__ == "__main__":
    asyncio.run(main())   # 여기서는 에이전트 실행만
