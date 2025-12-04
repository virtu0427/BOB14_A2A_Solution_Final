import click
import uvicorn
from starlette.requests import Request # 타입 힌트용

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
)
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from agent import root_agent as vehicle_agent, plugin

# [수정] agent_executor에서 정의한 변수를 import
from agent_executor import ADKAgentExecutor
from iam.policy_enforcement import GLOBAL_REQUEST_TOKEN

def main(inhost, inport):
    # Agent card (metadata)
    agent_card = AgentCard(
        name='Vehicle Agent',
        description=vehicle_agent.description,
        url=f'http://{inhost}:{inport}',
        version="1.0.0",
        defaultInputModes=["text", "text/plain"],
        defaultOutputModes=["text", "text/plain"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[
            AgentSkill(
                id="vehicle_agent",
                name="manage fleet operations",
                description="Handle vehicle availability, fleet management, and dispatch optimization",
                tags=["vehicle", "fleet", "dispatch", "maintenance"],
                examples=[
                    "Get fleet availability status",
                    "Check vehicle status",
                    "Filter available vehicles",
                    "Get vehicles on maintenance",
                    "Recommend optimal vehicles"
                ],
            )
        ],
    )

    request_handler = DefaultRequestHandler(
        agent_executor=ADKAgentExecutor(
            agent=vehicle_agent,
            plugins=[plugin]
        ),
        task_store=InMemoryTaskStore(),
    )

    # 1. A2A 앱 생성
    server_app = A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=request_handler,
    )

    # 2. [수정] .build()를 먼저 호출하여 Starlette 앱 객체를 얻습니다.
    app = server_app.build()

    # 3. [수정] 미들웨어 추가: 헤더를 낚아채서 ContextVar에 저장
    @app.middleware("http")
    async def token_capture_middleware(request, call_next):
        auth_header = request.headers.get("Authorization") or request.headers.get("authorization")
        
        token_reset_token = None
        if auth_header:
            token_val = auth_header
            if token_val.lower().startswith("bearer "):
                token_val = token_val[7:].strip()
            
            # [여기!] 플러그인이 볼 수 있는 변수에 저장
            token_reset_token = GLOBAL_REQUEST_TOKEN.set(token_val)
            print(f"[1. Middleware] 토큰을 GLOBAL_VAR에 저장함: {token_val[:10]}...", flush=True)
        else:
            print(f"[1. Middleware] 헤더 없음", flush=True)

        try:
            response = await call_next(request)
            return response
        finally:
            # (선택사항) 요청 처리가 끝나면 변수 초기화 (메모리 누수 방지)
            if token_reset_token:
                GLOBAL_REQUEST_TOKEN.reset(token_reset_token)

    print(f"Vehicle Agent Running on {inhost}:{inport}", flush=True)
    uvicorn.run(app, host=inhost, port=inport)


if __name__ == "__main__":
    main("0.0.0.0", 10004)