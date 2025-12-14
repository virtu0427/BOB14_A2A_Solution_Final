import click
import uvicorn
from starlette.requests import Request  # type: ignore[unused-import]
from starlette.responses import JSONResponse
from starlette.routing import Route

from a2a.types import (
    AgentCapabilities,
    AgentCard,
    AgentSkill,
)
from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from Orchestrator_plugin.agent import (
    plugin as policy_plugin,
    root_agent as orchestrator_agent,
)
from Orchestrator_plugin.agent_executor import ADKAgentExecutor
from iam.policy_enforcement import GLOBAL_REQUEST_TOKEN

def main(inhost: str, inport: int):
    """Launch the orchestrator agent server."""
    agent_card = AgentCard(
        name="Orchestrator Agent",
        description=orchestrator_agent.description,
        url=f"http://{inhost}:{inport}",
        version="1.0.0",
        defaultInputModes=["text", "text/plain"],
        defaultOutputModes=["text", "text/plain"],
        capabilities=AgentCapabilities(streaming=True),
        skills=[
            AgentSkill(
                id="orchestrator_agent",
                name="orchestrate other agents",
                description="Orchestrate other agents by user requestment",
                tags=["orchestrator"],
                examples=[
                    "What agent should I use to get delivery data for ORD1001",
                ],
            )
        ],
    )

    request_handler = DefaultRequestHandler(
        agent_executor=ADKAgentExecutor(
            agent=orchestrator_agent, plugins=[policy_plugin]
        ),
        task_store=InMemoryTaskStore(),
    )

    server = A2AStarletteApplication(
        agent_card=agent_card,
        http_handler=request_handler,
    )

    # Build the Starlette app first so we can attach middleware that captures
    # the incoming Authorization header. The PolicyEnforcementPlugin and
    # remote tool callers both rely on GLOBAL_REQUEST_TOKEN to propagate the
    # caller's JWT to downstream agents.
    app = server.build()

    # ------------------------------------------------------------------
    # 정책 캐시 새로고침 API 엔드포인트
    # ------------------------------------------------------------------
    async def refresh_policy_handler(request: Request):
        """정책 캐시를 비우고 새로고침합니다."""
        try:
            body = {}
            try:
                body = await request.json()
            except Exception:
                pass
            
            tenant = body.get("tenant") if body else None
            result = policy_plugin.clear_policy_cache(tenant=tenant)
            
            return JSONResponse({
                "success": True,
                "message": "정책 캐시가 새로고침되었습니다.",
                "details": result,
            })
        except Exception as e:
            return JSONResponse({
                "success": False,
                "error": str(e),
            }, status_code=500)

    async def get_cache_status_handler(request: Request):
        """현재 정책 캐시 상태를 반환합니다."""
        try:
            status = policy_plugin.get_cache_status()
            return JSONResponse({
                "success": True,
                "cache": status,
            })
        except Exception as e:
            return JSONResponse({
                "success": False,
                "error": str(e),
            }, status_code=500)

    # 기존 라우트에 추가
    app.routes.append(Route("/api/refresh-policy", refresh_policy_handler, methods=["POST"]))
    app.routes.append(Route("/api/cache-status", get_cache_status_handler, methods=["GET"]))

    @app.middleware("http")
    async def token_capture_middleware(request, call_next):
        auth_header = request.headers.get("Authorization") or request.headers.get("authorization")

        token_reset_token = None
        if auth_header:
            token_val = auth_header
            if token_val.lower().startswith("bearer "):
                token_val = token_val[7:].strip()

            token_reset_token = GLOBAL_REQUEST_TOKEN.set(token_val)
            print(f"[1. Middleware] 토큰을 GLOBAL_VAR에 저장함: {token_val[:10]}...", flush=True)
        else:
            print("[1. Middleware] 헤더 없음", flush=True)

        try:
            response = await call_next(request)
            return response
        finally:
            if token_reset_token:
                GLOBAL_REQUEST_TOKEN.reset(token_reset_token)

    uvicorn.run(app, host=inhost, port=inport)


@click.command()
@click.option("--host", "inhost", default="0.0.0.0", help="Host to bind the orchestrator server.")
@click.option("--port", "inport", default=10000, type=int, help="Port to bind the orchestrator server.")
def cli(inhost: str, inport: int):
    main(inhost, inport)


if __name__ == "__main__":
    cli()
