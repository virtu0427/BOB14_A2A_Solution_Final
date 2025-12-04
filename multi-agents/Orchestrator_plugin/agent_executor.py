import logging
from uuid import uuid4

from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.types import Message, TextPart, Part, Role
from google.adk.errors.already_exists_error import AlreadyExistsError
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types
from iam.policy_enforcement import GLOBAL_REQUEST_TOKEN

logger = logging.getLogger(__name__)
_DEFAULT_USER_ERROR = "요청을 처리하는 중 오류가 발생했습니다. 잠시 후 다시 시도해주세요."


class ADKAgentExecutor(AgentExecutor):
    def __init__(
        self,
        agent,
        *,
        app_name: str = "orchestrator_app",
        user_id: str = "user1",
        session_id: str | None = None,
        plugins=None,
    ):
        self.agent = agent
        self.app_name = app_name
        self.user_id = user_id
        self.session_id = session_id or uuid4().hex
        self._session_created = False
        self.plugins = plugins or []
        self.session_service = InMemorySessionService()
        self.runner = Runner(
            agent=self.agent,
            app_name=self.app_name,
            session_service=self.session_service,
            plugins=self.plugins,
        )

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        try:
            # 세션 보장
            if not self._session_created:
                try:
                    await self.session_service.create_session(
                        app_name=self.app_name, user_id=self.user_id, session_id=self.session_id
                    )
                except AlreadyExistsError:
                    logger.debug("Session already exists; reusing existing session %s", self.session_id)
                finally:
                    self._session_created = True

            # 사용자 입력 추출
            user_input = ""
            if context.message and context.message.parts:
                user_input = " ".join(
                    getattr(p.root, "text", "")
                    for p in context.message.parts
                    if hasattr(p.root, "text")
                )

            user_message = types.Content(role="user", parts=[types.Part(text=user_input)])

            final_response = None

            # Runner 실행 → 이벤트 스트림 수집
            callback_context = self._build_callback_context(context)

            # Pass the request headers/metadata to plugins before execution so
            # policy enforcement can capture the client JWT on the very first
            # fetch.
            for plugin in self.plugins:
                try:
                    plugin._capture_auth_from_context(callback_context)  # noqa: SLF001
                except Exception:
                    logger.exception("플러그인 사전 준비 중 오류")

            async for event in self.runner.run_async(
                user_id=self.user_id,
                session_id=self.session_id,
                new_message=user_message,
                run_config=None,
            ):
                if event.content and event.content.parts:
                    for part in event.content.parts:
                        if getattr(part, "text", None):
                            final_response = part.text

            if not final_response:
                final_response = "응답 없음"

            # 결과 Message 반환 (messageId 필수)
            msg = Message(
                role=Role.agent,
                parts=[Part(root=TextPart(text=final_response))],
                messageId=uuid4().hex,
            )
            await event_queue.enqueue_event(msg)

        except Exception as e:
            logger.exception("ADKAgentExecutor.execute 오류")
            safe_error = self._format_user_error(str(e))
            error_msg = Message(
                role=Role.agent,
                parts=[Part(root=TextPart(text=safe_error))],
                messageId=uuid4().hex,
            )
            await event_queue.enqueue_event(error_msg)

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        return

    def _build_callback_context(self, context: RequestContext) -> dict:
        headers = {}
        state = {}
        if getattr(context, "call_context", None):
            state = getattr(context.call_context, "state", {}) or {}
            headers = state.get("headers") or {}
        message = getattr(context, "message", None)
        message_metadata = {}
        task_id = None
        message_id = None
        if message is not None:
            message_metadata = getattr(message, "metadata", {}) or {}
            task_id = getattr(message, "taskId", None) or message_metadata.get("taskId")
            message_id = getattr(message, "messageId", None)

        # Ensure downstream plugins and tools can access the caller token even
        # if the request handler didn't attach headers/state. We rely on the
        # GLOBAL_REQUEST_TOKEN set by the middleware in __main__.py.
        token = GLOBAL_REQUEST_TOKEN.get(None)

        safe_headers = dict(headers) if isinstance(headers, dict) else {}
        safe_state = dict(state) if isinstance(state, dict) else {}

        if token:
            safe_headers.setdefault("Authorization", f"Bearer {token}")
            safe_state.setdefault("auth_token", token)

        return {
            "headers": safe_headers,
            "metadata": getattr(context, "metadata", {}) or {},
            "state": safe_state,
            "message": {
                "metadata": message_metadata,
                "taskId": task_id,
                "messageId": message_id,
            },
        }

    def _format_user_error(self, raw_message: str) -> str:
        message = raw_message or ""
        for plugin in self.plugins:
            sanitizer = getattr(plugin, "sanitize_error_message", None)
            if callable(sanitizer):
                try:
                    return sanitizer(message)
                except Exception:  # pragma: no cover - defensive
                    logger.exception("에러 메시지 정제 실패")
        condensed = message.strip()
        if condensed:
            if len(condensed) > 200:
                condensed = condensed[:200] + "..."
            return f"{_DEFAULT_USER_ERROR}\n세부 정보: {condensed}"
        return _DEFAULT_USER_ERROR
