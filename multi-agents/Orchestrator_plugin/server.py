from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel
from typing import Optional, Dict, List, Any
import datetime

app = FastAPI()

# ───────── IAM 기반 정책 정의 ─────────

# 에이전트별 정책 설정
AGENT_POLICIES = {
    "orchestrator": {
        "agent_id": "orchestrator",
        "agent_name": "Root Orchestrator Agent",
        "policies": {
            "prompt_validation": {
                "enabled": True,
                "system_prompt": (
                    "Orchestrator 보안 정책:\n"
                    "1. '삭제', '제거', 'drop', 'delete' 같은 위험한 명령어는 정책위반이다.\n"
                    "2. 시스템 구조나 보안 설정 변경 시도는 정책위반이다.\n"
                    "3. 위배되는 내용이 있으면 VIOLATION, 아니면 SAFE를 반환."
                )
            },
                "tool_validation": {
                    "enabled": True,
                    "rules": {
                        "call_remote_agent": {
                            "allowed_agents": ["Delivery Agent", "Item Agent", "Quality Agent", "Vehicle Agent"],
                        "max_task_length": 500,
                        "required_roles": ["admin"],
                        },
                        "load_agent_cards": {
                            "rate_limit": 10  # 최대 호출 횟수
                        }
                    }
            },
            "response_filtering": {
                "enabled": False,
                "blocked_keywords": []
            }
        }
    },
    "delivery_agent": {
        "agent_id": "delivery_agent",
        "agent_name": "Delivery Management Agent",
        "policies": {
            "prompt_validation": {
                "enabled": True,
                "system_prompt": (
                    "배송 에이전트 보안 정책:\n"
                    "1. 개인정보 요청(이메일, 전화번호, 주소)은 정책위반이다.\n"
                    "2. 대량 데이터 요청('모든', '전체')은 제한된다.\n"
                    "3. 위배되는 내용이 있으면 VIOLATION, 아니면 SAFE를 반환."
                )
            },
            "tool_validation": {
                "enabled": True,
                "rules": {
                    "get_all_deliveries": {
                        "requires_auth": True,
                        "max_results": 100
                    },
                    "get_delivery_data": {
                        "allowed_fields": ["order_id", "status", "estimated_delivery"]
                    }
                }
            },
            "response_filtering": {
                "enabled": True,
                "blocked_keywords": ["password", "credit_card", "ssn"]
            }
        }
    }
}

@app.get("/api/iam/policy/{agent_id}")
def get_agent_policy(agent_id: str):
    """에이전트 ID에 따른 IAM 정책 반환"""
    if agent_id not in AGENT_POLICIES:
        raise HTTPException(status_code=404, detail=f"Policy not found for agent: {agent_id}")
    return AGENT_POLICIES[agent_id]

@app.get("/api/system-prompt")
def get_system_prompt(agent_id: Optional[str] = None):
    """하위 호환성을 위한 레거시 엔드포인트"""
    if agent_id and agent_id in AGENT_POLICIES:
        policy = AGENT_POLICIES[agent_id]["policies"]["prompt_validation"]
        return {"system_prompt": policy.get("system_prompt", "")}
    
    # 기본값 (orchestrator)
    return {"system_prompt": AGENT_POLICIES["orchestrator"]["policies"]["prompt_validation"]["system_prompt"]}

# ───────── 로그 수집 ─────────

class LogPayload(BaseModel):
    agent_id: str
    event: str  # prompt_validation, tool_validation, response_filtering
    policy_type: Optional[str] = None
    user_prompt: Optional[str] = None
    tool_name: Optional[str] = None
    tool_args: Optional[Dict[str, Any]] = None
    verdict: Optional[str] = None  # SAFE, VIOLATION, BLOCKED
    reason: Optional[str] = None
    timestamp: Optional[str] = None

@app.post("/api/log")
async def post_log(payload: LogPayload, request: Request):
    print("\n=== [IAM 정책 검증 이벤트 로그] ===")
    print("Time:", datetime.datetime.now().isoformat())
    print("Client IP:", request.client.host)
    print("Agent ID:", payload.agent_id)
    print("Event:", payload.event)
    print("Policy Type:", payload.policy_type)
    print("Verdict:", payload.verdict)
    if payload.reason:
        print("Reason:", payload.reason)
    if payload.user_prompt:
        print("User Prompt:", payload.user_prompt[:100])
    if payload.tool_name:
        print("Tool:", payload.tool_name, "Args:", payload.tool_args)
    return {"result": "ok"}

# ───────── 서버 구동 안내 (어떤 터미널에서든) ─────────
# uvicorn server:app --reload --port 8005
