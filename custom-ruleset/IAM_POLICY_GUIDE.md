# IAM 기반 정책 관리 시스템

## 개요

각 에이전트마다 서로 다른 보안 정책을 적용할 수 있는 IAM(Identity and Access Management) 기반 정책 시스템입니다.

## 주요 기능

### 1. **에이전트별 정책 분리**
- Orchestrator: 전체 시스템 조율 관련 정책
- DeliveryAgent: 배송 데이터 접근 관련 정책
- 각 에이전트는 고유한 `agent_id`를 가지며 서버에서 다른 정책을 받음

### 2. **다양한 검증 레이어**
- **프롬프트 검증** (`prompt_validation`): 사용자 입력 검사
- **툴 인자 검증** (`tool_validation`): 함수 호출 파라미터 검증
- **응답 필터링** (`response_filtering`): 민감 정보 차단 (확장 가능)

### 3. **유연한 정책 구조**
새로운 정책 유형을 쉽게 추가할 수 있는 확장 가능한 구조

## 아키텍처

```
┌─────────────────┐
│   User Request  │
└────────┬────────┘
         │
         ▼
┌─────────────────────────────────────────┐
│  PolicyEnforcementPlugin                │
│  ┌───────────────────────────────────┐  │
│  │ 1. Fetch IAM Policy from Server   │  │
│  │    (based on agent_id)            │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │ 2. Before Model Callback          │  │
│  │    → Prompt Validation            │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │ 3. Before Tool Callback           │  │
│  │    → Tool Argument Validation     │  │
│  └───────────────────────────────────┘  │
│  ┌───────────────────────────────────┐  │
│  │ 4. Send Logs to Server            │  │
│  └───────────────────────────────────┘  │
└─────────────────────────────────────────┘
         │
         ▼
┌─────────────────┐
│   LLM / Tools   │
└─────────────────┘
```

## 정책 서버 (server.py)

### 정책 구조

```python
AGENT_POLICIES = {
    "orchestrator": {
        "agent_id": "orchestrator",
        "agent_name": "Root Orchestrator Agent",
        "policies": {
            "prompt_validation": {
                "enabled": True,
                "system_prompt": "..."
            },
            "tool_validation": {
                "enabled": True,
                "rules": {
                    "tool_name": {
                        "allowed_agents": [...],
                        "max_task_length": 500
                    }
                }
            },
            "response_filtering": {
                "enabled": False,
                "blocked_keywords": []
            }
        }
    }
}
```

### API 엔드포인트

#### 1. 정책 조회
```http
GET /api/iam/policy/{agent_id}
```

**응답 예시:**
```json
{
  "agent_id": "orchestrator",
  "agent_name": "Root Orchestrator Agent",
  "policies": {
    "prompt_validation": { ... },
    "tool_validation": { ... },
    "response_filtering": { ... }
  }
}
```

#### 2. 로그 전송
```http
POST /api/log
Content-Type: application/json

{
  "agent_id": "delivery_agent",
  "event": "prompt_validation",
  "policy_type": "prompt",
  "user_prompt": "모든 배송 정보 알려줘",
  "verdict": "VIOLATION",
  "reason": "대량 데이터 요청 제한"
}
```

## PolicyEnforcementPlugin

### 초기화

```python
plugin = PolicyEnforcementPlugin(
    agent_id="orchestrator",           # 에이전트 고유 ID
    gemini_api_key=GEMINI_API_KEY,     # LLM 검증용
    policy_server_url="http://localhost:8005",
    log_server_url="http://localhost:8005"
)
```

### 콜백 메서드

#### 1. `before_model_callback` - 프롬프트 검증
```python
async def before_model_callback(self, *, callback_context, llm_request, **kwargs):
    # 1. 최신 사용자 메시지 추출
    # 2. IAM 정책의 system_prompt로 LLM 검증
    # 3. VIOLATION이면 거부 메시지 반환
    # 4. SAFE면 None 반환 (정상 진행)
```

#### 2. `before_tool_callback` - 툴 인자 검증
```python
async def before_tool_callback(self, *, callback_context, tool_call, **kwargs):
    # 1. 툴 이름과 인자 추출
    # 2. IAM 정책의 tool_validation 규칙 확인
    # 3. 규칙 위반 시 에러 반환 (툴 호출 차단)
    # 4. 통과 시 None 반환
```

## 정책 예시

### Orchestrator 정책

```python
"orchestrator": {
    "policies": {
        "prompt_validation": {
            "enabled": True,
            "system_prompt": (
                "1. '모든'이라는 단어가 들어가면 정책위반\n"
                "2. '삭제', '제거' 같은 위험한 명령어는 정책위반\n"
                "3. 위배 → VIOLATION, 아니면 SAFE"
            )
        },
        "tool_validation": {
            "enabled": True,
            "rules": {
                "call_remote_agent": {
                    "allowed_agents": ["delivery_agent", "item_agent"],
                    "max_task_length": 500
                }
            }
        }
    }
}
```

### JWT 역할 기반 테스트 방법

정책이 JWT 토큰 역할에 따라 다르게 적용되는지 확인하려면 아래 테스트를 실행하세요.

```bash
pytest iam/tests/test_policy_enforcement.py
```

- `roles` 클레임에 `admin`이 포함된 토큰이면 `call_remote_agent` 툴 호출이 허용됩니다.
- `roles`가 `admin`이 아닌 토큰이거나 역할 클레임이 없는 경우 정책에 의해 차단되며, 에러 메시지로 필요한 역할 정보를 확인할 수 있습니다.

### DeliveryAgent 정책

```python
"delivery_agent": {
    "policies": {
        "prompt_validation": {
            "enabled": True,
            "system_prompt": (
                "1. 개인정보 요청(이메일, 전화번호, 주소)은 정책위반\n"
                "2. 대량 데이터 요청('모든', '전체')은 제한\n"
                "3. 위배 → VIOLATION, 아니면 SAFE"
            )
        },
        "tool_validation": {
            "enabled": True,
            "rules": {
                "get_all_deliveries": {
                    "requires_auth": True,
                    "max_results": 100
                }
            }
        },
        "response_filtering": {
            "enabled": True,
            "blocked_keywords": ["password", "credit_card", "ssn"]
        }
    }
}
```

## 툴 검증 규칙

### 지원되는 규칙 유형

1. **`allowed_agents`** - 허용된 에이전트 목록
   ```python
   "allowed_agents": ["delivery_agent", "item_agent"]
   ```

2. **`max_task_length`** - 작업 설명 최대 길이
   ```python
   "max_task_length": 500
   ```

3. **`requires_auth`** - 인증 필요 여부
   ```python
   "requires_auth": True
   ```

4. **`max_results`** - 최대 결과 수
   ```python
   "max_results": 100
   ```

5. **`required_roles`** - JWT에 포함된 역할 기반 접근 제어
   ```python
   "required_roles": ["admin", "superuser"]
   ```
   `policy_enforcement.py`가 JWT 토큰을 해석해 `roles`, `role`, `permissions`, `scope` 클레임을 조회합니다. 값이 문자열이면 공백으로 분리하고, 배열이면 각 항목을 모두 비교합니다. 최소 한 개의 요구 역할이 사용자 토큰에 있어야 툴 호출이 허용됩니다.

### 새 규칙 추가 방법

`policy_enforcement_plugin.py`의 `_check_tool_rule` 메서드에 추가:

```python
def _check_tool_rule(self, tool_name: str, tool_args: Dict, rule: Dict) -> Optional[str]:
    # 기존 규칙...
    
    # 새 규칙 추가
    if "min_price" in rule:
        price = tool_args.get("price", 0)
        if price < rule["min_price"]:
            return f"Price ({price}) below minimum ({rule['min_price']})"
    
    return None
```

## 사용 방법

### 1. 정책 서버 시작

```bash
cd Attager/Orchestrator_plugin
uvicorn server:app --reload --port 8005
```

### 2. Orchestrator 실행

```bash
cd Attager/Orchestrator_plugin
python agent.py
```

### 3. DeliveryAgent 실행

```bash
cd Attager/agents/delivery_agent
python agent.py
```

## 로그 확인

정책 서버 콘솔에서 실시간 로그 확인:

```
=== [IAM 정책 검증 이벤트 로그] ===
Time: 2025-11-09T...
Client IP: 127.0.0.1
Agent ID: delivery_agent
Event: prompt_validation
Policy Type: prompt
Verdict: VIOLATION
Reason: 대량 데이터 요청 제한
User Prompt: 모든 배송 정보 알려줘
```

## 확장 가능성

### 새로운 정책 유형 추가

1. **서버에 정책 정의 추가** (`server.py`)
   ```python
   "my_new_policy": {
       "enabled": True,
       "config": { ... }
   }
   ```

2. **플러그인에 콜백 추가** (`policy_enforcement_plugin.py`)
   ```python
   async def after_model_callback(self, *, callback_context, llm_response, **kwargs):
       # 응답 후처리 로직
       pass
   ```

3. **규칙 검증 로직 구현**
   ```python
   def _validate_my_policy(self, data):
       # 검증 로직
       pass
   ```

## 보안 고려사항

1. **Fail-open vs Fail-close**: 현재는 정책 로드 실패 시 통과 (fail-open)
2. **Rate Limiting**: 툴 호출 횟수 제한 추가 가능
3. **Audit Logging**: 모든 정책 검증 이벤트 로그 저장
4. **Dynamic Policy Update**: 서버 재시작 없이 정책 업데이트 가능

## 문제 해결

### 정책이 적용되지 않는 경우
1. 정책 서버가 실행 중인지 확인
2. `agent_id`가 서버의 `AGENT_POLICIES`에 정의되어 있는지 확인
3. 플러그인 초기화 시 올바른 URL 사용 확인

### 툴 검증이 작동하지 않는 경우
1. `tool_validation.enabled`가 `True`인지 확인
2. 툴 이름이 정확히 일치하는지 확인 (대소문자 구분)
3. `before_tool_callback`이 호출되는지 로그 확인

## 향후 개선 사항

- [ ] 정책 동적 업데이트 (캐시 무효화)
- [ ] 응답 필터링 구현
- [ ] 정책 버전 관리
- [ ] 사용자별 권한 관리
- [ ] 정책 테스트 도구
- [ ] 대시보드 UI

