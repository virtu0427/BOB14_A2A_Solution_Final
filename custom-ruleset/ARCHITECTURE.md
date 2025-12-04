# Attager IAM System Architecture

## 시스템 구조 개요

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Interface                          │
│                   (Web Browser - Port 8006)                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ┌────────▼────────┐
                    │  Frontend App   │
                    │  (Flask)        │
                    │  Port: 8006     │
                    └────────┬────────┘
                             │
                    ┌────────▼────────┐
                    │  Redis (IAM)    │
                    │  Port: 6380     │
                    │  용도: IAM 정책   │
                    │  - Agents       │
                    │  - Rulesets     │
                    │  - Policies     │
                    │  - Logs         │
                    └─────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      Policy Server Layer                        │
└─────────────────────────────────────────────────────────────────┘

                    ┌────────────────┐
                    │ Policy Server  │
                    │ (FastAPI)      │
                    │ Port: 8005     │
                    └────┬───────────┘
                         │
                         │ (Fetch Policies & Log Events)
                         │
                    ┌────▼───────────┐
                    │  Redis (IAM)   │
                    │  Port: 6380    │
                    └────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                      Agent Execution Layer                      │
└─────────────────────────────────────────────────────────────────┘

┌──────────────────┐  ┌──────────────────┐  ┌──────────────────┐
│  Orchestrator    │  │ Delivery Agent   │  │  Item Agent      │
│  + Plugin        │  │  + Plugin        │  │  + Plugin        │
│  Port: Local     │  │  Port: 10001     │  │  Port: 10002     │
└────┬─────────────┘  └────┬─────────────┘  └────┬─────────────┘
     │                     │                     │
     │ (Policy Check)      │ (Policy Check)      │ (Policy Check)
     │                     │                     │
     └─────────────────────┼─────────────────────┘
                           │
                  ┌────────▼────────┐
                  │ Policy Server   │
                  │ Port: 8005      │
                  └────────┬────────┘
                           │
                  ┌────────▼────────┐
                  │ Redis (IAM)     │
                  │ Port: 6380      │
                  └─────────────────┘

┌──────────────────┐  ┌──────────────────┐
│ Quality Agent    │  │ Vehicle Agent    │
│  + Plugin        │  │  + Plugin        │
│  Port: 10003     │  │  Port: 10004     │
└────┬─────────────┘  └────┬─────────────┘
     │                     │
     │ (Data Access)       │ (Data Access)
     │                     │
     └─────────────────────┘
                           │
                  ┌────────▼────────┐
                  │ Redis (Agents)  │
                  │ Port: 6379      │
                  │ 용도: 에이전트 데이터│
                  │ - 배송 정보       │
                  │ - 상품 정보       │
                  │ - 품질 데이터     │
                  │ - 차량 정보       │
                  └─────────────────┘
```

## Redis 분리 구조

### Redis (Agents) - Port 6379
**용도**: 에이전트의 비즈니스 데이터 저장
- 배송 정보 (Delivery Agent)
- 상품 정보 (Item Agent)
- 품질 데이터 (Quality Agent)
- 차량 정보 (Vehicle Agent)

**접근**:
- Delivery Agent
- Item Agent
- Quality Agent
- Vehicle Agent

### Redis (IAM) - Port 6380
**용도**: IAM 정책 및 보안 로그 저장
- Agents 정보 (`agents:{agent_id}`)
- Rulesets (`rulesets:{ruleset_id}`)
- Policies (`policies:{policy_id}`)
- Security Logs (`logs:all`)

**접근**:
- Frontend App (8006)
- Policy Server (8005)

## 데이터 흐름

### 1. 정책 관리 흐름 (Admin → IAM)
```
User → Frontend (8006) → Redis (IAM, 6380)
```

### 2. 정책 적용 흐름 (Agent → Policy Check)
```
Agent → Policy Plugin → Policy Server (8005) → Redis (IAM, 6380)
      ↓
   Verdict (PASS/VIOLATION)
```

### 3. 로그 기록 흐름
```
Agent → Policy Plugin → Policy Server (8005) → Redis (IAM, 6380)
                                                    ↓
                                         Frontend (8006) 조회 가능
```

### 4. 에이전트 데이터 접근 흐름
```
Agent → Business Logic → Redis (Agents, 6379)
```

## 컴포넌트 설명

### Frontend (Flask - Port 8006)
- **역할**: IAM 관리 웹 UI
- **기능**:
  - Dashboard: 시스템 통계 및 현황
  - Agents: 에이전트 목록 및 정책 조회
  - Ruleset: 정책 룰셋 CRUD
  - Logs: 보안 이벤트 로그 모니터링
- **연결**: Redis (IAM, 6380)

### Policy Server (FastAPI - Port 8005)
- **역할**: 에이전트용 정책 API 서버
- **기능**:
  - `/api/iam/policy/{agent_id}`: 에이전트별 정책 제공
  - `/api/logs`: 보안 이벤트 로그 수집
  - `/api/system-prompt`: 레거시 호환 엔드포인트
- **연결**: Redis (IAM, 6380)

### Policy Enforcement Plugin
- **역할**: 에이전트에 적용되는 정책 검증 플러그인
- **기능**:
  - `before_model_callback`: 프롬프트 검증
  - `before_tool_callback`: 툴 호출 검증
  - 정책 위반 시 차단 및 로깅
- **연결**: Policy Server (8005)

### Agents
- **역할**: 비즈니스 로직 실행
- **구성**:
  - Orchestrator: 작업 조율
  - Delivery Agent: 배송 관리
  - Item Agent: 상품 관리
  - Quality Agent: 품질 관리
  - Vehicle Agent: 차량 관리
- **연결**:
  - Policy Server (8005) - 정책 검증
  - Redis (Agents, 6379) - 데이터 저장

## 보안 정책 적용 과정

### 1. Prompt Validation
```
User Input
    ↓
Policy Plugin (before_model_callback)
    ↓
Fetch Policy from Redis (IAM)
    ↓
LLM Inspection (Gemini)
    ↓
PASS → Continue | VIOLATION → Block & Log
```

### 2. Tool Validation
```
Tool Call Request
    ↓
Policy Plugin (before_tool_callback)
    ↓
Fetch Policy from Redis (IAM)
    ↓
Validate Arguments (allowed_agents, max_length, etc.)
    ↓
ALLOWED → Execute | BLOCKED → Reject & Log
```

## 환경 변수 구성

### Frontend & Policy Server
```bash
REDIS_HOST=redis-iam  # Docker: redis-iam, Local: localhost
REDIS_PORT=6379       # Container 내부 포트 (외부는 6380)
PORT=8006            # Frontend
PORT=8005            # Policy Server
```

### Agents
```bash
# 정책 서버 연결
POLICY_SERVER_URL=http://policy-server:8005
LOG_SERVER_URL=http://policy-server:8005

# 에이전트 데이터 Redis (필요 시 AGENT_REDIS_* 로 오버라이드 가능)
REDIS_HOST=redis-agents  # Docker: redis-agents, Local: localhost
REDIS_PORT=6379
AGENT_REDIS_HOST=redis-agents
AGENT_REDIS_PORT=6379
AGENT_REDIS_DB=0

# API Key
GEMINI_API_KEY=your-api-key
```

## 포트 매핑

| Service          | Container Port | Host Port | 용도                |
|------------------|----------------|-----------|---------------------|
| redis-agents     | 6379          | 6379      | 에이전트 데이터      |
| redis-iam        | 6379          | 6380      | IAM 정책 및 로그    |
| policy-server    | 8005          | 8005      | 정책 API            |
| frontend         | 8006          | 8006      | 웹 UI               |
| delivery-agent   | 10001         | 10001     | 배송 에이전트       |
| item-agent       | 10002         | 10002     | 상품 에이전트       |
| quality-agent    | 10003         | 10003     | 품질 에이전트       |
| vehicle-agent    | 10004         | 10004     | 차량 에이전트       |

## 데이터 독립성

### Redis (Agents) - 비즈니스 데이터
- 에이전트 간 공유되는 비즈니스 데이터
- 배송, 상품, 품질, 차량 정보
- IAM 시스템과 완전히 독립적

### Redis (IAM) - 보안 정책 데이터
- IAM 정책 및 룰셋
- 보안 이벤트 로그
- 에이전트의 비즈니스 데이터와 완전히 분리

## 확장성

### 새 에이전트 추가
1. Docker Compose에 에이전트 서비스 추가
2. Frontend의 `database.py`에 기본 Agent 정보 추가
3. Policy 및 Ruleset 생성 (Frontend UI 사용)

### 새 Ruleset 타입 추가
1. Frontend의 `ruleset.js`에 타입 추가
2. `policy_enforcement_plugin.py`에 검증 로직 추가
3. Database 스키마는 유연하게 설계되어 추가 필요 없음

## 백업 및 복구

### Redis (IAM) 백업
```bash
# 백업
docker exec attager-redis-iam redis-cli SAVE
docker cp attager-redis-iam:/data/dump.rdb ./backup/iam-backup.rdb

# 복구
docker cp ./backup/iam-backup.rdb attager-redis-iam:/data/dump.rdb
docker restart attager-redis-iam
```

### Redis (Agents) 백업
```bash
# 백업
docker exec attager-redis-agents redis-cli SAVE
docker cp attager-redis-agents:/data/dump.rdb ./backup/agents-backup.rdb

# 복구
docker cp ./backup/agents-backup.rdb attager-redis-agents:/data/dump.rdb
docker restart attager-redis-agents
```

