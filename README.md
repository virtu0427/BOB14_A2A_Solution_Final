# A2A Multi-Agent + IAM Stack

다중 에이전트 오케스트레이션과 IAM(JWT/JWS) 서비스를 한 번에 실행할 수 있는 예제 스택입니다.

## 폴더 한눈에 보기
📁 Project Structure
```
BOB14_A2A_Solution_Final/
├── multi-agents/        # 멀티 에이전트 데모 실행/샘플/도구
├── client/              # FastAPI 기반 Orchestrator Chat UI
├── solution/            # 메인 솔루션 백엔드·프론트
├── custom-ruleset/      # IAM 정책/DB/가이드 문서
├── jwt-server/          # JWT 발급·검증 API
├── jws-server/          # JWS 서명·검증 API
├── docker-compose.yml   # 전체 스택 Compose 파일
└── requirements.txt     # Python 공통 의존성
```

## 빠른 시작
### 실행 방법 1: 루트에서 전체 스택 일괄 실행
```bash
docker compose up --build
```
- 주요 포트: orchestrator 10000, delivery 10001, item 10002, quality 10003, vehicle 10004, policy-server(IAM) 8005, orchestrator-client 8010, JWT 8000, JWS 8001, solution 3000, Redis(agents/iam/solution/jwt) 6379/6381/6382/6380.

### 실행 방법 2: 서비스 폴더별 개별 실행
- 원하는 서비스 폴더로 이동한 뒤, 루트 Compose 파일을 지정해 필요한 서비스만 올릴 수 있습니다.
  - 예시 (에이전트 스택):  
    ```bash
    cd multi-agents
    docker compose -f ../docker-compose.yml up --build policy-server redis-iam redis-agents agent-redis-seeder solution solution-redis orchestrator delivery-agent item-agent quality-agent vehicle-agent
    ```
  - 예시 (JWT):  
    ```bash
    cd jwt-server
    docker compose -f ../docker-compose.yml up --build jwt-redis jwt-server
    ```
  - 예시 (JWS):  
    ```bash
    cd jws-server
    docker compose -f ../docker-compose.yml up --build jws-server
    ```
  - 예시 (UI 클라이언트만):  
    ```bash
    cd client
    docker compose -f ../docker-compose.yml up --build orchestrator-client
    ```

## 참고 문서
- `custom-ruleset/ARCHITECTURE.md`: 전체 아키텍처
- `custom-ruleset/IAM_POLICY_GUIDE.md`: IAM/정책 가이드
- `multi-agents/README.md`: 멀티 에이전트 상세 실행법
- `multi-agents/GEMINI_SETUP.md`: Gemini 설정 가이드
- `jwt-server/README.md`: JWT 서버 안내
- `jws-server/README.md`: JWS 서버 안내

## 기타
- 멀티 에이전트는 기본적으로 Google Gemini를 사용하며 `FALLBACK_TO_LOCAL=true` 설정 시 로컬 LLM으로 폴백할 수 있습니다.
- Redis 인스턴스는 에이전트, IAM, 솔루션, JWT 용도로 분리되어 있으니 포트와 DB 번호를 맞춰 사용하세요.
