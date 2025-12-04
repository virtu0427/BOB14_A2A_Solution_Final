# Gemini 모델 설정 가이드

이 프로젝트는 Google Gemini 모델을 우선으로 사용하고, Gemini가 사용 불가능할 때 로컬 LLM(Ollama)을 fallback으로 사용하도록 구성되어 있습니다.

## 📋 목차

1. [Google API Key 설정](#google-api-key-설정)
2. [환경변수 설정](#환경변수-설정)
3. [모델 우선순위 설정](#모델-우선순위-설정)
4. [트러블슈팅](#트러블슈팅)

## 🔑 Google API Key 설정

### 1. Google AI Studio에서 API Key 발급

1. [Google AI Studio](https://makersuite.google.com/app/apikey)에 접속
2. Google 계정으로 로그인
3. "Create API Key" 버튼 클릭
4. API Key 복사

### 2. 환경변수 파일 생성

`.env` 파일은 다음 두 위치 중 어디에서든 설정할 수 있습니다:

**옵션 1: 프로젝트 루트 (권장)**
```bash
# AttagerMain/.env 
```

**옵션 2: Attager 폴더 내**
```bash
# AttagerMain/Attager/.env
```

시스템이 자동으로 상위 디렉토리부터 `.env` 파일을 찾아서 로드합니다.

## ⚙️ 환경변수 설정

프로젝트 루트 디렉토리(`AttagerMain/`)에 `.env` 파일을 생성하고 다음과 같이 설정하세요:

```env
# Google AI Studio API Key
GOOGLE_API_KEY=your_actual_api_key_here

# Google AI Studio 사용 설정 (Vertex AI를 사용하지 않는 경우)
GOOGLE_GENAI_USE_VERTEXAI=FALSE

# Ollama 설정 (fallback용)
OLLAMA_HOST=localhost

# 모델 우선순위 설정
USE_GEMINI=true
FALLBACK_TO_LOCAL=true
```

### 필수 환경변수

- `GOOGLE_API_KEY`: Google AI Studio에서 발급받은 API Key
- `GOOGLE_GENAI_USE_VERTEXAI`: `FALSE` (Google AI Studio 사용)
- `USE_GEMINI`: `true` (Gemini 사용 활성화)
- `FALLBACK_TO_LOCAL`: `true` (로컬 LLM fallback 활성화)

## 🎯 모델 우선순위 설정

### 시나리오 1: Gemini 우선, 로컬 LLM fallback (권장)
```env
USE_GEMINI=true
FALLBACK_TO_LOCAL=true
```

### 시나리오 2: Gemini만 사용 (fallback 없음)
```env
USE_GEMINI=true
FALLBACK_TO_LOCAL=false
```

### 시나리오 3: 로컬 LLM만 사용
```env
USE_GEMINI=false
FALLBACK_TO_LOCAL=true
```

## 🔧 적용된 에이전트

다음 모든 에이전트에 Gemini 지원이 추가되었습니다:

- **Root Orchestrator**: `Attager/Orchestrator/agent.py`
- **Delivery Agent**: `Attager/agents/delivery_agent/agent.py`
- **Item Agent**: `Attager/agents/item_agent/agent.py`
- **Quality Agent**: `Attager/agents/qulity_agent/agent.py`
- **Vehicle Agent**: `Attager/agents/vehicle_agent/agent.py`

## 🔄 Fallback 동작 방식

1. **1단계**: Gemini 모델 사용 시도
   - Google API Key 확인
   - Gemini 모델 초기화
   
2. **2단계**: Gemini 실패시 로컬 LLM 사용
   - Ollama 기반 로컬 모델 사용
   - `gpt-oss:20b` 모델 연결

3. **3단계**: 모든 것이 실패하는 경우
   - 에러 로그 출력
   - 안전한 종료

## 🚀 실행 방법

### 1. 의존성 설치
```bash
pip install -r requirements.txt
```

### 2. 환경변수 설정 확인
```bash
# .env 파일이 제대로 설정되었는지 확인
cat .env
```

### 3. 에이전트 실행
```bash
# Attager 디렉토리로 이동
cd Attager

# Orchestrator 실행
cd Orchestrator
python agent.py

# 개별 에이전트 실행 (예: Delivery Agent)
cd ../agents/delivery_agent
python agent.py
```

## 🐛 트러블슈팅

### 문제 1: "Google API Key가 설정되지 않았습니다"
**해결방법**:
- `.env` 파일에 `GOOGLE_API_KEY`가 올바르게 설정되었는지 확인
- API Key가 `your_google_api_key_here`가 아닌 실제 Key인지 확인

### 문제 2: "Gemini 모델 설정 실패"
**해결방법**:
- 인터넷 연결 확인
- Google API Key가 유효한지 확인
- API 할당량 초과 여부 확인

### 문제 3: "로컬 LLM도 사용할 수 없음"
**해결방법**:
- Ollama가 실행 중인지 확인: `ollama serve`
- `gpt-oss:20b` 모델이 설치되었는지 확인: `ollama list`
- 필요시 모델 다운로드: `ollama pull gpt-oss:20b`

### 문제 4: "ImportError: No module named 'utils.model_config'"
**해결방법**:
- Python path 설정 확인
- 각 에이전트 디렉토리에서 실행할 때 `sys.path.append("../..")`가 제대로 작동하는지 확인

## 📊 모델 사용 상태 확인

각 에이전트는 시작할 때 다음과 같은 로그를 출력합니다:

```
INFO - [AgentName] 모델 설정 완료: gemini-1.5-pro-latest
```

또는

```
INFO - [AgentName] 최후 fallback으로 로컬 LLM 사용
```

## 💡 팁

1. **API 비용 관리**: Gemini API 사용량을 모니터링하세요
2. **로컬 개발**: 개발 중에는 `USE_GEMINI=false`로 설정하여 로컬 LLM만 사용할 수 있습니다
3. **프로덕션**: 프로덕션에서는 `FALLBACK_TO_LOCAL=true`로 설정하여 안정성을 높이세요

## 📞 지원

문제가 지속되면 다음을 확인하세요:
- Google ADK 문서: https://google.github.io/adk-docs/agents/models/
- Ollama 문서: https://ollama.ai/docs
- 프로젝트 로그 파일: 각 에이전트의 로그 출력 확인
