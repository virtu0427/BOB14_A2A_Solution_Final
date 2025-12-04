"""
모델 설정 및 fallback 로직을 담당하는 유틸리티 모듈
"""
import os
import logging
from typing import Optional, Any
from dotenv import load_dotenv, find_dotenv
from google.adk.models.lite_llm import LiteLlm

logger = logging.getLogger(__name__)

# .env 파일을 프로젝트 루트에서부터 찾아서 로드
def load_env_from_root():
    """
    프로젝트 루트 디렉토리에서부터 .env 파일을 찾아서 로드
    Docker 환경에서는 환경변수가 직접 전달되므로 .env 파일 로드는 선택적
    """
    try:
        # Docker 환경 감지 (환경변수가 이미 설정되어 있는지 확인)
        if os.getenv("GOOGLE_API_KEY") and os.getenv("GOOGLE_API_KEY") != "your_google_api_key_here":
            logger.info("환경변수가 이미 설정되어 있습니다. .env 파일 로드를 생략합니다.")
            return
            
        # find_dotenv()는 현재 디렉토리부터 상위로 올라가면서 .env 파일을 찾음
        env_file = find_dotenv(usecwd=True)
        if env_file:
            load_dotenv(env_file)
            logger.info(f".env 파일을 로드했습니다: {env_file}")
        else:
            logger.info("Docker 환경에서 실행 중입니다. 환경변수를 직접 사용합니다.")
    except Exception as e:
        logger.info(f"환경변수를 직접 사용합니다: {e}")

# 모듈 로드시 자동으로 .env 파일 로드 (Docker 환경에서는 선택적)
load_env_from_root()

def get_model_with_fallback() -> Any:
    """
    Gemini 모델을 우선 사용하고, 실패하면 로컬 LLM으로 fallback하는 모델 인스턴스 반환
    """
    use_gemini = os.getenv("USE_GEMINI", "true").lower() == "true"
    fallback_to_local = os.getenv("FALLBACK_TO_LOCAL", "true").lower() == "true"
    
    if use_gemini:
        try:
            # Google API Key 확인
            google_api_key = os.getenv("GOOGLE_API_KEY")
            if not google_api_key or google_api_key == "your_google_api_key_here":
                logger.warning("GOOGLE_API_KEY가 설정되지 않았습니다. 로컬 LLM을 사용합니다.")
                if fallback_to_local:
                    return get_local_model()
                else:
                    raise ValueError("Google API Key가 설정되지 않았고 fallback이 비활성화되어 있습니다.")
            
            # Gemini 모델 사용 - Google ADK 문서에 따라 직접 문자열로 전달
            model_name = get_gemini_model("gemini-2.0-flash")
            logger.info(f"Gemini 모델을 사용합니다: {model_name}")
            return model_name
            
        except Exception as e:
            logger.error(f"Gemini 모델 설정 실패: {e}")
            if fallback_to_local:
                logger.info("로컬 LLM으로 fallback합니다.")
                return get_local_model()
            else:
                raise
    else:
        logger.info("USE_GEMINI가 false로 설정되어 있습니다. 로컬 LLM을 사용합니다.")
        return get_local_model()

def get_local_model() -> LiteLlm:
    """
    로컬 Ollama 모델 인스턴스 반환
    """
    ollama_host = os.getenv("OLLAMA_HOST", "localhost")
    return LiteLlm(
        model="ollama_chat/gpt-oss:20b",
        api_base=f"http://{ollama_host}:11434",
        temperature=0.7,
    )

def get_gemini_model(model_name: str = "gemini-2.0-flash") -> str:
    """
    Gemini 모델명 반환 (Google ADK에서 직접 문자열로 사용)
    """
    google_api_key = os.getenv("GOOGLE_API_KEY")
    if not google_api_key or google_api_key == "your_google_api_key_here":
        raise ValueError("Google API Key가 설정되지 않았습니다.")
    
    # Google ADK 문서에 따른 환경변수 설정 확인
    # Google AI Studio 사용시 VERTEXAI를 FALSE로 설정
    os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "FALSE")
    
    # API Key가 환경변수에 제대로 설정되었는지 확인
    os.environ["GOOGLE_API_KEY"] = google_api_key
    
    logger.info(f"Gemini 모델 설정: {model_name}, VERTEXAI: {os.environ['GOOGLE_GENAI_USE_VERTEXAI']}")
    
    return model_name

def is_gemini_available() -> bool:
    """
    Gemini 모델이 사용 가능한지 확인
    """
    try:
        google_api_key = os.getenv("GOOGLE_API_KEY")
        if not google_api_key or google_api_key == "your_google_api_key_here":
            return False
        return True
    except Exception:
        return False
