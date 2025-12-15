import json

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from .auth import verify_password, hash_password, create_access_token, decode_access_token
from .db import redis_client
from .schemas import User, UserInDB, Token

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

DEFAULT_USER_CREDENTIALS = [
    {
        "email": "user2@example.com",
        "tenant": "logistics",
        "name": "물류 오퍼레이터",
        "title": "운영 매니저",
        "password": "password1234",
    },
    {
        "email": "user@example.com",
        "tenant": "customer-service",
        "name": "고객 상담원",
        "title": "CS 스페셜리스트",
        "password": "password123",
    },
    {
        "email": "admin@example.com",
        "tenant": "logistics",
        "name": "관리자",
        "title": "Admin",
        "password": "admin123",
    },
]


def _user_key(email: str) -> str:
    return f"user:{email}"


def _serialize_tenant(tenant):
    return json.dumps(tenant)


def _seed_default_users():
    for user in DEFAULT_USER_CREDENTIALS:
        key = _user_key(user["email"])
        if redis_client.exists(key):
            continue

        redis_client.hset(
            key,
            mapping={
                "email": user["email"],
                "tenant": _serialize_tenant(user["tenant"]),
                "name": user.get("name", ""),
                "title": user.get("title", ""),
                "hashed_password": hash_password(user["password"]),
            },
        )


def _deserialize_tenant(raw_value: str | None):
    if not raw_value:
        return []

    try:
        return json.loads(raw_value)
    except json.JSONDecodeError:
        return raw_value


_seed_default_users()

def get_user(email: str):
    key = _user_key(email)
    user_data = redis_client.hgetall(key)
    if not user_data:
        return None

    tenant_value = _deserialize_tenant(user_data.get("tenant"))
    return UserInDB(
        email=user_data["email"],
        tenant=tenant_value,
        name=user_data.get("name") or None,
        title=user_data.get("title") or None,
        hashed_password=user_data["hashed_password"],
    )

def _normalize_tenants(value):
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(item) for item in value if isinstance(item, str)]
    return []

# FastAPI에서 로그인용 토큰을 발급하는 엔드포인트
@router.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invailid credentials")
    
    access_token = create_access_token(subject=user.email, tenant=user.tenant)
    return {"access_token": access_token, "token_type": "bearer"}


# 토큰 속에서 이메일로 사용자 정보를 찾아 리턴하는 엔드포인트
@router.get("/users/me", response_model=User)
def read_users_me(token: str = Depends(oauth2_scheme)):
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token")
    
    email: str | None = payload.get("sub")
    tenant_claim = payload.get("tenant")
    claim_tenants = _normalize_tenants(tenant_claim)
    if not email or not claim_tenants:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token missing identity claims")

    user = get_user(email)
    user_tenants = _normalize_tenants(user.tenant) if user else []
    if not user or not user_tenants or set(user_tenants) != set(claim_tenants):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found")
    
    return user


# 토큰 갱신 엔드포인트 (기존 토큰이 유효하면 새 토큰 발급)
@router.post("/refresh", response_model=Token)
def refresh_token(token: str = Depends(oauth2_scheme)):
    """
    현재 유효한 토큰을 새 토큰으로 갱신합니다.
    토큰이 만료되기 전에 호출해야 합니다.
    """
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    
    email: str | None = payload.get("sub")
    tenant_claim = payload.get("tenant")
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token missing identity claims",
        )
    
    # 사용자가 여전히 존재하는지 확인
    user = get_user(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    
    # 새 토큰 발급 (사용자의 현재 tenant 정보 사용)
    new_token = create_access_token(subject=user.email, tenant=user.tenant)
    return {"access_token": new_token, "token_type": "bearer"}
