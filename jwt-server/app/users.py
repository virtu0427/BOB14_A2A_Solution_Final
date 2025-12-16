import json

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from .auth import verify_password, hash_password, create_access_token, decode_access_token
from .db import redis_client
from .schemas import User, UserInDB, Token

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# 기본 시드 유저는 테넌트를 비워 둔다. 테넌트는 그룹에 추가될 때만 부여한다.
DEFAULT_USER_CREDENTIALS = [
    {
        "email": "user2@example.com",
        "name": "Logistics Staff",
        "title": "Operations Manager",
        "password": "pwd123",
    },
    {
        "email": "user@example.com",
        "name": "Customer Support",
        "title": "CS Specialist",
        "password": "pwd123",
    },
    {
        "email": "admin@example.com",
        "name": "Admin",
        "title": "Admin",
        "password": "admin123",
    },
        {
        "email": "user3@example.com",
        "name": "Hong Gil-dong",
        "title": "Staff",
        "password": "pwd123",
    },
            {
        "email": "user4@example.com",
        "name": "Lee Soon-shin",
        "title": "Staff",
        "password": "pwd123",
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
            # 기존 시드 유저가 있으면 테넌트를 비워 초기 상태를 유지한다.
            redis_client.hset(key, mapping={"tenant": _serialize_tenant([])})
            continue

        redis_client.hset(
            key,
            mapping={
                "email": user["email"],
                "tenant": _serialize_tenant([]),
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


@router.post("/token", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """패스워드 기반 로그인 후 JWT 발급."""
    user = get_user(form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invailid credentials",
        )

    access_token = create_access_token(subject=user.email, tenant=user.tenant)
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/users/me", response_model=User)
def read_users_me(token: str = Depends(oauth2_scheme)):
    """JWT로 사용자 정보를 조회한다. 테넌트가 없어도 통과."""
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    email: str | None = payload.get("sub")
    tenant_claim = payload.get("tenant")
    claim_tenants = _normalize_tenants(tenant_claim)
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token missing identity claims",
        )

    user = get_user(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # 토큰에 테넌트가 비어 있어도 로그인은 허용한다.
    if not claim_tenants:
        user.tenant = []

    return user


@router.post("/refresh", response_model=Token)
def refresh_token(token: str = Depends(oauth2_scheme)):
    """만료 전 토큰으로 새 토큰을 발급한다."""
    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )

    email: str | None = payload.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token missing identity claims",
        )

    user = get_user(email)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    new_token = create_access_token(subject=user.email, tenant=user.tenant)
    return {"access_token": new_token, "token_type": "bearer"}
