import base64
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger(__name__)


def _default_int(env_key: str, fallback: int) -> int:
    raw = os.getenv(env_key)
    if raw is None:
        return fallback
    try:
        return int(raw)
    except ValueError:
        logger.warning("Invalid integer for %s: %s (fallback=%s)", env_key, raw, fallback)
        return fallback


class JWTTokenManager:
    def __init__(self) -> None:
        self.default_ttl_minutes = _default_int("JWT_TOKEN_FALLBACK_MINUTES", 55)
        self.clock_skew_seconds = _default_int("JWT_TOKEN_CLOCK_SKEW_SECONDS", 30)
        self.timeout_seconds = float(os.getenv("JWT_SERVER_TIMEOUT", "10"))
        self.jwt_server_url = os.getenv("JWT_SERVER_URL", "http://localhost:8000").rstrip("/")
        self.username = os.getenv("JWT_USERNAME")
        self.password = os.getenv("JWT_PASSWORD")
        self.auto_login_enabled = os.getenv("JWT_AUTO_LOGIN", "true").lower() == "true"
        self._token: Optional[str] = None
        self._expires_at: Optional[datetime] = None
        self._token_file = os.getenv("JWT_TOKEN_FILE")

    def _decode_exp_from_token(self, token: str) -> Optional[datetime]:
        try:
            payload_segment = token.split(".")[1]
            padding = "=" * (-len(payload_segment) % 4)
            decoded_bytes = base64.urlsafe_b64decode(payload_segment + padding)
            payload = json.loads(decoded_bytes.decode("utf-8"))
            exp_value = payload.get("exp")
            if isinstance(exp_value, (int, float)):
                return datetime.fromtimestamp(exp_value, tz=timezone.utc)
        except Exception as exc:  # pragma: no cover - defensive, logging only
            logger.debug("Failed to decode exp from JWT: %s", exc)
        return None

    def _set_token(self, token: str) -> None:
        expires_at = self._decode_exp_from_token(token)
        if not expires_at:
            expires_at = datetime.now(timezone.utc) + timedelta(minutes=self.default_ttl_minutes)
        self._token = token
        self._expires_at = expires_at
        logger.info("Loaded JWT token; expires at %s", expires_at.isoformat())

    def _is_token_valid(self) -> bool:
        if not self._token or not self._expires_at:
            return False
        skew = timedelta(seconds=self.clock_skew_seconds)
        now = datetime.now(timezone.utc)
        return now + skew < self._expires_at

    def _fetch_token(self) -> Optional[str]:
        if not self.auto_login_enabled:
            return None
        if not self.username or not self.password:
            logger.debug("JWT_AUTO_LOGIN enabled but credentials missing")
            return None

        url = f"{self.jwt_server_url}/token"
        try:
            resp = httpx.post(
                url,
                data={"username": self.username, "password": self.password},
                timeout=self.timeout_seconds,
            )
            resp.raise_for_status()
            payload = resp.json()
            return payload.get("access_token")
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch JWT from %s: %s", url, exc)
            return None

    def _read_token_source(self) -> Optional[str]:
        env_token = os.getenv("JWT_ACCESS_TOKEN")
        if env_token:
            return env_token.strip()
        if not self._token_file:
            logger.debug("No JWT_ACCESS_TOKEN or JWT_TOKEN_FILE configured")
            return None
        try:
            token = Path(self._token_file).read_text().strip()
            return token or None
        except Exception as exc:
            logger.warning("Failed to read JWT token file %s: %s", self._token_file, exc)
            return None

    def get_token(self) -> Optional[str]:
        if self._token and self._is_token_valid():
            return self._token
        token = self._read_token_source()
        if token:
            self._set_token(token)
            return self._token
        token = self._fetch_token()
        if token:
            self._set_token(token)
            return self._token
        logger.warning(
            "JWT token unavailable; set JWT_ACCESS_TOKEN, JWT_TOKEN_FILE, or enable JWT_AUTO_LOGIN with credentials"
        )
        return None

    def reload_token(self) -> Optional[str]:
        self._token = None
        self._expires_at = None
        return self.get_token()


jwt_token_manager = JWTTokenManager()
