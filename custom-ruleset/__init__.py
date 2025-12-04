"""Core IAM security solution components for the Attager multi-agent platform."""

from .database import IAMDatabase, get_db  # Re-export lightweight DB helpers

__all__ = [
    "PolicyEnforcementPlugin",
    "IAMDatabase",
    "get_db",
]


def __getattr__(name: str):  # pragma: no cover - module attribute hook
    if name == "PolicyEnforcementPlugin":
        from .policy_enforcement import PolicyEnforcementPlugin

        return PolicyEnforcementPlugin
    if name in {"IAMDatabase", "get_db"}:
        return globals()[name]
    raise AttributeError(name)


def __dir__():  # pragma: no cover - interactive helper
    return sorted(__all__)
