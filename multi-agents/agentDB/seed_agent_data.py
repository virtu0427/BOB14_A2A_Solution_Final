"""Utility script to seed the agent Redis dataset in a portable way."""
from __future__ import annotations

import os
import shlex
import time
from pathlib import Path
from typing import Iterable, List

import redis
from redis import exceptions as redis_exceptions


def _resolve_seed_file() -> Path:
    seed_override = os.getenv("AGENT_REDIS_SEED_FILE")
    if seed_override:
        path = Path(seed_override)
    else:
        path = Path(__file__).parent / "seed_data.txt"

    if not path.exists():
        raise FileNotFoundError(f"Seed file not found: {path}")
    return path


def _get_redis_client() -> redis.Redis:
    host = os.getenv("AGENT_REDIS_HOST", os.getenv("REDIS_HOST", "localhost"))
    port = int(os.getenv("AGENT_REDIS_PORT", os.getenv("REDIS_PORT", "6379")))
    db = int(os.getenv("AGENT_REDIS_DB", os.getenv("REDIS_DB", "0")))
    return redis.Redis(host=host, port=port, db=db, decode_responses=True)


def _wait_for_connection(client: redis.Redis) -> None:
    timeout = float(os.getenv("AGENT_REDIS_WAIT_SECONDS", "30"))
    poll_interval = float(os.getenv("AGENT_REDIS_WAIT_INTERVAL", "1"))
    deadline = time.monotonic() + timeout
    conn_kwargs = client.connection_pool.connection_kwargs
    host = conn_kwargs.get("host")
    port = conn_kwargs.get("port")

    print(f"Waiting for agent Redis at {host}:{port} (timeout {timeout}s)...")

    while True:
        try:
            client.ping()
            print("Agent Redis connection established.")
            return
        except redis_exceptions.ConnectionError:
            if time.monotonic() >= deadline:
                raise TimeoutError(
                    f"Timed out after {timeout} seconds waiting for Redis at {host}:{port}"
                )
            time.sleep(poll_interval)


def _parse_seed_commands(seed_lines: Iterable[str]) -> List[tuple[str, str, List[str]]]:
    commands: List[tuple[str, str, List[str]]] = []
    for line in seed_lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = shlex.split(stripped)
        if not parts:
            continue

        command = parts[0].upper()
        if len(parts) < 2:
            raise ValueError(f"Malformed seed line (missing key): {line}")

        key = parts[1]
        args = parts[2:]
        commands.append((command, key, args))
    return commands


def seed_agent_redis(seed_version: str = "1") -> None:
    client = _get_redis_client()

    try:
        _wait_for_connection(client)
    except TimeoutError as exc:
        raise ConnectionError(str(exc)) from exc

    force_reseed = os.getenv("AGENT_REDIS_FORCE_RESEED", "false").lower() in {"1", "true", "yes"}

    if force_reseed:
        print("Force reseed requested; flushing existing agent dataset...")
        client.flushdb()
    elif client.exists("agent_seed:version"):
        print("Agent Redis already seeded; skipping.")
        return

    seed_file = _resolve_seed_file()
    with seed_file.open(encoding="utf-8") as fh:
        commands = _parse_seed_commands(fh)

    pipe = client.pipeline(transaction=False)
    applied = 0

    for command, key, args in commands:
        if command == "HSET":
            if len(args) % 2 != 0:
                raise ValueError(f"HSET command for {key} has uneven field/value pairs: {args}")
            mapping = {args[i]: args[i + 1] for i in range(0, len(args), 2)}
            pipe.hset(key, mapping=mapping)
            applied += 1
        elif command == "SET":
            if not args:
                raise ValueError(f"SET command for {key} is missing a value")
            pipe.set(key, args[0])
            applied += 1
        else:
            raise ValueError(f"Unsupported seed command '{command}' in {seed_file}")

    pipe.set("agent_seed:version", seed_version)
    pipe.execute()
    print(f"Seeded agent Redis with {applied} commands from {seed_file}.")


if __name__ == "__main__":
    version = os.getenv("AGENT_REDIS_SEED_VERSION", "1")
    seed_agent_redis(seed_version=version)
