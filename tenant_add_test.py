"""
Simple smoke test for tenant/group creation against jwt-server.

Usage:
  python tenant_add_test.py --base-url http://localhost:8000 --token <admin_jwt>

Notes:
- This uses only stdlib (urllib) and expects jwt-server to be running.
- Provide an admin JWT with rights to create tenants/groups.
"""

import argparse
import json
import sys
import urllib.error
import urllib.request


def request(method: str, url: str, token: str | None = None, payload: dict | None = None):
    data = json.dumps(payload or {}).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(url, data=data, method=method.upper())
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8")
            return resp.status, body
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        return e.code, body
    except Exception as e:  # pragma: no cover - simple smoke output
        return None, str(e)


def main():
    parser = argparse.ArgumentParser(description="Tenant/group creation smoke test")
    parser.add_argument("--base-url", default="http://localhost:8000", help="jwt-server base URL")
    parser.add_argument("--token", required=True, help="admin JWT for Authorization header")
    parser.add_argument("--tenant-id", default="test-tenant", help="tenant id to create")
    parser.add_argument("--tenant-name", default="Test Tenant", help="tenant name to create")
    parser.add_argument("--group-id", default="test-group", help="group id to create under the tenant")
    parser.add_argument("--group-name", default="Test Group", help="group name")
    args = parser.parse_args()

    base = args.base_url.rstrip("/")
    tenant_url = f"{base}/tenants"
    group_url = f"{base}/tenants/{args.tenant_id}/groups"

    print(f"[1] Create tenant {args.tenant_id} ...")
    status, body = request(
        "POST",
        tenant_url,
        token=args.token,
        payload={"id": args.tenant_id, "name": args.tenant_name},
    )
    print(f"    status={status}\n    body={body}")

    print(f"[2] Create group {args.group_id} under tenant {args.tenant_id} ...")
    status, body = request(
        "POST",
        group_url,
        token=args.token,
        payload={"id": args.group_id, "name": args.group_name},
    )
    print(f"    status={status}\n    body={body}")


if __name__ == "__main__":
    sys.exit(main())
