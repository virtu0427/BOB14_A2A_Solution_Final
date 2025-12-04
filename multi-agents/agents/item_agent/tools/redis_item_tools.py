# /home/agents/tools/redis_item_tools.py
import redis
import os
from typing import Optional

# Redis 연결
REDIS_HOST = os.getenv("AGENT_REDIS_HOST", os.getenv("REDIS_HOST", "localhost"))
REDIS_PORT = int(os.getenv("AGENT_REDIS_PORT", os.getenv("REDIS_PORT", "6379")))
REDIS_DB = int(os.getenv("AGENT_REDIS_DB", os.getenv("REDIS_DB", "0")))

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True
)

def get_item_details(item_id: str) -> dict:
    """아이템 ID로 아이템 상세 조회"""
    key = f"item:{item_id}"
    data = redis_client.hgetall(key)
    if not data:
        return {"status": "error", "message": f"No item found for {item_id}"}
    return {"status": "success", "data": data}


def track_item_inventory(item_id: str, warehouse_id: Optional[str] = None) -> dict:
    """아이템 재고 추적 (warehouse_id가 주어지면 해당 창고만 확인)"""
    key = f"item:{item_id}"
    data = redis_client.hgetall(key)
    if not data:
        return {"status": "error", "message": f"No item found for {item_id}"}

    # 특정 창고 ID가 지정된 경우
    if warehouse_id:
        if data.get("warehouse_id") == warehouse_id:
            return {
                "status": "success",
                "item_id": item_id,
                "warehouse_id": warehouse_id,
                "quantity": data.get("quantity"),
            }
        else:
            return {
                "status": "error",
                "message": f"Item {item_id} not found in warehouse {warehouse_id}",
            }

    # 지정 없으면 전체 정보 반환
    return {"status": "success", "item_id": item_id, "data": data}


def get_all_warehouse_inventories_for_item(item_id: str) -> dict:
    """아이템의 모든 창고별 재고 현황 조회"""
    key = f"item:{item_id}"
    data = redis_client.hgetall(key)
    if not data:
        return {"status": "error", "message": f"No item found for {item_id}"}

    warehouse_id = data.get("warehouse_id")
    quantity = data.get("quantity")
    return {
        "status": "success",
        "item_id": item_id,
        "warehouses": [{ "warehouse_id": warehouse_id, "quantity": quantity }],
    }

def get_all_warehouse_inventories_for_item(item_id: str) -> dict:
    """아이템의 모든 창고별 재고 현황 조회"""
    key = f"item:{item_id}"
    data = redis_client.hgetall(key)
    if not data:
        return {"status": "error", "message": f"No item found for {item_id}"}
    return {"status": "success", "item_id": item_id, "data": data}

