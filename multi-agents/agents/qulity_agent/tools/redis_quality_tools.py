# /home/agents/tools/redis_quality_tools.py
import redis
import os

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

def get_quality_data(quality_id: str) -> dict:
    """품질 ID로 품질 검사 결과 조회"""
    key = f"quality:{quality_id}"
    data = redis_client.hgetall(key)
    if not data:
        return {"status": "error", "message": f"No quality info found for {quality_id}"}
    return {"status": "success", "data": data}

def get_all_quality_checks() -> dict:
    """모든 품질 검사 결과 조회"""
    results = []
    for key in redis_client.scan_iter("quality:*"):
        data = redis_client.hgetall(key)
        if data:
            results.append(data)
    return {"status": "success", "count": len(results), "data": results}

def get_failed_quality_checks() -> dict:
    """불합격(inspection=failed) 품질 검사 건수 및 목록"""
    results = []
    for key in redis_client.scan_iter("quality:*"):
        data = redis_client.hgetall(key)
        if data.get("inspection") == "failed":
            results.append(data)
    return {"status": "success", "failed_count": len(results), "data": results}

def update_quality_result(quality_id: str, inspection: str, defects: int) -> dict:
    """품질 검사 결과 업데이트"""
    key = f"quality:{quality_id}"
    if not redis_client.exists(key):
        return {"status": "error", "message": f"Quality {quality_id} does not exist."}
    redis_client.hset(key, mapping={
        "inspection": inspection,
        "defects": defects
    })
    return {"status": "success", "quality_id": quality_id, "inspection": inspection, "defects": defects}

def record_defect_details(quality_id: str, defect_code: str, metric_value: str) -> dict:
    """품질 검사 항목에 결함 코드 및 측정값 기록"""
    key = f"quality:defects:{quality_id}"
    redis_client.hset(key, mapping={
        "defect_code": defect_code,
        "metric_value": metric_value
    })
    return {"status": "success", "quality_id": quality_id, "defect_code": defect_code, "metric_value": metric_value}

def get_items_for_return_qc() -> dict:
    """품질 검사가 필요한 반품 상품 ID 리스트 조회"""
    items = []
    for key in redis_client.scan_iter("quality:*"):
        data = redis_client.hgetall(key)
        if data.get("qc_result") == "pending":
            items.append(data.get("id", key.split(":")[-1]))
    return {"status": "success", "count": len(items), "items": items}

def get_return_item_disposition(item_id: str) -> dict:
    """Redis에서 `quality:return:{item_id}` 키의 `disposition` 값을 가져와 반환"""
    key = f"quality:return:{item_id}"
    disposition = redis_client.hget(key, "disposition")
    if disposition is None:
        return {"status": "error", "message": f"Disposition not found for item {item_id}"}
    return {"status": "success", "item_id": item_id, "disposition": disposition}

def get_recall_items_list(product_id: str) -> dict:
    """특정 product_id에 대한 리콜 대상 아이템 리스트 조회"""
    items = []
    for key in redis_client.scan_iter(f"quality:recall:{product_id}:*"):
        item_id = key.split(":")[-1]
        items.append(item_id)
    return {"status": "success", "product_id": product_id, "recall_items": items}