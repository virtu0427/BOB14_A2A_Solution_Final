# /home/agents/tools/redis_delivery_tools.py
import os
import redis
from typing import Dict, Any, Optional, List, Tuple

# Redis 연결
REDIS_HOST = os.getenv("AGENT_REDIS_HOST", os.getenv("REDIS_HOST", "localhost"))
REDIS_PORT = int(os.getenv("AGENT_REDIS_PORT", os.getenv("REDIS_PORT", "6379")))
REDIS_DB = int(os.getenv("AGENT_REDIS_DB", os.getenv("REDIS_DB", "0")))

redis_client = redis.Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    db=REDIS_DB,
    decode_responses=True,
)

# ---------- 내부 유틸 ----------

PREFIXES = ("quality", "delivery", "vehicle", "item")

def _exists_key(prefix: str, ident: str) -> bool:
    return redis_client.exists(f"{prefix}:{ident}") == 1

def _get_hash(prefix: str, ident: str) -> Dict[str, str]:
    return redis_client.hgetall(f"{prefix}:{ident}")

def _scan_first(prefix: str, field: str, value: str) -> Optional[Dict[str, str]]:
    """
    지정 prefix:*, field==value 인 해시 1개를 찾아 반환 (없으면 None).
    """
    for key in redis_client.scan_iter(f"{prefix}:*"):
        data = redis_client.hgetall(key)
        if data.get(field) == value:
            return data
    return None

def _scan_all(prefix: str, field: str, value: str) -> List[Dict[str, str]]:
    """
    지정 prefix:*, field==value 인 해시 전부를 리스트로 반환.
    """
    out = []
    for key in redis_client.scan_iter(f"{prefix}:*"):
        data = redis_client.hgetall(key)
        if data.get(field) == value:
            out.append(data)
    return out

def _infer_type_and_load(ident: str) -> Tuple[Optional[str], Optional[Dict[str, str]]]:
    """
    ident(Q001/D001/V001/I001 등)로부터 타입을 추정하고 해시를 로드.
    1) 키 존재 확인으로 빠르게 판별
    2) 없으면 id 필드 스캔으로 판별
    """
    # 1) 키 존재로 판별
    candidates = [p for p in PREFIXES if _exists_key(p, ident)]
    if len(candidates) == 1:
        p = candidates[0]
        return p, _get_hash(p, ident)
    elif len(candidates) > 1:
        # 이례적 중복: 우선순위 부여 (delivery > vehicle > item > quality)
        for p in ("delivery", "vehicle", "item", "quality"):
            if p in candidates:
                return p, _get_hash(p, ident)

    # 2) id 필드 스캔으로 판별
    for p in PREFIXES:
        data = _scan_first(p, "id", ident)
        if data:
            return p, data

    return None, None

def _build_context_from(start_type: str, start_data: Dict[str, str]) -> Dict[str, Any]:
    """
    출발 엔티티에서 전체 컨텍스트(quality, delivery, vehicle, items)를 구성.
    """
    result: Dict[str, Any] = {}
    quality, delivery, vehicle = None, None, None
    items: List[Dict[str, str]] = []

    # 출발점 배치
    if start_type == "quality":
        quality = start_data
    elif start_type == "delivery":
        delivery = start_data
    elif start_type == "vehicle":
        vehicle = start_data
    elif start_type == "item":
        items = [start_data]
    else:
        return result

    # --- 상하위 추적 규칙 ---
    # delivery <-> quality : delivery.quality_id == quality.id
    # vehicle <-> delivery : vehicle.delivery_id == delivery.id
    # item    -> vehicle   : item.vehicle_id == vehicle.id

    # 1) delivery 채우기
    if delivery is None and quality is not None:
        delivery = _scan_first("delivery", "quality_id", quality.get("id", ""))

    if delivery is None and vehicle is not None:
        # vehicle.delivery_id 로 delivery 찾기
        did = vehicle.get("delivery_id")
        if did:
            # 빠른 경로
            if _exists_key("delivery", did):
                delivery = _get_hash("delivery", did)
            else:
                delivery = _scan_first("delivery", "id", did)

    if delivery is None and items:
        # 아이템에서 vehicle 거쳐 delivery 도달
        v_id = items[0].get("vehicle_id")
        if v_id:
            v = _get_hash("vehicle", v_id) if _exists_key("vehicle", v_id) else _scan_first("vehicle", "id", v_id)
            if v:
                vehicle = vehicle or v
                did = v.get("delivery_id")
                if did:
                    delivery = _get_hash("delivery", did) if _exists_key("delivery", did) else _scan_first("delivery", "id", did)

    # 2) quality 채우기
    if quality is None and delivery is not None:
        qid = delivery.get("quality_id")
        if qid:
            quality = _get_hash("quality", qid) if _exists_key("quality", qid) else _scan_first("quality", "id", qid)

    # 3) vehicle 채우기
    if vehicle is None and delivery is not None:
        did = delivery.get("id", "")
        if did:
            vehicle = _scan_first("vehicle", "delivery_id", did)

    # 4) items 채우기 (여러 개 가능)
    if not items and vehicle is not None:
        vid = vehicle.get("id", "")
        if vid:
            items = _scan_all("item", "vehicle_id", vid)

    # 결과 구성 (존재하는 것만)
    if quality:
        result["quality"] = quality
    if delivery:
        result["delivery"] = delivery
    if vehicle:
        result["vehicle"] = vehicle
    if items:
        result["items"] = items

    return result

# ---------- 공개 툴 함수 ----------

def get_delivery_data(identifier: str) -> dict:
    """
    어떤 식별자든(Q001/D001/V001/I001) 받으면 전체 컨텍스트를 조회해서 반환.
    - 입력: identifier (예: "Q001", "D001", "V001", "I001")
    - 출력: { status, data: {quality?, delivery?, vehicle?, items?} }
    """
    start_type, start_data = _infer_type_and_load(identifier)
    if not start_type or not start_data:
        return {"status": "error", "message": f"No entity found for '{identifier}'"}

    context = _build_context_from(start_type, start_data)
    if not context:
        return {"status": "error", "message": f"Context build failed for '{identifier}'"}

    return {"status": "success", "data": context, "start_type": start_type}

def get_all_deliveries() -> dict:
    """
    모든 배송 해시 반환 (delivery:*)
    """
    deliveries = []
    for key in redis_client.scan_iter("delivery:*"):
        data = redis_client.hgetall(key)
        if data:
            deliveries.append(data)
    return {"status": "success", "count": len(deliveries), "data": deliveries}

def get_completed_deliveries() -> dict:
    """
    상태가 delivered 인 배송 건수/목록
    """
    completed = []
    for key in redis_client.scan_iter("delivery:*"):
        data = redis_client.hgetall(key)
        if data.get("status") == "delivered":
            completed.append(data)
    return {"status": "success", "completed_count": len(completed), "data": completed}
