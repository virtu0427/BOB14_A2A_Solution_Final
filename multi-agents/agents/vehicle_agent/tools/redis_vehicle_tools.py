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

def get_vehicle_data(vehicle_id: str) -> dict:
    """차량 ID로 차량 상세 조회"""
    key = f"vehicle:{vehicle_id}"
    data = redis_client.hgetall(key)
    if not data:
        return {"status": "error", "message": f"No vehicle info found for {vehicle_id}"}
    return {"status": "success", "data": data}

# === agent.py에서 요구하는 함수 시그니처에 맞춘 wrapper/추가 ===

def get_vehicle_status(vehicle_id: str) -> dict:
    """단일 차량 상태 조회 (get_vehicle_data를 래핑)"""
    return get_vehicle_data(vehicle_id)


def filter_available_vehicles() -> dict:
    """가용 상태(available) 차량 조회 (get_available_vehicles를 래핑)"""
    return get_available_vehicles()


def get_vehicles_on_maintenance() -> dict:
    """현재 정비 중인 차량 리스트 조회"""
    vehicles = []
    for key in redis_client.scan_iter("vehicle:*"):
        data = redis_client.hgetall(key)
        if data.get("status") == "maintenance":
            vehicles.append(data)
    return {"status": "success", "count": len(vehicles), "vehicles": vehicles}


def get_assigned_recall_vehicles(recall_id: str) -> dict:
    """특정 recall_id에 배정된 차량 리스트 조회"""
    vehicles = []
    for key in redis_client.scan_iter("vehicle:*"):
        data = redis_client.hgetall(key)
        if data.get("status") == "assigned_for_recall" and data.get("recall_id") == recall_id:
            vehicles.append(data)
    return {"status": "success", "recall_id": recall_id, "vehicles": vehicles}


def get_vehicle_capacity(vehicle_id: str) -> dict:
    """차량 적재 용량 조회"""
    key = f"vehicle:{vehicle_id}"
    capacity = redis_client.hget(key, "capacity")
    if capacity is None:
        return {"status": "error", "message": f"Capacity info not found for {vehicle_id}"}
    return {"status": "success", "vehicle_id": vehicle_id, "capacity": int(capacity)}


def recommend_optimal_vehicles(origin: str, destination: str, required_capacity: int) -> dict:
    """출발지/목적지/필요 용량 기반 차량 추천 (간단 버전)"""
    candidates = []
    for key in redis_client.scan_iter("vehicle:*"):
        data = redis_client.hgetall(key)
        if data.get("status") == "available":
            try:
                capacity = int(data.get("capacity", 0))
            except ValueError:
                continue
            if capacity >= required_capacity:
                vehicle_id = key.split(":")[-1]
                # 간단한 distance 계산 (placeholder)
                distance = abs(hash(origin) - hash(destination)) % 1000
                candidates.append({
                    "vehicle_id": vehicle_id,
                    "capacity": capacity,
                    "distance_to_destination": distance
                })
    candidates.sort(key=lambda x: x["distance_to_destination"])
    return {
        "status": "success",
        "origin": origin,
        "destination": destination,
        "required_capacity": required_capacity,
        "recommended_vehicles": candidates
    }

# === 기존 함수들 유지 ===

def get_all_vehicles() -> dict:
    """Redis에 저장된 모든 차량 조회"""
    vehicles = []
    for key in redis_client.scan_iter("vehicle:*"):
        data = redis_client.hgetall(key)
        if data:
            vehicles.append(data)
    return {"status": "success", "count": len(vehicles), "data": vehicles}

def get_vehicles_by_delivery(delivery_id: str) -> dict:
    """특정 배송에 할당된 차량 조회"""
    vehicles = []
    for key in redis_client.scan_iter("vehicle:*"):
        data = redis_client.hgetall(key)
        if data.get("delivery_id") == delivery_id:
            vehicles.append(data)
    return {"status": "success", "delivery_id": delivery_id, "vehicles": vehicles}

def update_vehicle_status(vehicle_id: str, new_status: str) -> dict:
    """차량 상태 업데이트"""
    key = f"vehicle:{vehicle_id}"
    if not redis_client.exists(key):
        return {"status": "error", "message": f"Vehicle {vehicle_id} does not exist."}
    redis_client.hset(key, "status", new_status)
    return {"status": "success", "vehicle_id": vehicle_id, "new_status": new_status}

def assign_vehicle_to_delivery(vehicle_id: str, delivery_id: str) -> dict:
    """차량을 특정 배송에 배정"""
    key = f"vehicle:{vehicle_id}"
    if not redis_client.exists(key):
        return {"status": "error", "message": f"Vehicle {vehicle_id} does not exist."}
    redis_client.hset(key, "delivery_id", delivery_id)
    redis_client.hset(key, "status", "on_delivery")
    return {"status": "success", "vehicle_id": vehicle_id, "assigned_delivery_id": delivery_id}

def release_vehicle(vehicle_id: str) -> dict:
    """배송 종료 후 차량 배정 해제"""
    key = f"vehicle:{vehicle_id}"
    if not redis_client.exists(key):
        return {"status": "error", "message": f"Vehicle {vehicle_id} does not exist."}
    redis_client.hdel(key, "delivery_id")
    redis_client.hset(key, "status", "available")
    return {"status": "success", "vehicle_id": vehicle_id, "new_status": "available"}

def get_available_vehicles() -> dict:
    """가용 상태 차량 조회"""
    available = []
    for key in redis_client.scan_iter("vehicle:*"):
        data = redis_client.hgetall(key)
        if data.get("status") == "available":
            available.append(data)
    return {"status": "success", "count": len(available), "vehicles": available}

def get_fleet_availability() -> dict:
    """상태별 차량 수 요약"""
    status_summary = {
        "available": 0,
        "on_delivery": 0,
        "maintenance": 0,
        "out_of_service": 0
    }
    for key in redis_client.scan_iter("vehicle:*"):
        data = redis_client.hgetall(key)
        status = data.get("status")
        if status in status_summary:
            status_summary[status] += 1
    return {"status": "success", "data": status_summary}
