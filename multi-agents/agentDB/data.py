import os
import redis
from datetime import datetime, timedelta
import random


def _get_redis_client() -> redis.Redis:
    """Return a Redis client that honours environment overrides."""
    host = os.getenv("AGENT_REDIS_HOST", os.getenv("REDIS_HOST", "localhost"))
    port = int(os.getenv("AGENT_REDIS_PORT", os.getenv("REDIS_PORT", "6379")))
    db = int(os.getenv("AGENT_REDIS_DB", os.getenv("REDIS_DB", "0")))

    return redis.Redis(host=host, port=port, db=db, decode_responses=True)

def seed_large_data(n=800):
    redis_client = _get_redis_client()
    redis_client.flushdb()  # DB 초기화
    base_time = datetime(2025, 9, 25, 10, 0, 0)

    for i in range(1, n + 1):
        # ID 생성
        delivery_id = f"ORD{i:04d}"
        quality_id = f"Q{i:04d}"
        vehicle_id = f"V{i:04d}"
        item_id = f"I{i:04d}"

        # 배송 상태 랜덤
        delivery_status = random.choice(["delivered", "in_transit", "ready"])
        timestamp = (base_time + timedelta(minutes=i)).isoformat()

        # 🚚 배송 데이터
        redis_client.hset(f"delivery:{delivery_id}", mapping={
            "id": delivery_id,
            "status": delivery_status,
            "quality_id": quality_id,
            "timestamp": timestamp
        })

        # 📦 아이템 데이터 (✅ warehouse_id 필드 사용)
        item_name = random.choice(["전자부품", "가전제품", "식품", "의류", "서적"])
        redis_client.hset(f"item:{item_id}", mapping={
            "id": item_id,
            "name": item_name,
            "quantity": str(random.randint(50, 500)),
            "warehouse_id": f"WH{random.randint(1,5)}",   # ✅ 수정됨
            "vehicle_id": vehicle_id
        })

        # ✅ 품질 데이터
        inspection_result = random.choice(["passed", "failed"])
        defects = str(random.randint(0, 5)) if inspection_result == "failed" else "0"
        qc_result = "pending" if inspection_result == "failed" and random.random() < 0.3 else "done"

        redis_client.hset(f"quality:{quality_id}", mapping={
            "id": quality_id,
            "inspection": inspection_result,
            "qc_result": qc_result,
            "defects": defects,
            "timestamp": timestamp
        })

        # 반품 처분 데이터 (일부만)
        if inspection_result == "failed":
            disposition = random.choice(["폐기", "재검사", "재판매 불가", "재판매 가능"])
            redis_client.hset(f"quality:return:{item_id}", mapping={
                "item_id": item_id,
                "disposition": disposition
            })

        # 🚗 차량 데이터
        vehicle_status = random.choice(["available", "on_delivery", "maintenance", "out_of_service"])
        redis_client.hset(f"vehicle:{vehicle_id}", mapping={
            "id": vehicle_id,
            "vehicle_no": f"{random.randint(10,99)}가{random.randint(1000,9999)}",
            "status": vehicle_status,
            "driver": random.choice(["김철수", "이영희", "박민수", "최지훈"]),
            "capacity": str(random.randint(100, 1000)),
            "delivery_id": delivery_id
        })

    print(f"✅ {n}개의 데이터 입력 완료")

if __name__ == "__main__":
    seed_large_data(800)
