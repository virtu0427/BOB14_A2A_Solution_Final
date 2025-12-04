#!/bin/sh
# 컨테이너 안에서 실행됨

echo "Entrypoint script started."

# Redis 서버를 백그라운드로 실행
echo "Starting Redis server in background..."
redis-server --daemonize yes

# Redis 시작 대기
echo "Waiting for Redis to start..."
sleep 2

# 시드 데이터 주입
if [ -f /tmp/dump.rdb ]; then
  echo "Copying dump.rdb from /tmp to /data..."
  cp /tmp/dump.rdb /data/dump.rdb
  echo "dump.rdb copied to /data."
else
  echo "dump.rdb not found at /tmp/dump.rdb"
fi

if [ -f /usr/local/etc/redis/seed-data.redis ]; then
  echo "Seeding data from seed-data.redis..."
  redis-cli < /usr/local/etc/redis/seed-data.redis
  echo "Data seeding complete."
else
  echo "seed-data.redis not found at /usr/local/etc/redis/seed-data.redis"
fi

# /data 디렉토리 내용 확인
echo "Contents of /data before SAVE:"
ls -l /data

# dump.rdb 생성
echo "Executing Redis SAVE command..."
redis-cli SAVE
echo "Redis SAVE command executed."

# /data 디렉토리 내용 확인 후
echo "Contents of /data after SAVE:"
ls -l /data

# Redis 종료 (앞에서 daemonize yes로 켰던 것)
echo "Shutting down background Redis server..."
redis-cli shutdown
echo "Background Redis server shut down."

# Redis를 포그라운드로 실행 (컨테이너 메인 프로세스)
echo "Starting main Redis server in foreground..."
exec redis-server --appendonly yes
