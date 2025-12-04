FROM redis:7-alpine
COPY dump.rdb.bak2 /data/dump.rdb
CMD ["redis-server", "--appendonly", "yes"]
