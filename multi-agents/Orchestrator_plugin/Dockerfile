# Dockerfile for Policy Server
FROM python:3.11-slim

WORKDIR /app

# Copy shared requirements
COPY requirements.txt ./requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy server files
COPY multi-agents/Orchestrator_plugin/server_redis.py .

# Copy IAM security solution modules
COPY custom-ruleset/ ./iam

EXPOSE 8005

CMD ["python", "server_redis.py"]
