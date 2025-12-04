FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    build-essential \
    gcc \
    g++ \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements from root
COPY requirements.txt .

# Install Python dependencies
RUN pip install --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

# Copy utils and shared IAM package
COPY multi-agents/utils/ ./utils/
COPY custom-ruleset/ ./iam

# Copy agent files
COPY multi-agents/agents/qulity_agent/ .

# Copy .env file if it exists (for local settings)
COPY multi-agents/agents/qulity_agent/.env* ./

# Expose port
EXPOSE 10003

# Run the agent
CMD ["python", "__main__.py", "--host", "0.0.0.0", "--port", "10003"]
