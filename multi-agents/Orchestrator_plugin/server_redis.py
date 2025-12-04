"""
Redis-based Policy Server (Backward compatible with existing agents)
This can be replaced by frontend/app.py in the future
"""
import sys
import os
from pathlib import Path

# Add parent directory to path for database import
parent_dir = Path(__file__).parent.parent
sys.path.insert(0, str(parent_dir))

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Optional
import uvicorn

# Import database module from IAM package
from iam.database import get_db

app = FastAPI(title="IAM Policy Server (Redis Backend)")

# Redis connection settings
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", 6380))
REDIS_DB = int(os.getenv("REDIS_DB", 0))

# Initialize database
db = get_db(redis_host=REDIS_HOST, redis_port=REDIS_PORT, redis_db=REDIS_DB)

# ========== Models ==========
class LogPayload(BaseModel):
    agent_id: str
    policy_type: str
    tool_name: Optional[str] = None
    tool_args: Optional[Dict] = None
    prompt: Optional[str] = None
    verdict: str
    reason: Optional[str] = None
    timestamp: Optional[str] = None

# ========== API Endpoints ==========

@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "service": "IAM Policy Server",
        "backend": "Redis",
        "status": "running"
    }

@app.get("/api/iam/policy/{agent_id}")
async def get_policy(agent_id: str):
    """
    Get IAM policy for specific agent
    Returns policy with enriched ruleset details
    """
    try:
        policy = db.get_policy_by_agent(agent_id)
        
        if not policy:
            raise HTTPException(
                status_code=404,
                detail=f"No policy found for agent: {agent_id}"
            )
        
        return policy
    except HTTPException:
        raise
    except Exception as e:
        print(f"[PolicyServer] Error fetching policy for {agent_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/system-prompt")
async def get_system_prompt(agent_id: str = "orchestrator"):
    """
    Legacy endpoint for backward compatibility
    Returns system prompt for prompt validation
    """
    try:
        policy = db.get_policy_by_agent(agent_id)
        
        if not policy or not policy.get('prompt_validation_rules'):
            return {"system_prompt": ""}
        
        # Return first prompt validation rule
        first_rule = policy['prompt_validation_rules'][0]
        return {
            "system_prompt": first_rule.get('system_prompt', ''),
            "model": first_rule.get('model', 'gemini-2.0-flash-exp')
        }
    except Exception as e:
        print(f"[PolicyServer] Error fetching system prompt: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/logs")
async def log_event(payload: LogPayload):
    """
    Log policy enforcement event
    """
    try:
        log_data = payload.dict()
        success = db.add_log(log_data)
        
        if success:
            print(f"[PolicyServer] Logged event: {payload.agent_id} - {payload.policy_type} - {payload.verdict}")
            return {"status": "logged"}
        else:
            raise HTTPException(status_code=500, detail="Failed to log event")
    except Exception as e:
        print(f"[PolicyServer] Error logging event: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/logs")
async def get_logs(limit: int = 100, agent_id: Optional[str] = None):
    """
    Get logs with optional filtering
    """
    try:
        logs = db.get_logs(limit=limit, agent_id=agent_id)
        return logs
    except Exception as e:
        print(f"[PolicyServer] Error fetching logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        stats = db.get_stats()
        return {
            "status": "healthy",
            "redis": "connected",
            "stats": stats
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "error": str(e)
        }

if __name__ == "__main__":
    port = int(os.getenv("PORT", 8005))
    print(f"Starting Redis-based Policy Server on port {port}")
    print(f"Redis: {REDIS_HOST}:{REDIS_PORT}")
    
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=port,
        log_level="info"
    )

