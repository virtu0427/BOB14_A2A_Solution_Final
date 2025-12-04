"""
Redis Database Manager for IAM Policy System
"""
import redis
import json
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime
import os

class IAMDatabase:
    def __init__(self, redis_host: str = "localhost", redis_port: int = 6379, redis_db: int = 0):
        """Initialize Redis connection"""
        self.redis_client = redis.Redis(
            host=redis_host,
            port=redis_port,
            db=redis_db,
            decode_responses=True
        )
        self.redis_settings = {
            "host": redis_host,
            "port": redis_port,
            "db": redis_db,
        }
        
        # Initialize with default data if empty
        self._init_default_data()
    
    def _init_default_data(self):
        """Initialize database with default agents and policies"""
        # Check if already initialized
        if self.redis_client.exists("agents:orchestrator"):
            return
        
        # Default agents
        default_agents = [
            {
                "agent_id": "orchestrator",
                "name": "Orchestrator",
                "description": "Main orchestrator agent",
                "status": "active",
                "policy_id": "policy_orchestrator",
                "plugins": json.dumps([
                    {"name": "Coordinator", "type": "core", "status": "active"},
                    {"name": "Task Router", "type": "routing", "status": "active"}
                ]),
                "created_at": datetime.now().isoformat()
            },
            {
                "agent_id": "delivery_agent",
                "name": "Delivery Agent",
                "description": "Handles delivery operations",
                "status": "active",
                "policy_id": "policy_delivery",
                "plugins": json.dumps([
                    {"name": "Order Intake", "type": "ingest", "status": "active"},
                    {"name": "Route Planner", "type": "optimizer", "status": "active"}
                ]),
                "created_at": datetime.now().isoformat()
            },
            {
                "agent_id": "item_agent",
                "name": "Item Agent",
                "description": "Manages item information",
                "status": "active",
                "policy_id": "policy_item",
                "plugins": json.dumps([
                    {"name": "Catalog Sync", "type": "sync", "status": "active"},
                    {"name": "Inventory Guard", "type": "monitor", "status": "active"}
                ]),
                "created_at": datetime.now().isoformat()
            },
            {
                "agent_id": "quality_agent",
                "name": "Quality Agent",
                "description": "Quality assurance agent",
                "status": "active",
                "policy_id": "policy_quality",
                "plugins": json.dumps([
                    {"name": "Inspection", "type": "monitor", "status": "active"},
                    {"name": "Remediation", "type": "action", "status": "standby"}
                ]),
                "created_at": datetime.now().isoformat()
            },
            {
                "agent_id": "vehicle_agent",
                "name": "Vehicle Agent",
                "description": "Vehicle management agent",
                "status": "active",
                "policy_id": "policy_vehicle",
                "plugins": json.dumps([
                    {"name": "Telemetry", "type": "ingest", "status": "active"},
                    {"name": "Maintenance Advisor", "type": "analytics", "status": "active"}
                ]),
                "created_at": datetime.now().isoformat()
            }
        ]
        
        for agent in default_agents:
            agent_id = agent["agent_id"]
            self.redis_client.hset(f"agents:{agent_id}", mapping=agent)
            self.redis_client.sadd("agents:all", agent_id)
        
        # Default rulesets
        default_rulesets = [
            {
                "ruleset_id": "ruleset_prompt_orchestrator",
                "name": "Orchestrator Prompt Validation",
                "type": "prompt_validation",
                "description": "Validates user prompts for orchestrator",
                "system_prompt": """당신은 사용자 질문이 정책에 위반되는지 검증하는 보안 검사 AI입니다.

[검증 규칙]
1. 위험한 시스템 명령어 실행 요청 (예: 파일 삭제, 권한 변경, 시스템 설정 변경)
2. 내부 시스템 구조/설정 변경 요청
3. 관리자 권한이 필요한 작업

[응답 형식]
- 위반인 경우: "VIOLATION"
- 정상인 경우: "PASS"

사용자 질문: {prompt}

판정:""",
                "model": "gemini-2.0-flash-exp",
                "enabled": "true",
                "created_at": datetime.now().isoformat()
            },
            {
                "ruleset_id": "ruleset_tool_call_remote_agent",
                "name": "Call Remote Agent Validation",
                "type": "tool_validation",
                "tool_name": "call_remote_agent",
                "description": "Validates call_remote_agent tool arguments",
                "rules": json.dumps({
                    "allowed_agents": ["Delivery Agent", "Item Agent", "Quality Agent", "Vehicle Agent"],
                    "max_task_length": 500,
                    "rate_limit": 10
                }),
                "enabled": "true",
                "created_at": datetime.now().isoformat()
            }
        ]
        
        for ruleset in default_rulesets:
            ruleset_id = ruleset["ruleset_id"]
            self.redis_client.hset(f"rulesets:{ruleset_id}", mapping=ruleset)
            self.redis_client.sadd("rulesets:all", ruleset_id)
        
        # Default policies (mapping agents to rulesets)
        default_policies = [
            {
                "policy_id": "policy_orchestrator",
                "agent_id": "orchestrator",
                "name": "Orchestrator Policy",
                "prompt_validation_rulesets": json.dumps(["ruleset_prompt_orchestrator"]),
                "tool_validation_rulesets": json.dumps(["ruleset_tool_call_remote_agent"]),
                "response_filtering_rulesets": json.dumps([]),
                "enabled": "true",
                "created_at": datetime.now().isoformat()
            },
            {
                "policy_id": "policy_delivery",
                "agent_id": "delivery_agent",
                "name": "Delivery Agent Policy",
                "prompt_validation_rulesets": json.dumps([]),
                "tool_validation_rulesets": json.dumps([]),
                "response_filtering_rulesets": json.dumps([]),
                "enabled": "true",
                "created_at": datetime.now().isoformat()
            },
            {
                "policy_id": "policy_item",
                "agent_id": "item_agent",
                "name": "Item Agent Policy",
                "prompt_validation_rulesets": json.dumps([]),
                "tool_validation_rulesets": json.dumps([]),
                "response_filtering_rulesets": json.dumps([]),
                "enabled": "true",
                "created_at": datetime.now().isoformat()
            },
            {
                "policy_id": "policy_quality",
                "agent_id": "quality_agent",
                "name": "Quality Agent Policy",
                "prompt_validation_rulesets": json.dumps([]),
                "tool_validation_rulesets": json.dumps([]),
                "response_filtering_rulesets": json.dumps([]),
                "enabled": "true",
                "created_at": datetime.now().isoformat()
            },
            {
                "policy_id": "policy_vehicle",
                "agent_id": "vehicle_agent",
                "name": "Vehicle Agent Policy",
                "prompt_validation_rulesets": json.dumps([]),
                "tool_validation_rulesets": json.dumps([]),
                "response_filtering_rulesets": json.dumps([]),
                "enabled": "true",
                "created_at": datetime.now().isoformat()
            }
        ]
        
        for policy in default_policies:
            policy_id = policy["policy_id"]
            self.redis_client.hset(f"policies:{policy_id}", mapping=policy)
            self.redis_client.sadd("policies:all", policy_id)
    
    # ========== Agent Operations ==========
    def _serialize_agent_data(self, data: Dict) -> Dict:
        """Prepare agent data for storage in Redis"""
        serialized = data.copy()
        if "plugins" in serialized and isinstance(serialized["plugins"], (list, dict)):
            serialized["plugins"] = json.dumps(serialized["plugins"])
        return serialized

    def _parse_agent_data(self, agent_data: Dict) -> Dict:
        """Parse agent data retrieved from Redis"""
        parsed = agent_data.copy()
        if "plugins" in parsed:
            try:
                parsed["plugins"] = json.loads(parsed["plugins"])
            except Exception:
                parsed["plugins"] = []
        return parsed

    def get_all_agents(self) -> List[Dict]:
        """Get all agents"""
        agent_ids = self.redis_client.smembers("agents:all")
        agents = []
        for agent_id in agent_ids:
            agent_data = self.redis_client.hgetall(f"agents:{agent_id}")
            if agent_data:
                agents.append(self._parse_agent_data(agent_data))
        return agents

    def get_agent(self, agent_id: str) -> Optional[Dict]:
        """Get agent by ID"""
        agent_data = self.redis_client.hgetall(f"agents:{agent_id}")
        return self._parse_agent_data(agent_data) if agent_data else None

    def update_agent(self, agent_id: str, data: Dict) -> bool:
        """Update agent"""
        if not self.redis_client.exists(f"agents:{agent_id}"):
            return False
        self.redis_client.hset(f"agents:{agent_id}", mapping=self._serialize_agent_data(data))
        return True

    def create_agent(self, data: Dict) -> bool:
        """Create new agent"""
        agent_id = data.get("agent_id")
        if not agent_id:
            return False
        data["created_at"] = datetime.now().isoformat()
        self.redis_client.hset(f"agents:{agent_id}", mapping=self._serialize_agent_data(data))
        self.redis_client.sadd("agents:all", agent_id)
        return True
    
    # ========== Ruleset Operations ==========
    def get_all_rulesets(self) -> List[Dict]:
        """Get all rulesets"""
        ruleset_ids = self.redis_client.smembers("rulesets:all")
        rulesets = []
        for ruleset_id in ruleset_ids:
            ruleset_data = self.redis_client.hgetall(f"rulesets:{ruleset_id}")
            if ruleset_data:
                # Parse JSON fields
                if "rules" in ruleset_data:
                    try:
                        ruleset_data["rules"] = json.loads(ruleset_data["rules"])
                    except:
                        pass
                if "blocked_keywords" in ruleset_data:
                    try:
                        ruleset_data["blocked_keywords"] = json.loads(ruleset_data["blocked_keywords"])
                    except:
                        pass
                if "enabled" in ruleset_data:
                    ruleset_data["enabled"] = ruleset_data["enabled"].lower() == "true"
                rulesets.append(ruleset_data)
        return rulesets
    
    def get_ruleset(self, ruleset_id: str) -> Optional[Dict]:
        """Get ruleset by ID"""
        ruleset_data = self.redis_client.hgetall(f"rulesets:{ruleset_id}")
        if not ruleset_data:
            return None
        
        # Parse JSON fields
        if "rules" in ruleset_data:
            try:
                ruleset_data["rules"] = json.loads(ruleset_data["rules"])
            except:
                pass
        if "blocked_keywords" in ruleset_data:
            try:
                ruleset_data["blocked_keywords"] = json.loads(ruleset_data["blocked_keywords"])
            except:
                pass
        if "enabled" in ruleset_data:
            ruleset_data["enabled"] = ruleset_data["enabled"].lower() == "true"

        return ruleset_data
    
    def create_ruleset(self, data: Dict) -> bool:
        """Create new ruleset"""
        ruleset_id = data.get("ruleset_id")
        if not ruleset_id:
            return False
        
        data["created_at"] = datetime.now().isoformat()
        
        # Convert complex types to JSON strings
        if "rules" in data and isinstance(data["rules"], dict):
            data["rules"] = json.dumps(data["rules"])
        if "blocked_keywords" in data and isinstance(data["blocked_keywords"], list):
            data["blocked_keywords"] = json.dumps(data["blocked_keywords"])
        if "enabled" in data:
            data["enabled"] = str(data["enabled"]).lower()

        self.redis_client.hset(f"rulesets:{ruleset_id}", mapping=data)
        self.redis_client.sadd("rulesets:all", ruleset_id)
        return True
    
    def update_ruleset(self, ruleset_id: str, data: Dict) -> bool:
        """Update ruleset"""
        if not self.redis_client.exists(f"rulesets:{ruleset_id}"):
            return False
        
        data["updated_at"] = datetime.now().isoformat()
        
        # Convert complex types to JSON strings
        if "rules" in data and isinstance(data["rules"], dict):
            data["rules"] = json.dumps(data["rules"])
        if "blocked_keywords" in data and isinstance(data["blocked_keywords"], list):
            data["blocked_keywords"] = json.dumps(data["blocked_keywords"])
        if "enabled" in data:
            data["enabled"] = str(data["enabled"]).lower()

        self.redis_client.hset(f"rulesets:{ruleset_id}", mapping=data)
        return True
    
    def delete_ruleset(self, ruleset_id: str) -> bool:
        """Delete ruleset"""
        if not self.redis_client.exists(f"rulesets:{ruleset_id}"):
            return False
        
        self.redis_client.delete(f"rulesets:{ruleset_id}")
        self.redis_client.srem("rulesets:all", ruleset_id)
        return True
    
    # ========== Policy Operations ==========
    def get_all_policies(self) -> List[Dict]:
        """Get all policies"""
        policy_ids = self.redis_client.smembers("policies:all")
        policies = []
        for policy_id in policy_ids:
            policy_data = self.redis_client.hgetall(f"policies:{policy_id}")
            if policy_data:
                # Parse JSON fields
                for field in ["prompt_validation_rulesets", "tool_validation_rulesets", "response_filtering_rulesets"]:
                    if field in policy_data:
                        try:
                            policy_data[field] = json.loads(policy_data[field])
                        except:
                            policy_data[field] = []
                if "enabled" in policy_data:
                    policy_data["enabled"] = policy_data["enabled"].lower() == "true"
                policies.append(policy_data)
        return policies
    
    def get_policy(self, policy_id: str) -> Optional[Dict]:
        """Get policy by ID"""
        policy_data = self.redis_client.hgetall(f"policies:{policy_id}")
        if not policy_data:
            return None
        
        # Parse JSON fields
        for field in ["prompt_validation_rulesets", "tool_validation_rulesets", "response_filtering_rulesets"]:
            if field in policy_data:
                try:
                    policy_data[field] = json.loads(policy_data[field])
                except:
                    policy_data[field] = []
        if "enabled" in policy_data:
            policy_data["enabled"] = policy_data["enabled"].lower() == "true"
        
        return policy_data
    
    def get_policy_by_agent(self, agent_id: str) -> Optional[Dict]:
        """Get policy by agent ID with enriched ruleset details"""
        # Find policy by agent_id
        policy_ids = self.redis_client.smembers("policies:all")
        policy = None
        
        for policy_id in policy_ids:
            policy_data = self.redis_client.hgetall(f"policies:{policy_id}")
            if policy_data and policy_data.get("agent_id") == agent_id:
                policy = policy_data
                break
        
        if not policy:
            return None
        
        # Parse JSON fields
        for field in ["prompt_validation_rulesets", "tool_validation_rulesets", "response_filtering_rulesets"]:
            if field in policy:
                try:
                    policy[field] = json.loads(policy[field])
                except:
                    policy[field] = []
        if "enabled" in policy:
            policy["enabled"] = policy["enabled"].lower() == "true"
        
        # Enrich policy with ruleset details
        policy['prompt_validation_rules'] = []
        policy['tool_validation_rules'] = {}
        
        for ruleset_id in policy.get('prompt_validation_rulesets', []):
            ruleset = self.get_ruleset(ruleset_id)
            if ruleset and ruleset.get('enabled'):
                policy['prompt_validation_rules'].append({
                    'system_prompt': ruleset.get('system_prompt', ''),
                    'model': ruleset.get('model', 'gemini-2.0-flash-exp')
                })
        
        for ruleset_id in policy.get('tool_validation_rulesets', []):
            ruleset = self.get_ruleset(ruleset_id)
            if ruleset and ruleset.get('enabled'):
                tool_name = ruleset.get('tool_name')
                if tool_name:
                    policy['tool_validation_rules'][tool_name] = ruleset.get('rules', {})
        
        return policy
    
    def update_policy(self, policy_id: str, data: Dict) -> bool:
        """Update policy"""
        if not self.redis_client.exists(f"policies:{policy_id}"):
            return False
        
        data["updated_at"] = datetime.now().isoformat()
        
        # Convert complex types to JSON strings
        for field in ["prompt_validation_rulesets", "tool_validation_rulesets", "response_filtering_rulesets"]:
            if field in data and isinstance(data[field], list):
                data[field] = json.dumps(data[field])
        if "enabled" in data:
            data["enabled"] = str(data["enabled"]).lower()
        
        self.redis_client.hset(f"policies:{policy_id}", mapping=data)
        return True
    
    def create_policy(self, data: Dict) -> bool:
        """Create new policy"""
        policy_id = data.get("policy_id")
        if not policy_id:
            return False

        data["created_at"] = datetime.now().isoformat()

        # Convert complex types to JSON strings
        for field in ["prompt_validation_rulesets", "tool_validation_rulesets", "response_filtering_rulesets"]:
            if field in data and isinstance(data[field], list):
                data[field] = json.dumps(data[field])
        if "enabled" in data:
            data["enabled"] = str(data["enabled"]).lower()

        self.redis_client.hset(f"policies:{policy_id}", mapping=data)
        self.redis_client.sadd("policies:all", policy_id)
        return True

    def assign_rulesets_to_agent(self, agent_id: str, assignments: Dict[str, List[str]], enabled: Optional[bool] = None) -> bool:
        """Assign a set of rulesets to the agent's policy."""
        agent = self.get_agent(agent_id)
        if not agent:
            return False

        policy = self.get_policy_by_agent(agent_id)
        if not policy:
            policy_id = f"policy_{agent_id}"
            self.create_policy({
                "policy_id": policy_id,
                "agent_id": agent_id,
                "name": f"{agent.get('name', agent_id)} Policy",
                "prompt_validation_rulesets": assignments.get("prompt_validation_rulesets", []),
                "tool_validation_rulesets": assignments.get("tool_validation_rulesets", []),
                "response_filtering_rulesets": assignments.get("response_filtering_rulesets", []),
                "enabled": enabled if enabled is not None else True
            })
            return True

        policy_id = policy.get("policy_id")
        update_payload: Dict[str, Any] = {
            "prompt_validation_rulesets": assignments.get("prompt_validation_rulesets", []),
            "tool_validation_rulesets": assignments.get("tool_validation_rulesets", []),
            "response_filtering_rulesets": assignments.get("response_filtering_rulesets", [])
        }

        if enabled is not None:
            update_payload["enabled"] = enabled

        return self.update_policy(policy_id, update_payload)

    def get_agent_flow(self, limit: int = 200) -> Dict[str, Any]:
        """Build agent flow information from recent logs"""
        logs = self.get_logs(limit=limit)
        agents = {agent["agent_id"]: agent for agent in self.get_all_agents()}

        node_metrics: Dict[str, Dict[str, Any]] = {}
        edge_map: Dict[Tuple[str, str], Dict[str, Any]] = {}

        for log in logs:
            source = log.get("agent_id") or log.get("source_agent") or "unknown"
            target = (
                log.get("target_agent")
                or log.get("destination_agent")
                or log.get("target")
                or "external"
            )

            verdict = (log.get("verdict") or "").upper()

            if source not in node_metrics:
                node_metrics[source] = {"events": 0, "violations": 0}
            node_metrics[source]["events"] += 1
            if verdict in {"VIOLATION", "BLOCKED"}:
                node_metrics[source]["violations"] += 1

            key = (source, target)
            if key not in edge_map:
                edge_map[key] = {"source": source, "target": target, "count": 0, "violations": 0}
            edge_map[key]["count"] += 1
            if verdict in {"VIOLATION", "BLOCKED"}:
                edge_map[key]["violations"] += 1

        nodes = []
        seen = set()
        for agent_id, agent in agents.items():
            metrics = node_metrics.get(agent_id, {"events": 0, "violations": 0})
            nodes.append({
                "id": agent_id,
                "name": agent.get("name", agent_id),
                "status": agent.get("status", "unknown"),
                "plugins": agent.get("plugins", []),
                "metrics": metrics
            })
            seen.add(agent_id)

        for node_id, metrics in node_metrics.items():
            if node_id not in seen:
                nodes.append({
                    "id": node_id,
                    "name": node_id.replace("_", " ").title(),
                    "status": "external" if node_id == "external" else "unknown",
                    "plugins": [],
                    "metrics": metrics
                })

        edges = list(edge_map.values())

        return {
            "nodes": nodes,
            "edges": edges,
            "meta": {
                "window": limit,
                "generated_at": datetime.utcnow().isoformat() + "Z",
                "total_events": len(logs)
            }
        }
    
    # ========== Log Operations ==========
    def add_log(self, log_data: Dict) -> bool:
        """Add log entry"""
        log_data['timestamp'] = datetime.now().isoformat()
        log_entry = json.dumps(log_data)
        
        # Store in list (newest first)
        self.redis_client.lpush("logs:all", log_entry)
        
        # Keep only last 10000 logs
        self.redis_client.ltrim("logs:all", 0, 9999)
        
        return True
    
    def get_logs(self, limit: int = 100, agent_id: Optional[str] = None) -> List[Dict]:
        """Get logs with optional filtering"""
        # Get logs from Redis
        log_entries = self.redis_client.lrange("logs:all", 0, limit - 1)
        
        logs = []
        for entry in log_entries:
            try:
                log = json.loads(entry)
                if agent_id is None or log.get("agent_id") == agent_id:
                    logs.append(log)
            except:
                continue
        
        return logs[:limit]
    
    def clear_logs(self) -> bool:
        """Clear all logs"""
        self.redis_client.delete("logs:all")
        return True
    
    def get_stats(self) -> Dict:
        """Get statistics"""
        return {
            "total_agents": self.redis_client.scard("agents:all"),
            "total_rulesets": self.redis_client.scard("rulesets:all"),
            "total_policies": self.redis_client.scard("policies:all"),
            "total_logs": self.redis_client.llen("logs:all")
        }

# Global database instance
db = None


def get_db(redis_host: str = "localhost", redis_port: int = 6379, redis_db: int = 0) -> IAMDatabase:
    """Get or create database instance"""
    global db
    if db is None:
        db = IAMDatabase(redis_host=redis_host, redis_port=redis_port, redis_db=redis_db)
    return db
