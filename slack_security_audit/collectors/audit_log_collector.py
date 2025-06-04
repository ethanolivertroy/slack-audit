"""
Audit log data collector for Enterprise Grid.
"""

from typing import Dict, Any
from .base import DataCollector


class AuditLogCollector(DataCollector):
    """Collects audit log information."""
    
    @property
    def name(self) -> str:
        return "audit_logs"
    
    async def collect(self) -> Dict[str, Any]:
        """Collect audit log data."""
        data = {}
        
        # Get audit logs (Enterprise Grid only)
        logs = await self.client.get_audit_logs(limit=1000)
        data["logs"] = logs
        data["log_count"] = len(logs)
        
        if logs:
            # Analyze log patterns
            stats = {
                "total_events": len(logs),
                "event_types": {},
                "user_actions": {},
                "admin_actions": 0,
                "security_events": 0
            }
            
            security_event_types = [
                "user_login", "user_logout", "user_session_invalidate",
                "file_downloaded", "file_deleted", "app_installed",
                "app_uninstalled", "workspace_settings_changed"
            ]
            
            for log in logs:
                event_type = log.get("action", "unknown")
                stats["event_types"][event_type] = stats["event_types"].get(event_type, 0) + 1
                
                # Track user actions
                user_id = log.get("actor", {}).get("user", {}).get("id")
                if user_id:
                    stats["user_actions"][user_id] = stats["user_actions"].get(user_id, 0) + 1
                
                # Count admin actions
                if log.get("actor", {}).get("admin", False):
                    stats["admin_actions"] += 1
                
                # Count security events
                if event_type in security_event_types:
                    stats["security_events"] += 1
            
            data["stats"] = stats
        
        return data
    
    def is_applicable(self, workspace_info: Dict[str, Any]) -> bool:
        """Only applicable for Enterprise Grid workspaces."""
        return workspace_info.get("is_enterprise", False)