"""
Enterprise Grid data collector.
"""

from typing import Dict, Any
from .base import DataCollector


class EnterpriseCollector(DataCollector):
    """Collects Enterprise Grid specific information."""
    
    @property
    def name(self) -> str:
        return "enterprise"
    
    async def collect(self) -> Dict[str, Any]:
        """Collect enterprise data."""
        data = {}
        
        # Get enterprise info
        enterprise_info = await self.client.get_enterprise_info()
        data["is_enterprise"] = enterprise_info.get("ok", False) and "teams" in enterprise_info
        
        if data["is_enterprise"]:
            data["teams"] = enterprise_info.get("teams", [])
            data["team_count"] = len(data["teams"])
            
            # Try to get enterprise-specific settings
            try:
                # Session duration settings
                session_settings = await self.client._make_request("admin.teams.settings.info")
                data["session_settings"] = session_settings
            except Exception:
                data["session_settings"] = {}
            
            # Information barriers
            try:
                barriers = await self.client._make_request("admin.barriers.list")
                data["information_barriers"] = barriers
            except Exception:
                data["information_barriers"] = {}
        
        return data
    
    def is_applicable(self, workspace_info: Dict[str, Any]) -> bool:
        """Only applicable for Enterprise Grid workspaces."""
        return workspace_info.get("is_enterprise", False)