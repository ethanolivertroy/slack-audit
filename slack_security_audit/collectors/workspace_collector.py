"""
Workspace data collector.
"""

from typing import Dict, Any
from .base import DataCollector


class WorkspaceCollector(DataCollector):
    """Collects workspace-level information."""
    
    @property
    def name(self) -> str:
        return "workspace"
    
    async def collect(self) -> Dict[str, Any]:
        """Collect workspace data."""
        data = {}
        
        # Get team information
        team_info = await self.client.get_team_info()
        data["team_info"] = team_info.get("team", {})
        
        # Get workspace preferences
        try:
            prefs = await self.client._make_request("team.preferences.list")
            data["preferences"] = prefs
        except Exception:
            data["preferences"] = {}
        
        # Get workspace settings
        try:
            settings = await self.client.get_session_settings()
            data["session_settings"] = settings
        except Exception:
            data["session_settings"] = {}
        
        # Get 2FA status
        data["2fa_status"] = await self.client.get_2fa_status()
        
        return data