"""
Application and integration data collector.
"""

from typing import Dict, Any
from .base import DataCollector


class AppCollector(DataCollector):
    """Collects app and integration information."""
    
    @property
    def name(self) -> str:
        return "apps"
    
    async def collect(self) -> Dict[str, Any]:
        """Collect app data."""
        data = {}
        
        # Get installed apps
        apps = await self.client.list_apps()
        data["installed_apps"] = apps
        data["app_count"] = len(apps)
        
        # Analyze app permissions
        risky_scopes = [
            "files:write", "files:read", "channels:write",
            "groups:write", "im:write", "mpim:write",
            "users:write", "admin"
        ]
        
        high_risk_apps = []
        for app in apps:
            # Try to get detailed permissions
            try:
                if "app_id" in app:
                    perms = await self.client.get_app_permissions(app["app_id"])
                    app["permissions"] = perms
                    
                    # Check for risky scopes
                    app_scopes = perms.get("info", {}).get("scopes", {}).get("app", [])
                    risky = [s for s in app_scopes if s in risky_scopes]
                    if risky:
                        high_risk_apps.append({
                            "app_id": app["app_id"],
                            "app_name": app.get("app_name", "Unknown"),
                            "risky_scopes": risky
                        })
            except Exception:
                pass
        
        data["high_risk_apps"] = high_risk_apps
        data["stats"] = {
            "total_apps": len(apps),
            "high_risk_apps": len(high_risk_apps)
        }
        
        return data