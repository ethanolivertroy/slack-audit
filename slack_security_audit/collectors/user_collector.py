"""
User data collector.
"""

from typing import Dict, Any
from .base import DataCollector


class UserCollector(DataCollector):
    """Collects user-related information."""
    
    @property
    def name(self) -> str:
        return "users"
    
    async def collect(self) -> Dict[str, Any]:
        """Collect user data."""
        data = {}
        
        # Get all users
        users = await self.client.list_users(include_deleted=True)
        data["users"] = users
        
        # Get user groups
        user_groups = await self.client.get_user_groups()
        data["user_groups"] = user_groups
        
        # Analyze user statistics
        data["stats"] = self._analyze_user_stats(users)
        
        return data
    
    def _analyze_user_stats(self, users: list) -> Dict[str, Any]:
        """Analyze user statistics."""
        stats = {
            "total_users": len(users),
            "active_users": sum(1 for u in users if not u.get("deleted", False)),
            "deleted_users": sum(1 for u in users if u.get("deleted", False)),
            "bot_users": sum(1 for u in users if u.get("is_bot", False)),
            "guest_users": sum(1 for u in users if u.get("is_restricted", False) or u.get("is_ultra_restricted", False)),
            "admin_users": sum(1 for u in users if u.get("is_admin", False)),
            "owner_users": sum(1 for u in users if u.get("is_owner", False)),
            "users_with_2fa": sum(1 for u in users if u.get("has_2fa", False)),
        }
        
        # Calculate percentages
        if stats["active_users"] > 0:
            stats["admin_percentage"] = (stats["admin_users"] / stats["active_users"]) * 100
            stats["2fa_percentage"] = (stats["users_with_2fa"] / stats["active_users"]) * 100
        
        return stats