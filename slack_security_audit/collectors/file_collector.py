"""
File sharing and storage data collector.
"""

from typing import Dict, Any
from .base import DataCollector


class FileCollector(DataCollector):
    """Collects file sharing information."""
    
    @property
    def name(self) -> str:
        return "files"
    
    async def collect(self) -> Dict[str, Any]:
        """Collect file data."""
        data = {}
        
        # Get sample of recent files
        files = await self.client.list_files(count=100)
        data["recent_files"] = files
        
        # Analyze file sharing patterns
        stats = {
            "total_files": len(files),
            "public_files": 0,
            "external_shares": 0,
            "file_types": {}
        }
        
        for file in files:
            # Check if file is public
            if file.get("is_public", False):
                stats["public_files"] += 1
            
            # Check for external sharing
            if file.get("is_external", False):
                stats["external_shares"] += 1
            
            # Track file types
            mimetype = file.get("mimetype", "unknown")
            stats["file_types"][mimetype] = stats["file_types"].get(mimetype, 0) + 1
        
        data["stats"] = stats
        
        # Get file retention settings if available
        try:
            retention = await self.client._make_request("admin.teams.settings.info")
            data["retention_settings"] = retention.get("team", {}).get("file_retention", {})
        except Exception:
            data["retention_settings"] = {}
        
        return data