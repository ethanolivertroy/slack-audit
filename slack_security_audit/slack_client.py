"""
Enhanced Slack API client with comprehensive endpoint coverage.
"""

import asyncio
import aiohttp
import time
from typing import Dict, List, Any, Optional
import logging
from urllib.parse import urlencode

from .config import ScanningConfig
from .exceptions import AuthenticationError, InsufficientPermissionsError, APIError


logger = logging.getLogger(__name__)


class SlackClient:
    """Async Slack API client with rate limiting and error handling."""
    
    BASE_URL = "https://api.slack.com/api"
    
    # Required scopes for comprehensive auditing
    REQUIRED_SCOPES = [
        "admin", "admin.teams:read", "admin.users:read",
        "admin.conversations:read", "admin.apps:read",
        "channels:read", "groups:read", "im:read", "mpim:read",
        "team:read", "users:read", "files:read", "apps:read",
        "audit:read"  # For Enterprise Grid audit logs
    ]
    
    def __init__(self, token: str, config: ScanningConfig):
        """
        Initialize Slack client.
        
        Args:
            token: Slack API token
            config: Scanning configuration
        """
        self.token = token
        self.config = config
        self.session = None
        self._rate_limiter = RateLimiter(
            requests_per_minute=60,
            burst_size=20
        )
    
    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(
            headers={
                "Authorization": f"Bearer {self.token}",
                "Content-Type": "application/json"
            },
            timeout=aiohttp.ClientTimeout(total=self.config.request_timeout)
        )
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()
    
    async def validate_token(self) -> Dict[str, Any]:
        """
        Validate token and check permissions.
        
        Returns:
            Workspace information
        """
        result = await self._make_request("auth.test")
        
        if not result.get("ok"):
            raise AuthenticationError(f"Invalid token: {result.get('error', 'Unknown error')}")
        
        # Check if we have admin access
        scopes = result.get("headers", {}).get("x-oauth-scopes", "").split(",")
        missing_scopes = set(self.REQUIRED_SCOPES) - set(scopes)
        
        if missing_scopes:
            logger.warning(f"Missing recommended scopes: {missing_scopes}")
        
        workspace_info = {
            "team_id": result.get("team_id"),
            "team_name": result.get("team"),
            "user_id": result.get("user_id"),
            "user_name": result.get("user"),
            "is_enterprise": result.get("is_enterprise_install", False),
            "scopes": scopes
        }
        
        # Get additional team info
        team_info = await self.get_team_info()
        workspace_info.update(team_info)
        
        return workspace_info
    
    async def _make_request(
        self,
        endpoint: str,
        method: str = "GET",
        params: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        paginate: bool = False
    ) -> Any:
        """
        Make an API request with rate limiting and error handling.
        
        Args:
            endpoint: API endpoint
            method: HTTP method
            params: Query parameters
            json_data: JSON body data
            paginate: Whether to automatically handle pagination
            
        Returns:
            API response data
        """
        await self._rate_limiter.acquire()
        
        url = f"{self.BASE_URL}/{endpoint}"
        
        if params:
            url += f"?{urlencode(params)}"
        
        try:
            async with self.session.request(method, url, json=json_data) as response:
                data = await response.json()
                
                if not data.get("ok"):
                    error = data.get("error", "Unknown error")
                    if error == "invalid_auth":
                        raise AuthenticationError(f"Authentication failed: {error}")
                    elif error == "missing_scope":
                        raise InsufficientPermissionsError(f"Missing required scope: {data.get('needed', 'unknown')}")
                    else:
                        raise APIError(f"API error: {error}")
                
                # Handle pagination if requested
                if paginate and data.get("response_metadata", {}).get("next_cursor"):
                    all_results = data.get("users", []) or data.get("channels", []) or data.get("files", []) or []
                    cursor = data["response_metadata"]["next_cursor"]
                    
                    while cursor:
                        params = params or {}
                        params["cursor"] = cursor
                        
                        page_data = await self._make_request(endpoint, method, params, json_data, paginate=False)
                        
                        # Append results based on response structure
                        if "users" in page_data:
                            all_results.extend(page_data["users"])
                        elif "channels" in page_data:
                            all_results.extend(page_data["channels"])
                        elif "files" in page_data:
                            all_results.extend(page_data["files"])
                        
                        cursor = page_data.get("response_metadata", {}).get("next_cursor")
                    
                    # Update original data with all results
                    if "users" in data:
                        data["users"] = all_results
                    elif "channels" in data:
                        data["channels"] = all_results
                    elif "files" in data:
                        data["files"] = all_results
                
                return data
                
        except asyncio.TimeoutError:
            raise APIError(f"Request to {endpoint} timed out")
        except aiohttp.ClientError as e:
            raise APIError(f"Network error: {str(e)}")
    
    # Team and Enterprise APIs
    async def get_team_info(self) -> Dict[str, Any]:
        """Get team information."""
        return await self._make_request("team.info")
    
    async def get_enterprise_info(self) -> Dict[str, Any]:
        """Get enterprise grid information."""
        try:
            return await self._make_request("admin.teams.list", params={"limit": 100})
        except (InsufficientPermissionsError, APIError):
            return {"ok": False, "error": "not_enterprise"}
    
    # User APIs
    async def list_users(self, include_deleted: bool = False) -> List[Dict[str, Any]]:
        """List all users in the workspace."""
        params = {"limit": 200}
        if include_deleted:
            params["include_deleted"] = "true"
        
        result = await self._make_request("users.list", params=params, paginate=True)
        return result.get("users", [])
    
    async def get_user_groups(self) -> List[Dict[str, Any]]:
        """Get user groups."""
        result = await self._make_request("usergroups.list")
        return result.get("usergroups", [])
    
    # Channel APIs
    async def list_channels(self, types: str = "public_channel,private_channel") -> List[Dict[str, Any]]:
        """List all channels."""
        params = {
            "types": types,
            "limit": 200,
            "exclude_archived": "false"
        }
        result = await self._make_request("conversations.list", params=params, paginate=True)
        return result.get("channels", [])
    
    # App APIs
    async def list_apps(self) -> List[Dict[str, Any]]:
        """List installed apps."""
        try:
            result = await self._make_request("admin.apps.approved.list", params={"limit": 200})
            return result.get("approved_apps", [])
        except InsufficientPermissionsError:
            # Fallback to basic apps list
            result = await self._make_request("apps.permissions.resources.list")
            return result.get("resources", [])
    
    async def get_app_permissions(self, app_id: str) -> Dict[str, Any]:
        """Get permissions for a specific app."""
        return await self._make_request("apps.permissions.info", params={"app_id": app_id})
    
    # File APIs
    async def list_files(self, count: int = 100) -> List[Dict[str, Any]]:
        """List recent files."""
        params = {"count": count}
        result = await self._make_request("files.list", params=params)
        return result.get("files", [])
    
    # Admin APIs (Enterprise Grid)
    async def get_admin_settings(self) -> Dict[str, Any]:
        """Get admin settings for the workspace."""
        settings = {}
        
        # Try various admin endpoints
        endpoints = [
            ("admin.apps.config.get", "app_management_settings"),
            ("admin.barriers.list", "information_barriers"),
            ("admin.conversations.getConversationPrefs", "conversation_settings"),
        ]
        
        for endpoint, key in endpoints:
            try:
                result = await self._make_request(endpoint)
                settings[key] = result
            except (InsufficientPermissionsError, APIError) as e:
                logger.debug(f"Could not access {endpoint}: {e}")
                settings[key] = {"available": False}
        
        return settings
    
    # Audit Log APIs (Enterprise Grid)
    async def get_audit_logs(self, limit: int = 1000) -> List[Dict[str, Any]]:
        """Get audit logs (Enterprise Grid only)."""
        try:
            params = {"limit": limit}
            result = await self._make_request("audit.logs", params=params)
            return result.get("entries", [])
        except (InsufficientPermissionsError, APIError):
            return []
    
    # Security APIs
    async def get_session_settings(self) -> Dict[str, Any]:
        """Get session configuration."""
        try:
            return await self._make_request("admin.teams.settings.info")
        except (InsufficientPermissionsError, APIError):
            return {"available": False}
    
    async def get_2fa_status(self) -> Dict[str, Any]:
        """Get 2FA enforcement status."""
        # This info is typically in team settings
        team_info = await self.get_team_info()
        return {
            "workspace_2fa_required": team_info.get("team", {}).get("two_factor_required", False)
        }


class RateLimiter:
    """Simple rate limiter for API requests."""
    
    def __init__(self, requests_per_minute: int = 60, burst_size: int = 20):
        self.requests_per_minute = requests_per_minute
        self.burst_size = burst_size
        self.tokens = burst_size
        self.last_update = time.time()
        self.lock = asyncio.Lock()
    
    async def acquire(self):
        """Acquire a token to make a request."""
        async with self.lock:
            now = time.time()
            elapsed = now - self.last_update
            
            # Add tokens based on elapsed time
            new_tokens = elapsed * (self.requests_per_minute / 60)
            self.tokens = min(self.burst_size, self.tokens + new_tokens)
            self.last_update = now
            
            # Wait if no tokens available
            while self.tokens < 1:
                await asyncio.sleep(0.1)
                now = time.time()
                elapsed = now - self.last_update
                new_tokens = elapsed * (self.requests_per_minute / 60)
                self.tokens = min(self.burst_size, self.tokens + new_tokens)
                self.last_update = now
            
            self.tokens -= 1