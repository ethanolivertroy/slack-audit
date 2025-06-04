"""
Base class for data collectors.
"""

from abc import ABC, abstractmethod
from typing import Dict, Any
from ..slack_client import SlackClient


class DataCollector(ABC):
    """Abstract base class for data collectors."""
    
    def __init__(self, client: SlackClient):
        """
        Initialize the data collector.
        
        Args:
            client: Slack API client
        """
        self.client = client
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Get the collector name."""
        pass
    
    @abstractmethod
    async def collect(self) -> Dict[str, Any]:
        """
        Collect data from Slack APIs.
        
        Returns:
            Dictionary containing collected data
        """
        pass
    
    def is_applicable(self, workspace_info: Dict[str, Any]) -> bool:
        """
        Check if this collector is applicable to the workspace.
        
        Args:
            workspace_info: Workspace information
            
        Returns:
            True if applicable, False otherwise
        """
        return True