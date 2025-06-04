"""
Base class for report generators.
"""

from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any
from ..models import AuditResult
from ..config import AuditConfig


class Reporter(ABC):
    """Abstract base class for report generators."""
    
    def __init__(self, config: AuditConfig):
        """
        Initialize the reporter.
        
        Args:
            config: Audit configuration
        """
        self.config = config
    
    @property
    @abstractmethod
    def format(self) -> str:
        """Get the report format name."""
        pass
    
    @abstractmethod
    async def generate(self, result: AuditResult, output_dir: Path) -> Path:
        """
        Generate report from audit results.
        
        Args:
            result: Audit results
            output_dir: Directory to save report
            
        Returns:
            Path to generated report
        """
        pass