"""
FedRAMP compliance framework implementation.
"""

from typing import Dict, List, Any
from ..models import ControlResult, ComplianceStatus
from .nist_800_53 import NIST80053Framework


class FedRAMPFramework(NIST80053Framework):
    """FedRAMP compliance framework (inherits from NIST 800-53)."""
    
    def _load_controls(self) -> Dict[str, Dict[str, Any]]:
        """Load FedRAMP control baselines."""
        # FedRAMP uses NIST 800-53 controls with specific baselines
        controls = super()._load_controls()
        
        # Add FedRAMP-specific control selections based on impact level
        if self.config.profile == "high":
            # High baseline includes all controls
            return controls
        elif self.config.profile == "moderate":
            # Moderate baseline excludes some controls
            moderate_excluded = ["AC-2(2)", "AC-2(4)", "AU-10", "SC-17"]
            return {k: v for k, v in controls.items() if k not in moderate_excluded}
        else:
            # Low baseline has fewer controls
            low_controls = [
                "AC-2", "AC-3", "AC-5", "AC-6", "AC-8",
                "AU-2", "AU-3", "AU-6", "AU-9",
                "CM-2", "CM-6",
                "IA-2", "IA-5",
                "SC-7", "SC-8", "SC-13",
                "SI-3", "SI-4"
            ]
            return {k: v for k, v in controls.items() if k in low_controls}
    
    async def assess(
        self,
        data: Dict[str, Any],
        workspace_info: Dict[str, Any]
    ) -> List[ControlResult]:
        """Assess FedRAMP compliance using NIST controls."""
        # Use NIST assessment with FedRAMP branding
        results = await super().assess(data, workspace_info)
        
        # Update framework name in results
        for result in results:
            result.framework = "fedramp"
        
        return results