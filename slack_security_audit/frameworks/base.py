"""
Base class for compliance framework implementations.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
from ..models import ControlResult, Finding, ComplianceStatus, Severity
from ..config import FrameworkConfig
from ..analyzers.cia_analyzer import CIAImpactAnalyzer
from ..analyzers.risk_scorer import RiskScorer


class ComplianceFramework(ABC):
    """Abstract base class for compliance frameworks."""
    
    def __init__(
        self,
        config: FrameworkConfig,
        cia_analyzer: CIAImpactAnalyzer,
        risk_scorer: RiskScorer
    ):
        """
        Initialize the compliance framework.
        
        Args:
            config: Framework configuration
            cia_analyzer: CIA impact analyzer
            risk_scorer: Risk scoring engine
        """
        self.config = config
        self.cia_analyzer = cia_analyzer
        self.risk_scorer = risk_scorer
        self.controls = self._load_controls()
    
    @abstractmethod
    def _load_controls(self) -> Dict[str, Dict[str, Any]]:
        """
        Load control definitions for this framework.
        
        Returns:
            Dictionary mapping control IDs to control information
        """
        pass
    
    @abstractmethod
    async def assess(
        self,
        data: Dict[str, Any],
        workspace_info: Dict[str, Any]
    ) -> List[ControlResult]:
        """
        Assess compliance with framework controls.
        
        Args:
            data: Collected Slack data
            workspace_info: Workspace information
            
        Returns:
            List of control assessment results
        """
        pass
    
    def create_control_result(
        self,
        control_id: str,
        control_title: str,
        status: ComplianceStatus,
        findings: List[Finding],
        evidence: Dict[str, Any],
        implementation_guidance: Optional[str] = None
    ) -> ControlResult:
        """
        Create a standardized control result.
        
        Args:
            control_id: Control identifier
            control_title: Control title
            status: Compliance status
            findings: List of findings
            evidence: Supporting evidence
            implementation_guidance: Optional guidance
            
        Returns:
            ControlResult object
        """
        # Analyze CIA impact for this control
        cia_impact = self.cia_analyzer.analyze_control(control_id, control_title)
        
        # Create the control result
        result = ControlResult(
            control_id=control_id,
            control_title=control_title,
            framework=self.config.name,
            status=status,
            findings=findings,
            evidence=evidence,
            cia_impact=cia_impact,
            implementation_guidance=implementation_guidance
        )
        
        # Calculate risk score
        result.risk_score = self.risk_scorer.calculate_control_risk(
            result,
            workspace_info
        )
        
        return result
    
    def create_finding(
        self,
        title: str,
        description: str,
        severity: Severity,
        evidence: Dict[str, Any],
        recommendations: List[str],
        affected_resources: Optional[List[str]] = None
    ) -> Finding:
        """
        Create a standardized finding.
        
        Args:
            title: Finding title
            description: Detailed description
            severity: Severity level
            evidence: Supporting evidence
            recommendations: List of recommendations
            affected_resources: Optional list of affected resources
            
        Returns:
            Finding object
        """
        finding = Finding(
            id=f"{self.config.name}_{title.lower().replace(' ', '_')}",
            title=title,
            description=description,
            severity=severity,
            evidence=evidence,
            recommendations=recommendations,
            affected_resources=affected_resources or []
        )
        
        # Analyze CIA impact
        finding.cia_impact = self.cia_analyzer.analyze_finding(finding)
        
        return finding
    
    def is_control_applicable(
        self,
        control_id: str,
        workspace_info: Dict[str, Any]
    ) -> bool:
        """
        Check if a control is applicable to the workspace.
        
        Args:
            control_id: Control identifier
            workspace_info: Workspace information
            
        Returns:
            True if applicable, False otherwise
        """
        # Check excluded controls
        if control_id in self.config.excluded_controls:
            return False
        
        # Check custom controls (if specified, only these are checked)
        if self.config.custom_controls:
            return control_id in self.config.custom_controls
        
        # Check control-specific applicability
        control_info = self.controls.get(control_id, {})
        
        # Example: Some controls only apply to Enterprise Grid
        if control_info.get("requires_enterprise") and not workspace_info.get("is_enterprise"):
            return False
        
        return True
    
    def filter_applicable_controls(
        self,
        workspace_info: Dict[str, Any]
    ) -> Dict[str, Dict[str, Any]]:
        """
        Filter controls to only those applicable to the workspace.
        
        Args:
            workspace_info: Workspace information
            
        Returns:
            Dictionary of applicable controls
        """
        return {
            control_id: control_info
            for control_id, control_info in self.controls.items()
            if self.is_control_applicable(control_id, workspace_info)
        }