"""
Risk scoring engine for security findings and controls.
"""

from typing import Dict, List, Any, Optional
from ..models import Finding, ControlResult, RiskScore, Severity, CIATriad
from ..config import AuditConfig


class RiskScorer:
    """Calculates risk scores based on multiple factors including CIA impact."""
    
    def __init__(self, config: AuditConfig):
        """
        Initialize the risk scorer.
        
        Args:
            config: Audit configuration with risk thresholds
        """
        self.config = config
        self.cia_weights = {
            "confidentiality": config.cia_weights.confidentiality,
            "integrity": config.cia_weights.integrity,
            "availability": config.cia_weights.availability
        }
    
    def calculate_finding_risk(
        self,
        finding: Finding,
        workspace_info: Dict[str, Any]
    ) -> RiskScore:
        """
        Calculate risk score for a finding.
        
        Args:
            finding: Security finding
            workspace_info: Workspace context information
            
        Returns:
            Calculated risk score
        """
        # Determine exploitability based on finding characteristics
        exploitability = self._calculate_exploitability(finding, workspace_info)
        
        # Determine remediation level
        remediation_level = self._calculate_remediation_level(finding)
        
        # Determine report confidence
        report_confidence = self._calculate_confidence(finding)
        
        # Calculate the risk score
        risk_score = RiskScore.calculate(
            severity=finding.severity,
            cia_impact=finding.cia_impact,
            cia_weights=self.cia_weights,
            exploitability=exploitability,
            remediation_level=remediation_level,
            report_confidence=report_confidence
        )
        
        return risk_score
    
    def calculate_control_risk(
        self,
        control: ControlResult,
        workspace_info: Dict[str, Any]
    ) -> float:
        """
        Calculate risk score for a control.
        
        Args:
            control: Control result
            workspace_info: Workspace context
            
        Returns:
            Risk score (0-10)
        """
        # If compliant, minimal risk
        if control.status.value == "compliant":
            return 0.0
        
        # Base risk on compliance status
        status_risk = {
            "non_compliant": 8.0,
            "partially_compliant": 5.0,
            "not_applicable": 0.0,
            "not_assessed": 3.0
        }
        
        base_risk = status_risk.get(control.status.value, 5.0)
        
        # Adjust based on CIA impact
        cia_multiplier = 1 + control.cia_impact.to_score(self.cia_weights)
        
        # Adjust based on workspace characteristics
        workspace_multiplier = self._calculate_workspace_multiplier(workspace_info)
        
        # Calculate final risk
        final_risk = base_risk * cia_multiplier * workspace_multiplier
        
        # Normalize to 0-10 scale
        return min(10.0, final_risk)
    
    def _calculate_exploitability(
        self,
        finding: Finding,
        workspace_info: Dict[str, Any]
    ) -> float:
        """
        Calculate exploitability score (0-1).
        
        Higher scores mean easier to exploit.
        """
        score = 0.5  # Default medium exploitability
        
        # Adjust based on finding characteristics
        if "external" in finding.title.lower() or "public" in finding.title.lower():
            score += 0.2
        
        if "authentication" in finding.title.lower() or "2fa" in finding.title.lower():
            score += 0.1
        
        if "admin" in finding.title.lower() or "privilege" in finding.title.lower():
            score += 0.15
        
        # Adjust based on workspace characteristics
        if workspace_info.get("is_enterprise"):
            score -= 0.1  # Enterprise has more security controls
        
        user_count = len(workspace_info.get("users", []))
        if user_count > 1000:
            score += 0.1  # Larger attack surface
        
        return max(0.0, min(1.0, score))
    
    def _calculate_remediation_level(self, finding: Finding) -> float:
        """
        Calculate remediation level (0-1).
        
        Higher scores mean harder to remediate.
        """
        # Check if automation is mentioned in recommendations
        has_automation = any("automat" in rec.lower() for rec in finding.recommendations)
        
        # Check complexity indicators
        is_complex = any(word in finding.description.lower() 
                        for word in ["implement", "deploy", "integrate", "migrate"])
        
        # Check if it's a configuration issue (easier to fix)
        is_config = "configuration" in finding.title.lower() or "setting" in finding.title.lower()
        
        if has_automation and is_config:
            return 0.2  # Easy to fix
        elif is_config:
            return 0.4  # Moderate
        elif is_complex:
            return 0.8  # Hard to fix
        else:
            return 0.5  # Default medium
    
    def _calculate_confidence(self, finding: Finding) -> float:
        """
        Calculate report confidence (0-1).
        
        Higher scores mean more confidence in the finding.
        """
        # Base confidence on evidence quality
        if finding.evidence:
            if len(finding.evidence) > 5:
                return 1.0  # High confidence with lots of evidence
            elif len(finding.evidence) > 2:
                return 0.8  # Good confidence
            else:
                return 0.6  # Some evidence
        else:
            return 0.4  # No evidence, lower confidence
    
    def _calculate_workspace_multiplier(self, workspace_info: Dict[str, Any]) -> float:
        """
        Calculate risk multiplier based on workspace characteristics.
        
        Returns:
            Multiplier (0.5-1.5)
        """
        multiplier = 1.0
        
        # Larger workspaces have higher risk
        user_count = len(workspace_info.get("users", []))
        if user_count > 5000:
            multiplier += 0.3
        elif user_count > 1000:
            multiplier += 0.2
        elif user_count > 100:
            multiplier += 0.1
        
        # Enterprise workspaces typically have better controls
        if workspace_info.get("is_enterprise"):
            multiplier -= 0.2
        
        # Check for high-risk industries (would need to be detected from workspace name/domain)
        workspace_name = workspace_info.get("team_name", "").lower()
        high_risk_indicators = ["financial", "health", "government", "defense"]
        if any(indicator in workspace_name for indicator in high_risk_indicators):
            multiplier += 0.2
        
        return max(0.5, min(1.5, multiplier))
    
    def prioritize_findings(
        self,
        findings: List[Finding],
        limit: Optional[int] = None
    ) -> List[Finding]:
        """
        Prioritize findings based on risk scores.
        
        Args:
            findings: List of findings to prioritize
            limit: Maximum number of findings to return
            
        Returns:
            Prioritized list of findings
        """
        # Sort by risk score (descending)
        sorted_findings = sorted(
            findings,
            key=lambda f: getattr(f, 'risk_score', 0),
            reverse=True
        )
        
        if limit:
            return sorted_findings[:limit]
        return sorted_findings
    
    def calculate_aggregate_risk(
        self,
        findings: List[Finding],
        control_results: List[ControlResult]
    ) -> Dict[str, Any]:
        """
        Calculate aggregate risk metrics.
        
        Args:
            findings: List of findings
            control_results: List of control results
            
        Returns:
            Dictionary with risk metrics
        """
        if not findings and not control_results:
            return {
                "overall_risk_score": 0.0,
                "risk_level": "low",
                "critical_risks": 0,
                "high_risks": 0
            }
        
        # Calculate average risk scores
        finding_scores = [getattr(f, 'risk_score', 0) for f in findings]
        control_scores = [c.risk_score for c in control_results]
        all_scores = finding_scores + control_scores
        
        avg_score = sum(all_scores) / len(all_scores) if all_scores else 0
        
        # Determine risk level
        if avg_score >= self.config.risk_thresholds["critical"]:
            risk_level = "critical"
        elif avg_score >= self.config.risk_thresholds["high"]:
            risk_level = "high"
        elif avg_score >= self.config.risk_thresholds["medium"]:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Count critical and high risks
        critical_risks = sum(1 for s in all_scores if s >= self.config.risk_thresholds["critical"])
        high_risks = sum(1 for s in all_scores if s >= self.config.risk_thresholds["high"])
        
        return {
            "overall_risk_score": round(avg_score, 2),
            "risk_level": risk_level,
            "critical_risks": critical_risks,
            "high_risks": high_risks,
            "total_risks": len(all_scores),
            "risk_distribution": {
                "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
                "high": sum(1 for f in findings if f.severity == Severity.HIGH),
                "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
                "low": sum(1 for f in findings if f.severity == Severity.LOW),
                "info": sum(1 for f in findings if f.severity == Severity.INFO)
            }
        }