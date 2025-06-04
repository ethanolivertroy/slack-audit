"""
Data models for the Slack Security Audit Platform.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional
from enum import Enum


class Severity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ComplianceStatus(Enum):
    """Compliance status for controls."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    NOT_ASSESSED = "not_assessed"


class CIAImpact(Enum):
    """CIA triad impact levels."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class CIATriad:
    """CIA triad impact assessment."""
    confidentiality: CIAImpact = CIAImpact.NONE
    integrity: CIAImpact = CIAImpact.NONE
    availability: CIAImpact = CIAImpact.NONE
    
    def to_score(self, weights: Dict[str, float]) -> float:
        """Convert CIA impacts to a weighted score."""
        impact_values = {
            CIAImpact.HIGH: 1.0,
            CIAImpact.MEDIUM: 0.6,
            CIAImpact.LOW: 0.3,
            CIAImpact.NONE: 0.0
        }
        
        return (
            impact_values[self.confidentiality] * weights.get("confidentiality", 0.33) +
            impact_values[self.integrity] * weights.get("integrity", 0.33) +
            impact_values[self.availability] * weights.get("availability", 0.34)
        )


@dataclass
class Finding:
    """Represents a security finding."""
    id: str
    title: str
    description: str
    severity: Severity
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cia_impact: CIATriad = field(default_factory=CIATriad)
    affected_resources: List[str] = field(default_factory=list)


@dataclass
class ControlResult:
    """Result of a control assessment."""
    control_id: str
    control_title: str
    framework: str
    status: ComplianceStatus
    findings: List[Finding] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    tested_at: datetime = field(default_factory=datetime.now)
    cia_impact: CIATriad = field(default_factory=CIATriad)
    risk_score: float = 0.0
    implementation_guidance: Optional[str] = None
    automation_available: bool = False


@dataclass
class RiskScore:
    """Risk scoring for a finding or control."""
    base_score: float
    temporal_score: float
    environmental_score: float
    cia_adjusted_score: float
    final_score: float
    severity: Severity
    
    @classmethod
    def calculate(
        cls,
        severity: Severity,
        cia_impact: CIATriad,
        cia_weights: Dict[str, float],
        exploitability: float = 0.5,
        remediation_level: float = 0.5,
        report_confidence: float = 1.0
    ) -> "RiskScore":
        """Calculate comprehensive risk score."""
        severity_scores = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 2.0,
            Severity.INFO: 0.0
        }
        
        base_score = severity_scores[severity]
        temporal_score = base_score * exploitability * remediation_level
        environmental_score = temporal_score * report_confidence
        cia_adjusted_score = environmental_score * (1 + cia_impact.to_score(cia_weights))
        
        # Normalize to 0-10 scale
        final_score = min(10.0, cia_adjusted_score)
        
        return cls(
            base_score=base_score,
            temporal_score=temporal_score,
            environmental_score=environmental_score,
            cia_adjusted_score=cia_adjusted_score,
            final_score=final_score,
            severity=severity
        )


@dataclass
class AuditResult:
    """Complete audit result."""
    audit_id: str
    audit_type: str  # "point_in_time" or "continuous"
    started_at: datetime
    completed_at: Optional[datetime] = None
    workspace_info: Dict[str, Any] = field(default_factory=dict)
    
    # Raw data collected
    raw_data: Dict[str, Any] = field(default_factory=dict)
    
    # Control results by framework
    control_results: Dict[str, List[ControlResult]] = field(default_factory=dict)
    
    # Aggregate findings
    findings: List[Finding] = field(default_factory=list)
    
    # Compliance summary
    compliance_summary: Dict[str, Dict[str, int]] = field(default_factory=dict)
    
    # Risk summary
    risk_summary: Dict[str, Any] = field(default_factory=dict)
    
    # Recommendations
    recommendations: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def add_control_result(self, framework: str, result: ControlResult):
        """Add a control result to the audit."""
        if framework not in self.control_results:
            self.control_results[framework] = []
        self.control_results[framework].append(result)
    
    def calculate_compliance_percentage(self, framework: str) -> float:
        """Calculate compliance percentage for a framework."""
        if framework not in self.control_results:
            return 0.0
        
        results = self.control_results[framework]
        if not results:
            return 0.0
        
        compliant = sum(1 for r in results if r.status == ComplianceStatus.COMPLIANT)
        total = len(results)
        
        return (compliant / total) * 100
    
    def get_critical_findings(self) -> List[Finding]:
        """Get all critical severity findings."""
        return [f for f in self.findings if f.severity == Severity.CRITICAL]
    
    def get_high_risk_controls(self, threshold: float = 7.0) -> List[ControlResult]:
        """Get controls with high risk scores."""
        high_risk = []
        for framework_results in self.control_results.values():
            high_risk.extend([r for r in framework_results if r.risk_score >= threshold])
        return sorted(high_risk, key=lambda x: x.risk_score, reverse=True)