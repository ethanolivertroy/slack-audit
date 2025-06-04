"""
CSV report generator.
"""

import csv
from pathlib import Path
from .base import Reporter
from ..models import AuditResult


class CSVReporter(Reporter):
    """Generates CSV reports."""
    
    @property
    def format(self) -> str:
        return "csv"
    
    async def generate(self, result: AuditResult, output_dir: Path) -> Path:
        """Generate CSV report."""
        # Generate findings CSV
        findings_path = output_dir / f"findings_{result.audit_id}.csv"
        
        with open(findings_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "id", "title", "severity", "risk_score",
                "confidentiality_impact", "integrity_impact", "availability_impact",
                "description", "recommendations"
            ])
            writer.writeheader()
            
            for finding in result.findings:
                writer.writerow({
                    "id": finding.id,
                    "title": finding.title,
                    "severity": finding.severity.value,
                    "risk_score": getattr(finding, "risk_score", 0),
                    "confidentiality_impact": finding.cia_impact.confidentiality.value,
                    "integrity_impact": finding.cia_impact.integrity.value,
                    "availability_impact": finding.cia_impact.availability.value,
                    "description": finding.description,
                    "recommendations": "; ".join(finding.recommendations)
                })
        
        # Generate control results CSV
        controls_path = output_dir / f"controls_{result.audit_id}.csv"
        
        with open(controls_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=[
                "framework", "control_id", "control_title", "status",
                "risk_score", "findings_count", "tested_at"
            ])
            writer.writeheader()
            
            for framework, controls in result.control_results.items():
                for control in controls:
                    writer.writerow({
                        "framework": framework,
                        "control_id": control.control_id,
                        "control_title": control.control_title,
                        "status": control.status.value,
                        "risk_score": control.risk_score,
                        "findings_count": len(control.findings),
                        "tested_at": control.tested_at.isoformat()
                    })
        
        return findings_path