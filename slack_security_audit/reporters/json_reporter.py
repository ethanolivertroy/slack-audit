"""
JSON report generator.
"""

import json
from pathlib import Path
from datetime import datetime
from typing import Any
from .base import Reporter
from ..models import AuditResult


class JSONReporter(Reporter):
    """Generates JSON reports."""
    
    @property
    def format(self) -> str:
        return "json"
    
    async def generate(self, result: AuditResult, output_dir: Path) -> Path:
        """Generate JSON report."""
        # Create report structure
        report = {
            "audit_metadata": {
                "audit_id": result.audit_id,
                "audit_type": result.audit_type,
                "started_at": result.started_at.isoformat(),
                "completed_at": result.completed_at.isoformat() if result.completed_at else None,
                "tool_version": result.metadata.get("tool_version", "2.0.0")
            },
            "workspace_info": result.workspace_info,
            "compliance_summary": result.compliance_summary,
            "risk_summary": result.risk_summary,
            "findings": [
                {
                    "id": f.id,
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "cia_impact": {
                        "confidentiality": f.cia_impact.confidentiality.value,
                        "integrity": f.cia_impact.integrity.value,
                        "availability": f.cia_impact.availability.value
                    },
                    "risk_score": getattr(f, "risk_score", 0),
                    "evidence": f.evidence if self.config.reporting.include_evidence else {},
                    "recommendations": f.recommendations,
                    "affected_resources": f.affected_resources
                }
                for f in result.findings
            ],
            "control_results": {
                framework: [
                    {
                        "control_id": cr.control_id,
                        "control_title": cr.control_title,
                        "status": cr.status.value,
                        "risk_score": cr.risk_score,
                        "cia_impact": {
                            "confidentiality": cr.cia_impact.confidentiality.value,
                            "integrity": cr.cia_impact.integrity.value,
                            "availability": cr.cia_impact.availability.value
                        },
                        "findings_count": len(cr.findings),
                        "evidence": cr.evidence if self.config.reporting.include_evidence else {},
                        "tested_at": cr.tested_at.isoformat()
                    }
                    for cr in controls
                ]
                for framework, controls in result.control_results.items()
            },
            "recommendations": result.recommendations
        }
        
        # Include raw data if configured
        if self.config.reporting.include_raw_data:
            report["raw_data"] = result.raw_data
        
        # Save report
        report_path = output_dir / f"audit_report_{result.audit_id}.json"
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        # Also save individual framework results
        for framework, controls in result.control_results.items():
            framework_path = output_dir / f"{framework}_results.json"
            framework_data = {
                "framework": framework,
                "audit_id": result.audit_id,
                "compliance_summary": result.compliance_summary.get(framework, {}),
                "controls": [
                    {
                        "control_id": cr.control_id,
                        "control_title": cr.control_title,
                        "status": cr.status.value,
                        "risk_score": cr.risk_score,
                        "findings": [
                            {
                                "title": f.title,
                                "severity": f.severity.value,
                                "description": f.description
                            }
                            for f in cr.findings
                        ]
                    }
                    for cr in controls
                ]
            }
            with open(framework_path, "w") as f:
                json.dump(framework_data, f, indent=2)
        
        return report_path