"""
Markdown report generator.
"""

from pathlib import Path
from datetime import datetime
from .base import Reporter
from ..models import AuditResult, Severity, ComplianceStatus


class MarkdownReporter(Reporter):
    """Generates Markdown reports."""
    
    @property
    def format(self) -> str:
        return "markdown"
    
    async def generate(self, result: AuditResult, output_dir: Path) -> Path:
        """Generate Markdown report."""
        lines = []
        
        # Header
        lines.append("# Slack Security Audit Report")
        lines.append(f"\n**Generated**: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"**Audit ID**: {result.audit_id}")
        lines.append(f"**Workspace**: {result.workspace_info.get('team_name', 'Unknown')}")
        lines.append(f"**Audit Type**: {result.audit_type.replace('_', ' ').title()}")
        
        # Executive Summary
        if self.config.reporting.executive_summary:
            lines.append("\n## Executive Summary")
            
            # Overall compliance
            lines.append("\n### Overall Compliance")
            for framework, summary in result.compliance_summary.items():
                lines.append(f"\n**{framework.upper()}**: {summary['compliance_percentage']:.1f}% Compliant")
                lines.append(f"- Total Controls: {summary['total_controls']}")
                lines.append(f"- Compliant: {summary['compliant']}")
                lines.append(f"- Non-Compliant: {summary['non_compliant']}")
            
            # Risk overview
            lines.append("\n### Risk Overview")
            risk = result.risk_summary
            lines.append(f"- **Total Findings**: {risk['total_findings']}")
            lines.append(f"- **Average Risk Score**: {risk['average_risk_score']:.2f}/10")
            lines.append(f"- **Critical Issues**: {risk['by_severity']['critical']}")
            lines.append(f"- **High Risk Issues**: {risk['by_severity']['high']}")
        
        # CIA Impact Summary
        lines.append("\n## CIA Triad Impact Analysis")
        lines.append("\nThis assessment evaluates impacts on:")
        lines.append("- **Confidentiality**: Protection of sensitive information")
        lines.append("- **Integrity**: Accuracy and trustworthiness of data")
        lines.append("- **Availability**: Accessibility of systems and data")
        
        # Critical Findings
        critical_findings = result.get_critical_findings()
        if critical_findings:
            lines.append("\n## Critical Findings")
            for finding in critical_findings[:10]:
                lines.append(f"\n### {finding.title}")
                lines.append(f"**Severity**: {finding.severity.value.upper()}")
                lines.append(f"**Risk Score**: {getattr(finding, 'risk_score', 'N/A')}")
                lines.append(f"**CIA Impact**: C={finding.cia_impact.confidentiality.value}, I={finding.cia_impact.integrity.value}, A={finding.cia_impact.availability.value}")
                lines.append(f"\n{finding.description}")
                
                if finding.recommendations:
                    lines.append("\n**Recommendations:**")
                    for rec in finding.recommendations:
                        if rec:
                            lines.append(f"- {rec}")
        
        # Top Recommendations
        if result.recommendations:
            lines.append("\n## Priority Recommendations")
            for i, rec in enumerate(result.recommendations[:10], 1):
                lines.append(f"\n### {i}. {rec['title']}")
                lines.append(f"**Risk Score**: {rec['risk_score']:.1f}")
                lines.append(f"**Estimated Effort**: {rec['estimated_effort'].title()}")
                lines.append("\n**Actions:**")
                for action in rec['recommendations']:
                    if action:
                        lines.append(f"- {action}")
        
        # Detailed Compliance Results
        if self.config.reporting.technical_details:
            lines.append("\n## Detailed Compliance Results")
            
            for framework, controls in result.control_results.items():
                lines.append(f"\n### {framework.upper()}")
                
                # Group by status
                compliant = [c for c in controls if c.status == ComplianceStatus.COMPLIANT]
                non_compliant = [c for c in controls if c.status == ComplianceStatus.NON_COMPLIANT]
                partial = [c for c in controls if c.status == ComplianceStatus.PARTIALLY_COMPLIANT]
                
                if non_compliant:
                    lines.append("\n#### Non-Compliant Controls")
                    for control in sorted(non_compliant, key=lambda x: x.risk_score, reverse=True):
                        lines.append(f"\n**{control.control_id}**: {control.control_title}")
                        lines.append(f"- Risk Score: {control.risk_score:.1f}")
                        lines.append(f"- CIA Impact: C={control.cia_impact.confidentiality.value}, I={control.cia_impact.integrity.value}, A={control.cia_impact.availability.value}")
                        if control.findings:
                            lines.append("- Findings:")
                            for finding in control.findings[:3]:
                                lines.append(f"  - {finding.title}")
                
                if partial:
                    lines.append("\n#### Partially Compliant Controls")
                    for control in partial:
                        lines.append(f"- **{control.control_id}**: {control.control_title} (Risk: {control.risk_score:.1f})")
        
        # Risk Matrix
        if self.config.reporting.risk_matrix:
            lines.append("\n## Risk Matrix")
            lines.append("\n| Risk Level | Count | Percentage |")
            lines.append("|------------|-------|------------|")
            
            total_findings = result.risk_summary['total_findings']
            for level in ["critical", "high", "medium", "low", "info"]:
                count = result.risk_summary['by_severity'][level]
                percentage = (count / total_findings * 100) if total_findings > 0 else 0
                lines.append(f"| {level.title()} | {count} | {percentage:.1f}% |")
        
        # Appendix
        lines.append("\n## Appendix")
        lines.append("\n### Audit Configuration")
        lines.append(f"- CIA Weights: C={self.config.cia_weights.confidentiality}, I={self.config.cia_weights.integrity}, A={self.config.cia_weights.availability}")
        lines.append(f"- Deep Scan: {self.config.scanning.deep_scan}")
        lines.append(f"- Frameworks Assessed: {', '.join(f.name for f in self.config.frameworks)}")
        
        # Save report
        report_path = output_dir / f"audit_report_{result.audit_id}.md"
        with open(report_path, "w") as f:
            f.write("\n".join(lines))
        
        return report_path