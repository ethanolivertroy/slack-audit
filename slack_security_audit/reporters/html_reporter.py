"""
HTML report generator.
"""

from pathlib import Path
from datetime import datetime
from .base import Reporter
from ..models import AuditResult


class HTMLReporter(Reporter):
    """Generates HTML reports."""
    
    @property
    def format(self) -> str:
        return "html"
    
    async def generate(self, result: AuditResult, output_dir: Path) -> Path:
        """Generate HTML report."""
        # Basic HTML report
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>Slack Security Audit Report - {result.audit_id}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1, h2, h3 {{ color: #333; }}
        .summary {{ background: #f0f0f0; padding: 20px; border-radius: 5px; }}
        .critical {{ color: #d32f2f; }}
        .high {{ color: #f57c00; }}
        .medium {{ color: #fbc02d; }}
        .low {{ color: #388e3c; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
    <h1>Slack Security Audit Report</h1>
    <div class="summary">
        <p><strong>Audit ID:</strong> {result.audit_id}</p>
        <p><strong>Workspace:</strong> {result.workspace_info.get('team_name', 'Unknown')}</p>
        <p><strong>Date:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    </div>
    
    <h2>Compliance Summary</h2>
    <table>
        <tr>
            <th>Framework</th>
            <th>Compliance Rate</th>
            <th>Compliant</th>
            <th>Non-Compliant</th>
        </tr>
"""
        for framework, summary in result.compliance_summary.items():
            html += f"""
        <tr>
            <td>{framework.upper()}</td>
            <td>{summary['compliance_percentage']:.1f}%</td>
            <td>{summary['compliant']}</td>
            <td>{summary['non_compliant']}</td>
        </tr>
"""
        
        html += """
    </table>
    
    <h2>Risk Summary</h2>
"""
        risk = result.risk_summary
        html += f"""
    <p><strong>Total Findings:</strong> {risk['total_findings']}</p>
    <p><strong>Average Risk Score:</strong> {risk['average_risk_score']:.2f}/10</p>
    <ul>
        <li class="critical">Critical: {risk['by_severity']['critical']}</li>
        <li class="high">High: {risk['by_severity']['high']}</li>
        <li class="medium">Medium: {risk['by_severity']['medium']}</li>
        <li class="low">Low: {risk['by_severity']['low']}</li>
    </ul>
    
    <h2>Top Recommendations</h2>
    <ol>
"""
        for rec in result.recommendations[:5]:
            html += f"""
        <li>
            <strong>{rec['title']}</strong> (Risk Score: {rec['risk_score']:.1f})
            <ul>
"""
            for action in rec['recommendations']:
                if action:
                    html += f"                <li>{action}</li>\n"
            html += """            </ul>
        </li>
"""
        
        html += """
    </ol>
</body>
</html>"""
        
        # Save report
        report_path = output_dir / f"audit_report_{result.audit_id}.html"
        with open(report_path, "w") as f:
            f.write(html)
        
        return report_path