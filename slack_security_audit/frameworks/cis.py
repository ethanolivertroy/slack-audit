"""
CIS Slack Benchmark compliance framework implementation.
"""

from typing import Dict, List, Any
from ..models import ControlResult, Finding, ComplianceStatus, Severity
from .base import ComplianceFramework


class CISFramework(ComplianceFramework):
    """CIS Slack Benchmark compliance framework."""
    
    def _load_controls(self) -> Dict[str, Dict[str, Any]]:
        """Load CIS Slack Benchmark controls."""
        return {
            "1.1": {
                "title": "Ensure workspace requires two-factor authentication",
                "description": "Two-factor authentication should be required for all users",
                "section": "Identity and Access Management"
            },
            "1.2": {
                "title": "Ensure SSO is configured",
                "description": "Single Sign-On should be configured for centralized authentication",
                "section": "Identity and Access Management"
            },
            "1.3": {
                "title": "Ensure session duration is appropriately configured",
                "description": "Session timeout should be set to organizational requirements",
                "section": "Identity and Access Management"
            },
            "1.4": {
                "title": "Ensure guest access is restricted",
                "description": "Guest users should have minimal permissions",
                "section": "Identity and Access Management"
            },
            "2.1": {
                "title": "Ensure message retention is configured",
                "description": "Message retention policies should align with data governance",
                "section": "Data Protection"
            },
            "2.2": {
                "title": "Ensure file sharing is restricted appropriately",
                "description": "File sharing should be limited to authorized users",
                "section": "Data Protection"
            },
            "2.3": {
                "title": "Ensure public link sharing is disabled",
                "description": "Public links for files should be disabled",
                "section": "Data Protection"
            },
            "3.1": {
                "title": "Ensure app installation is restricted",
                "description": "Only approved apps should be installable",
                "section": "Application Security"
            },
            "3.2": {
                "title": "Ensure app permissions are reviewed",
                "description": "App permissions should be minimal and reviewed regularly",
                "section": "Application Security"
            },
            "4.1": {
                "title": "Ensure audit logs are enabled",
                "description": "Comprehensive audit logging should be enabled",
                "section": "Logging and Monitoring"
            },
            "4.2": {
                "title": "Ensure audit logs are exported",
                "description": "Audit logs should be exported to SIEM",
                "section": "Logging and Monitoring"
            },
            "5.1": {
                "title": "Ensure workspace discovery is disabled",
                "description": "Workspace should not be discoverable publicly",
                "section": "Network Security"
            },
            "5.2": {
                "title": "Ensure email domain is verified",
                "description": "Email domains should be verified to prevent spoofing",
                "section": "Network Security"
            }
        }
    
    async def assess(
        self,
        data: Dict[str, Any],
        workspace_info: Dict[str, Any]
    ) -> List[ControlResult]:
        """Assess compliance with CIS Slack Benchmark."""
        results = []
        
        # 1.1 - Two-factor authentication
        team_2fa = workspace_info.get("workspace_2fa_required", False)
        findings = []
        if not team_2fa:
            findings.append(self.create_finding(
                title="Two-factor authentication not enforced",
                description="Workspace does not require 2FA for all users",
                severity=Severity.HIGH,
                evidence={"2fa_required": False},
                recommendations=[
                    "Enable mandatory 2FA in workspace settings",
                    "Configure SSO with MFA requirements"
                ]
            ))
        
        results.append(self.create_control_result(
            control_id="1.1",
            control_title="Ensure workspace requires two-factor authentication",
            status=ComplianceStatus.COMPLIANT if team_2fa else ComplianceStatus.NON_COMPLIANT,
            findings=findings,
            evidence={"2fa_required": team_2fa}
        ))
        
        # 1.2 - SSO configuration
        enterprise_data = data.get("enterprise", {})
        has_sso = enterprise_data.get("session_settings", {}).get("sso_enabled", False)
        findings = []
        if not has_sso:
            findings.append(self.create_finding(
                title="SSO not configured",
                description="Single Sign-On is not configured for the workspace",
                severity=Severity.MEDIUM,
                evidence={"sso_enabled": False},
                recommendations=[
                    "Configure SAML or OAuth SSO",
                    "Integrate with enterprise identity provider"
                ]
            ))
        
        results.append(self.create_control_result(
            control_id="1.2",
            control_title="Ensure SSO is configured",
            status=ComplianceStatus.COMPLIANT if has_sso else ComplianceStatus.NON_COMPLIANT,
            findings=findings,
            evidence={"sso_enabled": has_sso}
        ))
        
        # 2.2 - File sharing restrictions
        file_data = data.get("files", {})
        public_files = file_data.get("stats", {}).get("public_files", 0)
        findings = []
        if public_files > 0:
            findings.append(self.create_finding(
                title="Public files detected",
                description=f"Found {public_files} publicly accessible files",
                severity=Severity.HIGH,
                evidence={"public_files": public_files},
                recommendations=[
                    "Review and restrict public file access",
                    "Disable public link creation"
                ]
            ))
        
        results.append(self.create_control_result(
            control_id="2.2",
            control_title="Ensure file sharing is restricted appropriately",
            status=ComplianceStatus.COMPLIANT if public_files == 0 else ComplianceStatus.NON_COMPLIANT,
            findings=findings,
            evidence={"public_files": public_files}
        ))
        
        # 3.1 - App installation restrictions
        app_data = data.get("apps", {})
        high_risk_apps = len(app_data.get("high_risk_apps", []))
        findings = []
        if high_risk_apps > 0:
            findings.append(self.create_finding(
                title="High-risk apps detected",
                description=f"Found {high_risk_apps} apps with risky permissions",
                severity=Severity.HIGH,
                evidence={"high_risk_apps": high_risk_apps},
                recommendations=[
                    "Review and remove unnecessary apps",
                    "Restrict app installation to admins only"
                ]
            ))
        
        results.append(self.create_control_result(
            control_id="3.1",
            control_title="Ensure app installation is restricted",
            status=ComplianceStatus.PARTIALLY_COMPLIANT if high_risk_apps > 0 else ComplianceStatus.COMPLIANT,
            findings=findings,
            evidence={"high_risk_apps": high_risk_apps}
        ))
        
        # 4.1 - Audit logs
        audit_logs = data.get("audit_logs", {})
        has_logs = bool(audit_logs.get("logs", []))
        findings = []
        if not has_logs:
            findings.append(self.create_finding(
                title="Audit logs not available",
                description="Unable to access comprehensive audit logs",
                severity=Severity.HIGH,
                evidence={"audit_logs_available": False},
                recommendations=[
                    "Enable Enterprise Grid for audit logs",
                    "Configure audit log retention"
                ]
            ))
        
        results.append(self.create_control_result(
            control_id="4.1",
            control_title="Ensure audit logs are enabled",
            status=ComplianceStatus.COMPLIANT if has_logs else ComplianceStatus.NON_COMPLIANT,
            findings=findings,
            evidence={"audit_logs_available": has_logs}
        ))
        
        return results