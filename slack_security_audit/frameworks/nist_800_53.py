"""
NIST 800-53 Rev 5 compliance framework implementation.
"""

from typing import Dict, List, Any
from ..models import ControlResult, Finding, ComplianceStatus, Severity
from .base import ComplianceFramework


class NIST80053Framework(ComplianceFramework):
    """NIST 800-53 Rev 5 compliance framework."""
    
    def _load_controls(self) -> Dict[str, Dict[str, Any]]:
        """Load NIST 800-53 Rev 5 control definitions."""
        return {
            # Access Control Family
            "AC-2": {
                "title": "Account Management",
                "description": "Manage information system accounts",
                "family": "Access Control"
            },
            "AC-2(1)": {
                "title": "Account Management | Automated System Account Management",
                "description": "Support account management through automated mechanisms",
                "family": "Access Control"
            },
            "AC-2(2)": {
                "title": "Account Management | Removal of Temporary / Emergency Accounts",
                "description": "Automatically remove or disable temporary and emergency accounts",
                "family": "Access Control"
            },
            "AC-2(3)": {
                "title": "Account Management | Disable Inactive Accounts",
                "description": "Automatically disable inactive accounts",
                "family": "Access Control"
            },
            "AC-2(4)": {
                "title": "Account Management | Automated Audit Actions",
                "description": "Automatically audit account actions",
                "family": "Access Control"
            },
            "AC-3": {
                "title": "Access Enforcement",
                "description": "Enforce approved authorizations for logical access",
                "family": "Access Control"
            },
            "AC-4": {
                "title": "Information Flow Enforcement",
                "description": "Control information flows within the system",
                "family": "Access Control"
            },
            "AC-5": {
                "title": "Separation of Duties",
                "description": "Separate duties of individuals",
                "family": "Access Control"
            },
            "AC-6": {
                "title": "Least Privilege",
                "description": "Employ the principle of least privilege",
                "family": "Access Control"
            },
            "AC-7": {
                "title": "Unsuccessful Logon Attempts",
                "description": "Enforce a limit on consecutive invalid logon attempts",
                "family": "Access Control"
            },
            "AC-8": {
                "title": "System Use Notification",
                "description": "Display system use notification",
                "family": "Access Control"
            },
            "AC-11": {
                "title": "Session Lock",
                "description": "Prevent access via session lock",
                "family": "Access Control"
            },
            "AC-12": {
                "title": "Session Termination",
                "description": "Automatically terminate sessions",
                "family": "Access Control"
            },
            "AC-14": {
                "title": "Permitted Actions Without Identification or Authentication",
                "description": "Identify permitted actions without authentication",
                "family": "Access Control"
            },
            "AC-17": {
                "title": "Remote Access",
                "description": "Establish and document remote access",
                "family": "Access Control"
            },
            "AC-18": {
                "title": "Wireless Access",
                "description": "Establish usage restrictions for wireless",
                "family": "Access Control"
            },
            "AC-19": {
                "title": "Access Control for Mobile Devices",
                "description": "Establish usage restrictions for mobile devices",
                "family": "Access Control"
            },
            "AC-20": {
                "title": "Use of External Information Systems",
                "description": "Establish terms for use of external systems",
                "family": "Access Control"
            },
            
            # Audit and Accountability Family
            "AU-2": {
                "title": "Audit Events",
                "description": "Determine events to be audited",
                "family": "Audit and Accountability"
            },
            "AU-3": {
                "title": "Content of Audit Records",
                "description": "Ensure audit records contain required information",
                "family": "Audit and Accountability"
            },
            "AU-4": {
                "title": "Audit Storage Capacity",
                "description": "Allocate audit record storage capacity",
                "family": "Audit and Accountability"
            },
            "AU-5": {
                "title": "Response to Audit Processing Failures",
                "description": "Alert and take action on audit failures",
                "family": "Audit and Accountability"
            },
            "AU-6": {
                "title": "Audit Review, Analysis, and Reporting",
                "description": "Review and analyze audit records",
                "family": "Audit and Accountability"
            },
            "AU-7": {
                "title": "Audit Reduction and Report Generation",
                "description": "Provide audit reduction and report generation",
                "family": "Audit and Accountability"
            },
            "AU-8": {
                "title": "Time Stamps",
                "description": "Use internal system clocks for time stamps",
                "family": "Audit and Accountability"
            },
            "AU-9": {
                "title": "Protection of Audit Information",
                "description": "Protect audit information and tools",
                "family": "Audit and Accountability"
            },
            "AU-10": {
                "title": "Non-repudiation",
                "description": "Provide irrefutable evidence of actions",
                "family": "Audit and Accountability"
            },
            "AU-11": {
                "title": "Audit Record Retention",
                "description": "Retain audit records per policy",
                "family": "Audit and Accountability"
            },
            "AU-12": {
                "title": "Audit Generation",
                "description": "Generate audit records for events",
                "family": "Audit and Accountability"
            },
            
            # Configuration Management Family
            "CM-2": {
                "title": "Baseline Configuration",
                "description": "Maintain baseline configurations",
                "family": "Configuration Management"
            },
            "CM-3": {
                "title": "Configuration Change Control",
                "description": "Implement configuration change control",
                "family": "Configuration Management"
            },
            "CM-4": {
                "title": "Security Impact Analysis",
                "description": "Analyze security impacts of changes",
                "family": "Configuration Management"
            },
            "CM-5": {
                "title": "Access Restrictions for Change",
                "description": "Define and enforce access restrictions",
                "family": "Configuration Management"
            },
            "CM-6": {
                "title": "Configuration Settings",
                "description": "Establish and document configuration settings",
                "family": "Configuration Management"
            },
            "CM-7": {
                "title": "Least Functionality",
                "description": "Configure system for essential capabilities only",
                "family": "Configuration Management"
            },
            "CM-8": {
                "title": "Information System Component Inventory",
                "description": "Maintain inventory of system components",
                "family": "Configuration Management"
            },
            "CM-9": {
                "title": "Configuration Management Plan",
                "description": "Develop and implement CM plan",
                "family": "Configuration Management"
            },
            "CM-10": {
                "title": "Software Usage Restrictions",
                "description": "Control software use and installation",
                "family": "Configuration Management"
            },
            "CM-11": {
                "title": "User-Installed Software",
                "description": "Govern user-installed software",
                "family": "Configuration Management"
            },
            
            # Contingency Planning Family
            "CP-2": {
                "title": "Contingency Plan",
                "description": "Develop contingency plan",
                "family": "Contingency Planning"
            },
            "CP-3": {
                "title": "Contingency Training",
                "description": "Provide contingency training",
                "family": "Contingency Planning"
            },
            "CP-4": {
                "title": "Contingency Plan Testing",
                "description": "Test contingency plan",
                "family": "Contingency Planning"
            },
            "CP-6": {
                "title": "Alternate Storage Site",
                "description": "Establish alternate storage site",
                "family": "Contingency Planning"
            },
            "CP-7": {
                "title": "Alternate Processing Site",
                "description": "Establish alternate processing site",
                "family": "Contingency Planning"
            },
            "CP-8": {
                "title": "Telecommunications Services",
                "description": "Establish alternate telecommunications",
                "family": "Contingency Planning"
            },
            "CP-9": {
                "title": "Information System Backup",
                "description": "Conduct system backups",
                "family": "Contingency Planning"
            },
            "CP-10": {
                "title": "Information System Recovery and Reconstitution",
                "description": "Provide for recovery and reconstitution",
                "family": "Contingency Planning"
            },
            
            # Identification and Authentication Family
            "IA-2": {
                "title": "Identification and Authentication (Organizational Users)",
                "description": "Uniquely identify and authenticate users",
                "family": "Identification and Authentication"
            },
            "IA-2(1)": {
                "title": "Multi-factor Authentication",
                "description": "Implement multi-factor authentication",
                "family": "Identification and Authentication"
            },
            "IA-2(2)": {
                "title": "Multi-factor Authentication for Network Access",
                "description": "MFA for network access to privileged accounts",
                "family": "Identification and Authentication"
            },
            "IA-2(8)": {
                "title": "Network Access - Replay Resistant",
                "description": "Implement replay-resistant authentication",
                "family": "Identification and Authentication"
            },
            "IA-3": {
                "title": "Device Identification and Authentication",
                "description": "Identify and authenticate devices",
                "family": "Identification and Authentication"
            },
            "IA-4": {
                "title": "Identifier Management",
                "description": "Manage information system identifiers",
                "family": "Identification and Authentication"
            },
            "IA-5": {
                "title": "Authenticator Management",
                "description": "Manage information system authenticators",
                "family": "Identification and Authentication"
            },
            "IA-5(1)": {
                "title": "Password-based Authentication",
                "description": "Enforce password complexity and change requirements",
                "family": "Identification and Authentication"
            },
            "IA-6": {
                "title": "Authenticator Feedback",
                "description": "Obscure feedback during authentication",
                "family": "Identification and Authentication"
            },
            "IA-7": {
                "title": "Cryptographic Module Authentication",
                "description": "Implement cryptographic module authentication",
                "family": "Identification and Authentication"
            },
            "IA-8": {
                "title": "Identification and Authentication (Non-organizational Users)",
                "description": "Identify and authenticate non-organizational users",
                "family": "Identification and Authentication"
            },
            "IA-9": {
                "title": "Service Identification and Authentication",
                "description": "Identify and authenticate services",
                "family": "Identification and Authentication"
            },
            "IA-11": {
                "title": "Re-authentication",
                "description": "Require re-authentication",
                "family": "Identification and Authentication"
            },
            
            # Incident Response Family
            "IR-1": {
                "title": "Incident Response Policy and Procedures",
                "description": "Develop incident response policy",
                "family": "Incident Response"
            },
            "IR-2": {
                "title": "Incident Response Training",
                "description": "Provide incident response training",
                "family": "Incident Response"
            },
            "IR-3": {
                "title": "Incident Response Testing",
                "description": "Test incident response capability",
                "family": "Incident Response"
            },
            "IR-4": {
                "title": "Incident Handling",
                "description": "Implement incident handling capability",
                "family": "Incident Response"
            },
            "IR-5": {
                "title": "Incident Monitoring",
                "description": "Track and document incidents",
                "family": "Incident Response"
            },
            "IR-6": {
                "title": "Incident Reporting",
                "description": "Require incident reporting",
                "family": "Incident Response"
            },
            "IR-7": {
                "title": "Incident Response Assistance",
                "description": "Provide incident response support",
                "family": "Incident Response"
            },
            "IR-8": {
                "title": "Incident Response Plan",
                "description": "Develop incident response plan",
                "family": "Incident Response"
            },
            
            # Media Protection Family
            "MP-2": {
                "title": "Media Access",
                "description": "Restrict access to media",
                "family": "Media Protection"
            },
            "MP-3": {
                "title": "Media Marking",
                "description": "Mark media with distribution limitations",
                "family": "Media Protection"
            },
            "MP-4": {
                "title": "Media Storage",
                "description": "Physically control and securely store media",
                "family": "Media Protection"
            },
            "MP-5": {
                "title": "Media Transport",
                "description": "Protect media during transport",
                "family": "Media Protection"
            },
            "MP-6": {
                "title": "Media Sanitization",
                "description": "Sanitize media before disposal",
                "family": "Media Protection"
            },
            "MP-7": {
                "title": "Media Use",
                "description": "Restrict use of media types",
                "family": "Media Protection"
            },
            
            # System and Communications Protection Family
            "SC-1": {
                "title": "System and Communications Protection Policy",
                "description": "Develop SC policy and procedures",
                "family": "System and Communications Protection"
            },
            "SC-2": {
                "title": "Application Partitioning",
                "description": "Separate user functionality from management",
                "family": "System and Communications Protection"
            },
            "SC-4": {
                "title": "Information in Shared Resources",
                "description": "Prevent unauthorized information transfer",
                "family": "System and Communications Protection"
            },
            "SC-5": {
                "title": "Denial of Service Protection",
                "description": "Protect against denial of service",
                "family": "System and Communications Protection"
            },
            "SC-7": {
                "title": "Boundary Protection",
                "description": "Monitor and control communications",
                "family": "System and Communications Protection"
            },
            "SC-8": {
                "title": "Transmission Confidentiality and Integrity",
                "description": "Protect transmitted information",
                "family": "System and Communications Protection"
            },
            "SC-10": {
                "title": "Network Disconnect",
                "description": "Terminate network connection at session end",
                "family": "System and Communications Protection"
            },
            "SC-12": {
                "title": "Cryptographic Key Establishment and Management",
                "description": "Establish and manage cryptographic keys",
                "family": "System and Communications Protection"
            },
            "SC-13": {
                "title": "Cryptographic Protection",
                "description": "Implement cryptographic protection",
                "family": "System and Communications Protection"
            },
            "SC-15": {
                "title": "Collaborative Computing Devices",
                "description": "Prohibit remote activation of collaborative devices",
                "family": "System and Communications Protection"
            },
            "SC-17": {
                "title": "Public Key Infrastructure Certificates",
                "description": "Issue PKI certificates",
                "family": "System and Communications Protection"
            },
            "SC-18": {
                "title": "Mobile Code",
                "description": "Define acceptable mobile code",
                "family": "System and Communications Protection"
            },
            "SC-20": {
                "title": "Secure Name/Address Resolution Service",
                "description": "Provide secure name/address resolution",
                "family": "System and Communications Protection"
            },
            "SC-21": {
                "title": "Secure Name/Address Resolution Service (Recursive)",
                "description": "Request secure name/address resolution",
                "family": "System and Communications Protection"
            },
            "SC-22": {
                "title": "Architecture and Provisioning for Name/Address Resolution",
                "description": "Ensure name/address resolution resilience",
                "family": "System and Communications Protection"
            },
            "SC-23": {
                "title": "Session Authenticity",
                "description": "Protect session authenticity",
                "family": "System and Communications Protection"
            },
            "SC-28": {
                "title": "Protection of Information at Rest",
                "description": "Protect information at rest",
                "family": "System and Communications Protection"
            },
            
            # System and Information Integrity Family
            "SI-1": {
                "title": "System and Information Integrity Policy",
                "description": "Develop SI policy and procedures",
                "family": "System and Information Integrity"
            },
            "SI-2": {
                "title": "Flaw Remediation",
                "description": "Identify and remediate flaws",
                "family": "System and Information Integrity"
            },
            "SI-3": {
                "title": "Malicious Code Protection",
                "description": "Protect against malicious code",
                "family": "System and Information Integrity"
            },
            "SI-4": {
                "title": "Information System Monitoring",
                "description": "Monitor information system",
                "family": "System and Information Integrity"
            },
            "SI-5": {
                "title": "Security Alerts, Advisories, and Directives",
                "description": "Receive security alerts",
                "family": "System and Information Integrity"
            },
            "SI-6": {
                "title": "Security Function Verification",
                "description": "Verify security functions",
                "family": "System and Information Integrity"
            },
            "SI-7": {
                "title": "Software, Firmware, and Information Integrity",
                "description": "Detect unauthorized changes",
                "family": "System and Information Integrity"
            },
            "SI-8": {
                "title": "Spam Protection",
                "description": "Protect against spam",
                "family": "System and Information Integrity"
            },
            "SI-10": {
                "title": "Information Input Validation",
                "description": "Check information for accuracy",
                "family": "System and Information Integrity"
            },
            "SI-11": {
                "title": "Error Handling",
                "description": "Generate error messages",
                "family": "System and Information Integrity"
            },
            "SI-12": {
                "title": "Information Handling and Retention",
                "description": "Handle and retain information",
                "family": "System and Information Integrity"
            },
            "SI-16": {
                "title": "Memory Protection",
                "description": "Protect memory from unauthorized execution",
                "family": "System and Information Integrity"
            }
        }
    
    async def assess(
        self,
        data: Dict[str, Any],
        workspace_info: Dict[str, Any]
    ) -> List[ControlResult]:
        """Assess compliance with NIST 800-53 controls."""
        results = []
        
        # Get applicable controls
        applicable_controls = self.filter_applicable_controls(workspace_info)
        
        # Assess each control
        for control_id, control_info in applicable_controls.items():
            # Call the appropriate assessment method
            method_name = f"_assess_{control_id.lower().replace('-', '_').replace('(', '_').replace(')', '')}"
            
            if hasattr(self, method_name):
                assessment_method = getattr(self, method_name)
                result = await assessment_method(data, workspace_info)
            else:
                # Generic assessment for controls without specific implementation
                result = await self._generic_assessment(control_id, control_info, data, workspace_info)
            
            results.append(result)
        
        return results
    
    async def _assess_ac_2(self, data: Dict[str, Any], workspace_info: Dict[str, Any]) -> ControlResult:
        """Assess AC-2: Account Management."""
        findings = []
        evidence = {}
        
        # Get user data
        users_data = data.get("users", {})
        all_users = users_data.get("users", [])
        
        # Check for inactive users
        inactive_users = [u for u in all_users if u.get("deleted", False)]
        if len(inactive_users) > 0:
            findings.append(self.create_finding(
                title="Inactive User Accounts Detected",
                description=f"Found {len(inactive_users)} deleted/inactive user accounts that may need cleanup",
                severity=Severity.MEDIUM,
                evidence={"inactive_count": len(inactive_users)},
                recommendations=[
                    "Review and remove unnecessary inactive accounts",
                    "Implement automated account cleanup procedures"
                ]
            ))
        
        # Check for service accounts
        bot_users = [u for u in all_users if u.get("is_bot", False)]
        evidence["bot_users"] = len(bot_users)
        evidence["total_users"] = len(all_users)
        
        # Check for guest users
        guest_users = [u for u in all_users if u.get("is_restricted", False) or u.get("is_ultra_restricted", False)]
        if len(guest_users) > 0:
            evidence["guest_users"] = len(guest_users)
        
        # Determine compliance
        status = ComplianceStatus.COMPLIANT if not findings else ComplianceStatus.PARTIALLY_COMPLIANT
        
        return self.create_control_result(
            control_id="AC-2",
            control_title="Account Management",
            status=status,
            findings=findings,
            evidence=evidence,
            implementation_guidance="Implement automated account lifecycle management"
        )
    
    async def _assess_ac_2_1(self, data: Dict[str, Any], workspace_info: Dict[str, Any]) -> ControlResult:
        """Assess AC-2(1): Automated System Account Management."""
        findings = []
        evidence = {}
        
        # Check for SCIM provisioning (automated account management)
        admin_data = data.get("admin", {})
        has_scim = admin_data.get("scim_enabled", False)
        
        evidence["scim_enabled"] = has_scim
        
        if not has_scim:
            findings.append(self.create_finding(
                title="No Automated Account Management",
                description="SCIM provisioning is not enabled for automated account management",
                severity=Severity.HIGH,
                evidence={"scim_enabled": False},
                recommendations=[
                    "Enable SCIM provisioning for automated account management",
                    "Integrate with enterprise identity management system"
                ]
            ))
        
        status = ComplianceStatus.COMPLIANT if has_scim else ComplianceStatus.NON_COMPLIANT
        
        return self.create_control_result(
            control_id="AC-2(1)",
            control_title="Account Management | Automated System Account Management",
            status=status,
            findings=findings,
            evidence=evidence,
            implementation_guidance="Configure SCIM with your identity provider"
        )
    
    async def _assess_ia_2(self, data: Dict[str, Any], workspace_info: Dict[str, Any]) -> ControlResult:
        """Assess IA-2: Identification and Authentication."""
        findings = []
        evidence = {}
        
        # Check 2FA enforcement
        users_data = data.get("users", {})
        team_2fa = workspace_info.get("workspace_2fa_required", False)
        
        evidence["workspace_2fa_required"] = team_2fa
        
        if not team_2fa:
            # Check how many users have 2FA enabled
            all_users = users_data.get("users", [])
            users_with_2fa = [u for u in all_users if u.get("has_2fa", False)]
            
            percentage_with_2fa = (len(users_with_2fa) / len(all_users) * 100) if all_users else 0
            evidence["percentage_with_2fa"] = percentage_with_2fa
            
            findings.append(self.create_finding(
                title="Two-Factor Authentication Not Enforced",
                description=f"2FA is not enforced at workspace level. Only {percentage_with_2fa:.1f}% of users have 2FA enabled",
                severity=Severity.CRITICAL,
                evidence={
                    "workspace_2fa_required": False,
                    "percentage_with_2fa": percentage_with_2fa
                },
                recommendations=[
                    "Enable mandatory 2FA for all workspace users",
                    "Configure SSO with MFA requirements"
                ]
            ))
        
        status = ComplianceStatus.COMPLIANT if team_2fa else ComplianceStatus.NON_COMPLIANT
        
        return self.create_control_result(
            control_id="IA-2",
            control_title="Identification and Authentication (Organizational Users)",
            status=status,
            findings=findings,
            evidence=evidence,
            implementation_guidance="Enable workspace-wide 2FA enforcement in admin settings"
        )
    
    async def _assess_au_2(self, data: Dict[str, Any], workspace_info: Dict[str, Any]) -> ControlResult:
        """Assess AU-2: Audit Events."""
        findings = []
        evidence = {}
        
        # Check if audit logs are available
        audit_logs = data.get("audit_logs", {})
        has_audit_logs = bool(audit_logs.get("logs", []))
        
        evidence["has_audit_logs"] = has_audit_logs
        evidence["is_enterprise"] = workspace_info.get("is_enterprise", False)
        
        if not has_audit_logs and workspace_info.get("is_enterprise", False):
            findings.append(self.create_finding(
                title="Audit Logs Not Accessible",
                description="Unable to access audit logs despite Enterprise Grid subscription",
                severity=Severity.HIGH,
                evidence={"accessible": False},
                recommendations=[
                    "Enable audit log API access",
                    "Configure proper permissions for audit log retrieval"
                ]
            ))
        elif not workspace_info.get("is_enterprise", False):
            findings.append(self.create_finding(
                title="Limited Audit Capabilities",
                description="Full audit logs require Enterprise Grid subscription",
                severity=Severity.MEDIUM,
                evidence={"is_enterprise": False},
                recommendations=[
                    "Upgrade to Enterprise Grid for comprehensive audit logs",
                    "Implement compensating controls for audit trail"
                ]
            ))
        
        status = ComplianceStatus.COMPLIANT if has_audit_logs else ComplianceStatus.PARTIALLY_COMPLIANT
        
        return self.create_control_result(
            control_id="AU-2",
            control_title="Audit Events",
            status=status,
            findings=findings,
            evidence=evidence,
            implementation_guidance="Configure comprehensive audit event logging"
        )
    
    async def _assess_sc_8(self, data: Dict[str, Any], workspace_info: Dict[str, Any]) -> ControlResult:
        """Assess SC-8: Transmission Confidentiality and Integrity."""
        findings = []
        evidence = {}
        
        # Slack enforces TLS for all communications
        evidence["tls_enforced"] = True
        evidence["minimum_tls_version"] = "1.2"
        
        # Check for DLP policies
        admin_data = data.get("admin", {})
        has_dlp = admin_data.get("dlp_enabled", False)
        
        if not has_dlp:
            findings.append(self.create_finding(
                title="No Data Loss Prevention",
                description="DLP policies are not configured to protect data in transit",
                severity=Severity.MEDIUM,
                evidence={"dlp_enabled": False},
                recommendations=[
                    "Enable Slack's DLP features",
                    "Configure content policies for sensitive data"
                ]
            ))
        
        status = ComplianceStatus.COMPLIANT if not findings else ComplianceStatus.PARTIALLY_COMPLIANT
        
        return self.create_control_result(
            control_id="SC-8",
            control_title="Transmission Confidentiality and Integrity",
            status=status,
            findings=findings,
            evidence=evidence,
            implementation_guidance="Configure DLP policies for enhanced protection"
        )
    
    async def _generic_assessment(
        self,
        control_id: str,
        control_info: Dict[str, Any],
        data: Dict[str, Any],
        workspace_info: Dict[str, Any]
    ) -> ControlResult:
        """Generic assessment for controls without specific implementation."""
        # This is a placeholder for controls that need manual verification
        return self.create_control_result(
            control_id=control_id,
            control_title=control_info["title"],
            status=ComplianceStatus.NOT_ASSESSED,
            findings=[],
            evidence={"assessment": "Manual verification required"},
            implementation_guidance=f"Review {control_info['family']} requirements for this control"
        )