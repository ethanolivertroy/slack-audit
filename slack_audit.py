#!/usr/bin/env python3
"""
Slack FedRAMP Compliance Audit Tool

This script helps organizations audit their Slack workspace configuration
for FedRAMP compliance and gather evidence for NIST 800-53 controls.
"""

import os
import sys
import json
import argparse
import datetime
import requests
from typing import Dict, List, Any, Optional

class SlackAudit:
    """Main class for auditing Slack workspace for FedRAMP compliance."""
    
    def __init__(self, token: str, output_dir: str = "./audit_results"):
        """
        Initialize the SlackAudit tool.
        
        Args:
            token: Slack API token with admin privileges
            output_dir: Directory to store audit results
        """
        self.token = token
        self.output_dir = output_dir
        self.base_url = "https://api.slack.com/api"
        self.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        self.audit_results = {
            "metadata": {
                "audit_date": datetime.datetime.now().isoformat(),
                "tool_version": "1.0.0",
            },
            "compliance": {},
            "configurations": {},
            "recommendations": []
        }
        
        # Create output directory if it doesn't exist
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    def run_audit(self) -> Dict[str, Any]:
        """
        Run the complete audit process.
        
        Returns:
            Dict containing audit results
        """
        print("Starting Slack FedRAMP compliance audit...")
        
        # Check if token is valid
        self._validate_token()
        
        # Audit enterprise/team settings
        self.audit_results["configurations"]["enterprise"] = self._audit_enterprise_settings()
        
        # Audit admin settings
        self.audit_results["configurations"]["admin"] = self._audit_admin_settings()
        
        # Audit workspace settings
        self.audit_results["configurations"]["workspace"] = self._audit_workspace_settings()
        
        # Audit user settings and 2FA enforcement
        self.audit_results["configurations"]["users"] = self._audit_user_settings()
        
        # Audit app integrations
        self.audit_results["configurations"]["apps"] = self._audit_app_integrations()
        
        # Audit retention policies
        self.audit_results["configurations"]["retention"] = self._audit_retention_policies()
        
        # Analyze compliance with NIST 800-53 controls
        self._analyze_compliance()
        
        # Save results
        self._save_results()
        
        print(f"Audit completed. Results saved to {self.output_dir}")
        return self.audit_results
    
    def _validate_token(self) -> None:
        """Validate that the provided Slack token is valid and has required permissions."""
        response = self._make_api_request("auth.test")
        
        if not response.get("ok"):
            error_msg = response.get("error", "Unknown error")
            print(f"Error: Invalid token or insufficient permissions. API response: {error_msg}")
            sys.exit(1)
        
        print(f"Successfully authenticated as {response.get('user')} in workspace {response.get('team')}")
    
    def _make_api_request(self, endpoint: str, params: Dict = None) -> Dict:
        """
        Make a request to the Slack API.
        
        Args:
            endpoint: Slack API endpoint (without the base URL)
            params: Additional parameters to include in the request
            
        Returns:
            API response as a dictionary
        """
        if params is None:
            params = {}
        
        url = f"{self.base_url}/{endpoint}"
        try:
            response = requests.get(url, headers=self.headers, params=params)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            print(f"Error making API request to {endpoint}: {e}")
            return {"ok": False, "error": str(e)}
    
    def _audit_enterprise_settings(self) -> Dict[str, Any]:
        """
        Audit enterprise-level settings.
        
        Returns:
            Dict containing enterprise settings audit results
        """
        print("Auditing enterprise settings...")
        
        # Check organization-wide settings
        enterprise_info = self._make_api_request("admin.enterprise.info")
        
        if not enterprise_info.get("ok"):
            print("Could not retrieve enterprise information. This may not be an Enterprise Grid workspace.")
            return {"is_enterprise_grid": False}
        
        # Extract relevant enterprise settings
        settings = {
            "is_enterprise_grid": True,
            "enterprise_id": enterprise_info.get("enterprise", {}).get("id"),
            "enterprise_name": enterprise_info.get("enterprise", {}).get("name"),
            "domains": self._get_enterprise_domains(),
            "sso_settings": self._get_enterprise_sso_settings(),
            "session_settings": self._get_enterprise_session_settings()
        }
        
        return settings
    
    def _get_enterprise_domains(self) -> List[Dict[str, Any]]:
        """Get enterprise domain configurations."""
        domains_response = self._make_api_request("admin.enterprise.domains.list")
        
        if not domains_response.get("ok"):
            return []
        
        return domains_response.get("domains", [])
    
    def _get_enterprise_sso_settings(self) -> Dict[str, Any]:
        """Get enterprise SSO configurations."""
        sso_response = self._make_api_request("admin.team.settings.getInfo")
        
        sso_settings = {
            "sso_enabled": False,
            "sso_provider": None,
            "session_duration": None
        }
        
        if sso_response.get("ok"):
            team_info = sso_response.get("team", {})
            sso_settings["sso_enabled"] = team_info.get("sso_enabled", False)
            sso_settings["sso_provider"] = team_info.get("sso_provider", "unknown")
            sso_settings["session_duration"] = team_info.get("session_duration", 0)
        
        return sso_settings
    
    def _get_enterprise_session_settings(self) -> Dict[str, Any]:
        """Get enterprise session management configurations."""
        session_response = self._make_api_request("admin.team.settings.getInfo")
        
        session_settings = {
            "session_timeout_enabled": False,
            "session_duration_hours": 0,
            "mobile_session_duration_hours": 0
        }
        
        if session_response.get("ok"):
            team_info = session_response.get("team", {})
            session_settings["session_timeout_enabled"] = team_info.get("session_timeout_enabled", False)
            session_settings["session_duration_hours"] = team_info.get("session_duration", 0) / 3600
            session_settings["mobile_session_duration_hours"] = team_info.get("mobile_session_duration", 0) / 3600
        
        return session_settings
    
    def _audit_admin_settings(self) -> Dict[str, Any]:
        """
        Audit admin-level settings.
        
        Returns:
            Dict containing admin settings audit results
        """
        print("Auditing admin settings...")
        
        # Get team info
        team_info = self._make_api_request("admin.team.settings.info")
        
        # Extract relevant admin settings
        settings = {
            "who_can_create_channels": team_info.get("team", {}).get("who_can_create_channels"),
            "who_can_archive_channels": team_info.get("team", {}).get("who_can_archive_channels"),
            "who_can_create_shared_channels": team_info.get("team", {}).get("who_can_create_shared_channels"),
            "who_can_create_private_channels": team_info.get("team", {}).get("who_can_create_private_channels"),
            "who_can_delete_messages": team_info.get("team", {}).get("who_can_delete_messages"),
            "who_can_edit_messages": team_info.get("team", {}).get("who_can_edit_messages"),
            "who_can_invite_to_workspace": team_info.get("team", {}).get("who_can_invite"),
            "who_can_install_apps": team_info.get("team", {}).get("who_can_install_apps"),
            "app_directory_restrictions": self._get_app_directory_restrictions()
        }
        
        return settings
    
    def _get_app_directory_restrictions(self) -> Dict[str, Any]:
        """Get app directory restrictions."""
        app_restrictions = self._make_api_request("admin.apps.restricted.list")
        
        return {
            "app_directory_enabled": app_restrictions.get("ok", False),
            "restricted_apps_count": len(app_restrictions.get("restricted_apps", [])),
            "allowed_apps_count": len(app_restrictions.get("allowed_apps", []))
        }
    
    def _audit_workspace_settings(self) -> Dict[str, Any]:
        """
        Audit workspace-level settings.
        
        Returns:
            Dict containing workspace settings audit results
        """
        print("Auditing workspace settings...")
        
        # Get workspace info
        team_info = self._make_api_request("team.info")
        
        # Get workspace access logs (limited to 100 most recent)
        access_logs = self._make_api_request("team.accessLogs", {"count": 100})
        
        settings = {
            "team_id": team_info.get("team", {}).get("id"),
            "team_name": team_info.get("team", {}).get("name"),
            "team_domain": team_info.get("team", {}).get("domain"),
            "email_domain": team_info.get("team", {}).get("email_domain"),
            "workspace_creation_date": team_info.get("team", {}).get("created"),
            "has_access_logs": access_logs.get("ok", False),
            "access_logs_count": len(access_logs.get("logins", [])) if access_logs.get("ok") else 0,
            "default_channels": self._get_default_channels()
        }
        
        return settings
    
    def _get_default_channels(self) -> List[Dict[str, Any]]:
        """Get default channels in the workspace."""
        channels_response = self._make_api_request("conversations.list", {"exclude_archived": True, "types": "public_channel"})
        
        if not channels_response.get("ok"):
            return []
        
        default_channels = []
        for channel in channels_response.get("channels", []):
            if channel.get("is_general"):
                default_channels.append({
                    "id": channel.get("id"),
                    "name": channel.get("name"),
                    "is_general": channel.get("is_general"),
                    "created": channel.get("created")
                })
        
        return default_channels
    
    def _audit_user_settings(self) -> Dict[str, Any]:
        """
        Audit user-related settings and 2FA enforcement.
        
        Returns:
            Dict containing user settings audit results
        """
        print("Auditing user settings and 2FA enforcement...")
        
        # Get user list (limited to 1000 users)
        users_response = self._make_api_request("users.list", {"limit": 1000})
        
        if not users_response.get("ok"):
            return {"error": users_response.get("error")}
        
        users = users_response.get("members", [])
        
        # Check 2FA enforcement
        team_info = self._make_api_request("team.info")
        two_factor_enforcement = team_info.get("team", {}).get("two_factor_auth_required", False)
        
        # Analyze user settings
        total_users = len(users)
        admin_count = sum(1 for user in users if user.get("is_admin", False))
        owner_count = sum(1 for user in users if user.get("is_owner", False))
        bot_count = sum(1 for user in users if user.get("is_bot", False))
        two_factor_enabled_count = sum(1 for user in users if user.get("has_2fa", False))
        
        settings = {
            "total_users": total_users,
            "admin_count": admin_count,
            "owner_count": owner_count,
            "bot_count": bot_count,
            "two_factor_auth_required": two_factor_enforcement,
            "two_factor_enabled_count": two_factor_enabled_count,
            "two_factor_enabled_percentage": (two_factor_enabled_count / (total_users - bot_count) * 100) if (total_users - bot_count) > 0 else 0
        }
        
        return settings
    
    def _audit_app_integrations(self) -> Dict[str, Any]:
        """
        Audit app integrations.
        
        Returns:
            Dict containing app integration audit results
        """
        print("Auditing app integrations...")
        
        # Get installed apps
        apps_response = self._make_api_request("apps.list")
        
        if not apps_response.get("ok"):
            return {"error": apps_response.get("error")}
        
        apps = apps_response.get("apps", [])
        
        # Categorize apps
        app_categories = {}
        for app in apps:
            category = app.get("category", "Other")
            if category not in app_categories:
                app_categories[category] = 0
            app_categories[category] += 1
        
        # Check for potentially risky apps
        risky_apps = []
        for app in apps:
            if any(scope in app.get("scopes", []) for scope in [
                "channels:history", "channels:read", "chat:write", "files:read", 
                "files:write", "im:history", "im:read", "im:write", "users:read", 
                "users:write", "admin"
            ]):
                risky_apps.append({
                    "id": app.get("id"),
                    "name": app.get("name"),
                    "scopes": app.get("scopes")
                })
        
        settings = {
            "total_apps": len(apps),
            "app_categories": app_categories,
            "risky_apps_count": len(risky_apps),
            "risky_apps": risky_apps
        }
        
        return settings
    
    def _audit_retention_policies(self) -> Dict[str, Any]:
        """
        Audit retention policies.
        
        Returns:
            Dict containing retention policy audit results
        """
        print("Auditing retention policies...")
        
        # Get team retention policy
        retention_response = self._make_api_request("admin.conversations.restrictAccess.getInfo")
        
        settings = {
            "has_retention_policy": False,
            "retention_duration_days": None,
            "default_policy": "unknown"
        }
        
        if retention_response.get("ok"):
            policy = retention_response.get("policy", {})
            settings["has_retention_policy"] = True
            settings["retention_duration_days"] = policy.get("duration_days")
            settings["default_policy"] = policy.get("type", "unknown")
        
        return settings
    
    def _analyze_compliance(self) -> None:
        """Analyze compliance with NIST 800-53 controls."""
        print("Analyzing compliance with NIST 800-53 controls...")
        
        compliance = {
            "AC-2": self._check_ac2_compliance(),
            "AC-3": self._check_ac3_compliance(),
            "AC-7": self._check_ac7_compliance(),
            "AC-17": self._check_ac17_compliance(),
            "AU-2": self._check_au2_compliance(),
            "IA-2": self._check_ia2_compliance(),
            "IA-5": self._check_ia5_compliance(),
            "SC-8": self._check_sc8_compliance(),
            "SC-12": self._check_sc12_compliance(),
            "SI-7": self._check_si7_compliance()
        }
        
        self.audit_results["compliance"] = compliance
        
        # Generate recommendations based on compliance findings
        self._generate_recommendations()
    
    def _check_ac2_compliance(self) -> Dict[str, Any]:
        """Check compliance with AC-2 (Account Management)."""
        admin_settings = self.audit_results["configurations"]["admin"]
        user_settings = self.audit_results["configurations"]["users"]
        
        # Check who can invite users
        invite_restriction = admin_settings.get("who_can_invite_to_workspace") == "ADMIN_ONLY"
        
        # Check if there's a way to track account creation/deletion
        has_access_logs = self.audit_results["configurations"]["workspace"].get("has_access_logs", False)
        
        return {
            "control": "AC-2",
            "title": "Account Management",
            "compliant": invite_restriction and has_access_logs,
            "findings": {
                "invite_restriction": invite_restriction,
                "has_access_logs": has_access_logs,
                "admin_count": user_settings.get("admin_count", 0),
                "total_users": user_settings.get("total_users", 0)
            },
            "recommendations": [
                "Restrict user invitations to admins only" if not invite_restriction else None,
                "Enable access logs to track account creation and deletion" if not has_access_logs else None
            ]
        }
    
    def _check_ac3_compliance(self) -> Dict[str, Any]:
        """Check compliance with AC-3 (Access Enforcement)."""
        admin_settings = self.audit_results["configurations"]["admin"]
        
        # Check channel creation restrictions
        channel_creation_restricted = admin_settings.get("who_can_create_channels") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        private_channel_creation_restricted = admin_settings.get("who_can_create_private_channels") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        
        # Check message editing/deletion restrictions
        message_deletion_restricted = admin_settings.get("who_can_delete_messages") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        message_editing_restricted = admin_settings.get("who_can_edit_messages") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        
        is_compliant = (channel_creation_restricted and 
                        private_channel_creation_restricted and 
                        message_deletion_restricted and 
                        message_editing_restricted)
        
        return {
            "control": "AC-3",
            "title": "Access Enforcement",
            "compliant": is_compliant,
            "findings": {
                "channel_creation_restricted": channel_creation_restricted,
                "private_channel_creation_restricted": private_channel_creation_restricted,
                "message_deletion_restricted": message_deletion_restricted,
                "message_editing_restricted": message_editing_restricted
            },
            "recommendations": [
                "Restrict public channel creation to admins only" if not channel_creation_restricted else None,
                "Restrict private channel creation to admins only" if not private_channel_creation_restricted else None,
                "Restrict message deletion to admins only" if not message_deletion_restricted else None,
                "Restrict message editing to admins only" if not message_editing_restricted else None
            ]
        }
    
    def _check_ac7_compliance(self) -> Dict[str, Any]:
        """Check compliance with AC-7 (Unsuccessful Login Attempts)."""
        # Slack doesn't provide API access to this setting, but it does implement account lockout
        return {
            "control": "AC-7",
            "title": "Unsuccessful Login Attempts",
            "compliant": True,  # Slack handles this automatically
            "findings": {
                "note": "Slack automatically implements account lockout after multiple failed login attempts"
            },
            "recommendations": []
        }
    
    def _check_ac17_compliance(self) -> Dict[str, Any]:
        """Check compliance with AC-17 (Remote Access)."""
        enterprise_settings = self.audit_results["configurations"]["enterprise"]
        
        # Check if SSO is enabled
        sso_enabled = enterprise_settings.get("sso_settings", {}).get("sso_enabled", False)
        
        # Check session timeout settings
        session_timeout_enabled = enterprise_settings.get("session_settings", {}).get("session_timeout_enabled", False)
        session_duration_compliant = enterprise_settings.get("session_settings", {}).get("session_duration_hours", 24) <= 12
        
        is_compliant = sso_enabled and session_timeout_enabled and session_duration_compliant
        
        return {
            "control": "AC-17",
            "title": "Remote Access",
            "compliant": is_compliant,
            "findings": {
                "sso_enabled": sso_enabled,
                "session_timeout_enabled": session_timeout_enabled,
                "session_duration_hours": enterprise_settings.get("session_settings", {}).get("session_duration_hours", 24)
            },
            "recommendations": [
                "Enable SSO integration" if not sso_enabled else None,
                "Enable session timeout" if not session_timeout_enabled else None,
                "Reduce session duration to 12 hours or less" if not session_duration_compliant else None
            ]
        }
    
    def _check_au2_compliance(self) -> Dict[str, Any]:
        """Check compliance with AU-2 (Audit Events)."""
        workspace_settings = self.audit_results["configurations"]["workspace"]
        
        # Check if access logs are enabled
        has_access_logs = workspace_settings.get("has_access_logs", False)
        
        return {
            "control": "AU-2",
            "title": "Audit Events",
            "compliant": has_access_logs,
            "findings": {
                "has_access_logs": has_access_logs,
                "access_logs_count": workspace_settings.get("access_logs_count", 0)
            },
            "recommendations": [
                "Enable access logs" if not has_access_logs else None,
                "Consider using Slack Enterprise Grid for enhanced audit capabilities" if not workspace_settings.get("is_enterprise_grid", False) else None
            ]
        }
    
    def _check_ia2_compliance(self) -> Dict[str, Any]:
        """Check compliance with IA-2 (Identification and Authentication)."""
        user_settings = self.audit_results["configurations"]["users"]
        enterprise_settings = self.audit_results["configurations"]["enterprise"]
        
        # Check 2FA enforcement
        two_factor_required = user_settings.get("two_factor_auth_required", False)
        
        # Check SSO configuration
        sso_enabled = enterprise_settings.get("sso_settings", {}).get("sso_enabled", False)
        
        is_compliant = two_factor_required and sso_enabled
        
        return {
            "control": "IA-2",
            "title": "Identification and Authentication",
            "compliant": is_compliant,
            "findings": {
                "two_factor_auth_required": two_factor_required,
                "two_factor_enabled_percentage": user_settings.get("two_factor_enabled_percentage", 0),
                "sso_enabled": sso_enabled,
                "sso_provider": enterprise_settings.get("sso_settings", {}).get("sso_provider", None)
            },
            "recommendations": [
                "Enforce two-factor authentication for all users" if not two_factor_required else None,
                "Implement SSO integration" if not sso_enabled else None
            ]
        }
    
    def _check_ia5_compliance(self) -> Dict[str, Any]:
        """Check compliance with IA-5 (Authenticator Management)."""
        user_settings = self.audit_results["configurations"]["users"]
        enterprise_settings = self.audit_results["configurations"]["enterprise"]
        
        # Check 2FA enforcement
        two_factor_required = user_settings.get("two_factor_auth_required", False)
        
        # Check SSO configuration
        sso_enabled = enterprise_settings.get("sso_settings", {}).get("sso_enabled", False)
        
        is_compliant = two_factor_required and sso_enabled
        
        return {
            "control": "IA-5",
            "title": "Authenticator Management",
            "compliant": is_compliant,
            "findings": {
                "two_factor_auth_required": two_factor_required,
                "sso_enabled": sso_enabled
            },
            "recommendations": [
                "Enforce two-factor authentication for all users" if not two_factor_required else None,
                "Implement SSO integration to leverage organizational password policies" if not sso_enabled else None
            ]
        }
    
    def _check_sc8_compliance(self) -> Dict[str, Any]:
        """Check compliance with SC-8 (Transmission Confidentiality and Integrity)."""
        # Slack uses TLS for all communications by default
        return {
            "control": "SC-8",
            "title": "Transmission Confidentiality and Integrity",
            "compliant": True,  # Slack handles this automatically
            "findings": {
                "note": "Slack automatically uses TLS for all communications"
            },
            "recommendations": []
        }
    
    def _check_sc12_compliance(self) -> Dict[str, Any]:
        """Check compliance with SC-12 (Cryptographic Key Establishment and Management)."""
        # Slack handles key management internally
        return {
            "control": "SC-12",
            "title": "Cryptographic Key Establishment and Management",
            "compliant": True,  # Slack handles this automatically
            "findings": {
                "note": "Slack automatically handles cryptographic key management"
            },
            "recommendations": []
        }
    
    def _check_si7_compliance(self) -> Dict[str, Any]:
        """Check compliance with SI-7 (Software, Firmware, and Information Integrity)."""
        admin_settings = self.audit_results["configurations"]["admin"]
        
        # Check app installation restrictions
        app_installation_restricted = admin_settings.get("who_can_install_apps") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        app_directory_restricted = admin_settings.get("app_directory_restrictions", {}).get("app_directory_enabled", False)
        
        is_compliant = app_installation_restricted and app_directory_restricted
        
        return {
            "control": "SI-7",
            "title": "Software, Firmware, and Information Integrity",
            "compliant": is_compliant,
            "findings": {
                "app_installation_restricted": app_installation_restricted,
                "app_directory_restricted": app_directory_restricted,
                "risky_apps_count": self.audit_results["configurations"]["apps"].get("risky_apps_count", 0)
            },
            "recommendations": [
                "Restrict app installation to admins only" if not app_installation_restricted else None,
                "Enable app directory restrictions" if not app_directory_restricted else None,
                "Review installed apps with sensitive permissions" if self.audit_results["configurations"]["apps"].get("risky_apps_count", 0) > 0 else None
            ]
        }
    
    def _generate_recommendations(self) -> None:
        """Generate overall recommendations based on compliance findings."""
        recommendations = []
        
        # Collect all recommendations from compliance checks
        for control, check in self.audit_results["compliance"].items():
            for recommendation in check.get("recommendations", []):
                if recommendation:
                    recommendations.append(f"{control}: {recommendation}")
        
        self.audit_results["recommendations"] = recommendations
    
    def _save_results(self) -> None:
        """Save audit results to file."""
        filename = f"{self.output_dir}/slack_audit_{self.timestamp}.json"
        with open(filename, "w") as f:
            json.dump(self.audit_results, f, indent=2)
        
        print(f"Full audit results saved to: {filename}")
        
        # Generate a summary report
        self._generate_summary_report()
    
    def _generate_summary_report(self) -> None:
        """Generate a human-readable summary report."""
        filename = f"{self.output_dir}/slack_audit_summary_{self.timestamp}.md"
        
        with open(filename, "w") as f:
            f.write(f"# Slack FedRAMP Compliance Audit Summary\n\n")
            f.write(f"**Audit Date:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            # Workspace information
            workspace = self.audit_results["configurations"]["workspace"]
            f.write(f"## Workspace Information\n\n")
            f.write(f"- **Workspace Name:** {workspace.get('team_name')}\n")
            f.write(f"- **Workspace Domain:** {workspace.get('team_domain')}\n")
            f.write(f"- **Total Users:** {self.audit_results['configurations']['users'].get('total_users')}\n\n")
            
            # Compliance summary
            compliant_count = sum(1 for check in self.audit_results["compliance"].values() if check.get("compliant"))
            total_checks = len(self.audit_results["compliance"])
            compliance_percentage = (compliant_count / total_checks) * 100 if total_checks > 0 else 0
            
            f.write(f"## Compliance Summary\n\n")
            f.write(f"- **Compliance Score:** {compliance_percentage:.1f}% ({compliant_count}/{total_checks} controls)\n\n")
            
            # Control compliance details
            f.write(f"## Control Compliance Details\n\n")
            
            for control, check in self.audit_results["compliance"].items():
                status = "✅" if check.get("compliant") else "❌"
                f.write(f"### {status} {control}: {check.get('title')}\n\n")
                
                if not check.get("compliant"):
                    f.write("**Findings:**\n\n")
                    for key, value in check.get("findings", {}).items():
                        f.write(f"- {key.replace('_', ' ').title()}: {value}\n")
                    
                    f.write("\n**Recommendations:**\n\n")
                    for recommendation in check.get("recommendations", []):
                        if recommendation:
                            f.write(f"- {recommendation}\n")
                    f.write("\n")
            
            # Overall recommendations
            f.write(f"## Overall Recommendations\n\n")
            for recommendation in self.audit_results["recommendations"]:
                f.write(f"- {recommendation}\n")
        
        print(f"Summary report saved to: {filename}")


def main():
    """Main function to run the Slack FedRAMP compliance audit tool."""
    parser = argparse.ArgumentParser(description="Slack FedRAMP Compliance Audit Tool")
    parser.add_argument("--token", required=True, help="Slack API token with admin privileges")
    parser.add_argument("--output-dir", default="./audit_results", help="Directory to store audit results")
    
    args = parser.parse_args()
    
    # Run the audit
    auditor = SlackAudit(token=args.token, output_dir=args.output_dir)
    auditor.run_audit()


if __name__ == "__main__":
    main()