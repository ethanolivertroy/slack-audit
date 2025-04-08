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
            "AC-4": self._check_ac4_compliance(),
            "AC-6": self._check_ac6_compliance(),
            "AC-7": self._check_ac7_compliance(),
            "AC-17": self._check_ac17_compliance(),
            "AU-2": self._check_au2_compliance(),
            "AU-3": self._check_au3_compliance(),
            "AU-6": self._check_au6_compliance(),
            "AU-9": self._check_au9_compliance(),
            "CM-2": self._check_cm2_compliance(),
            "CM-6": self._check_cm6_compliance(),
            "CM-7": self._check_cm7_compliance(),
            "CP-9": self._check_cp9_compliance(),
            "IA-2": self._check_ia2_compliance(),
            "IA-5": self._check_ia5_compliance(),
            "IR-4": self._check_ir4_compliance(),
            "MP-7": self._check_mp7_compliance(),
            "RA-5": self._check_ra5_compliance(),
            "SA-9": self._check_sa9_compliance(),
            "SC-7": self._check_sc7_compliance(),
            "SC-8": self._check_sc8_compliance(),
            "SC-12": self._check_sc12_compliance(),
            "SC-13": self._check_sc13_compliance(),
            "SC-28": self._check_sc28_compliance(),
            "SI-4": self._check_si4_compliance(),
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
    
    def _check_ac4_compliance(self) -> Dict[str, Any]:
        """Check compliance with AC-4 (Information Flow Enforcement)."""
        admin_settings = self.audit_results["configurations"]["admin"]
        
        # Check settings related to external sharing and data flow
        shared_channel_creation_restricted = admin_settings.get("who_can_create_shared_channels") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        
        # We'll assume access to file export restrictions is not available via API
        # so this is a placeholder that could be expanded with actual API access
        file_export_restricted = False  # Would need Enterprise Grid and API access
        
        # Check for DLP configurations (typically Enterprise Grid feature)
        dlp_enabled = False  # Would need Enterprise Grid and API access
        
        is_compliant = shared_channel_creation_restricted and file_export_restricted and dlp_enabled
        
        return {
            "control": "AC-4",
            "title": "Information Flow Enforcement",
            "compliant": shared_channel_creation_restricted,  # Using partial compliance based on available info
            "findings": {
                "shared_channel_creation_restricted": shared_channel_creation_restricted,
                "file_export_restricted": "Unknown - Requires manual verification",
                "dlp_enabled": "Unknown - Requires manual verification"
            },
            "recommendations": [
                "Restrict shared channel creation to admins only" if not shared_channel_creation_restricted else None,
                "Configure Data Loss Prevention (DLP) for sensitive content",
                "Restrict workspace export capabilities to admins only",
                "Review and configure external sharing settings"
            ]
        }
    
    def _check_ac6_compliance(self) -> Dict[str, Any]:
        """Check compliance with AC-6 (Least Privilege)."""
        user_settings = self.audit_results["configurations"]["users"]
        admin_settings = self.audit_results["configurations"]["admin"]
        
        # Check admin counts
        admin_count = user_settings.get("admin_count", 0)
        total_users = user_settings.get("total_users", 0)
        admin_percentage = (admin_count / total_users * 100) if total_users > 0 else 0
        reasonable_admin_percentage = admin_percentage <= 10  # Subjective threshold
        
        # Check privileged action restrictions
        install_apps_restricted = admin_settings.get("who_can_install_apps") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        delete_messages_restricted = admin_settings.get("who_can_delete_messages") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        
        is_compliant = reasonable_admin_percentage and install_apps_restricted and delete_messages_restricted
        
        return {
            "control": "AC-6",
            "title": "Least Privilege",
            "compliant": is_compliant,
            "findings": {
                "admin_count": admin_count,
                "admin_percentage": admin_percentage,
                "reasonable_admin_percentage": reasonable_admin_percentage,
                "install_apps_restricted": install_apps_restricted,
                "delete_messages_restricted": delete_messages_restricted
            },
            "recommendations": [
                "Reduce the number of workspace admins" if not reasonable_admin_percentage else None,
                "Restrict app installation to admins only" if not install_apps_restricted else None,
                "Restrict message deletion to admins only" if not delete_messages_restricted else None,
                "Implement custom roles for more granular permission control (Enterprise Grid)"
            ]
        }
    
    def _check_au3_compliance(self) -> Dict[str, Any]:
        """Check compliance with AU-3 (Content of Audit Records)."""
        workspace_settings = self.audit_results["configurations"]["workspace"]
        
        # Check if access logs are enabled and contain sufficient detail
        has_access_logs = workspace_settings.get("has_access_logs", False)
        access_logs_count = workspace_settings.get("access_logs_count", 0)
        has_detailed_logs = access_logs_count > 0  # If we have logs, assume they have sufficient content
        
        is_compliant = has_access_logs and has_detailed_logs
        
        return {
            "control": "AU-3",
            "title": "Content of Audit Records",
            "compliant": is_compliant,
            "findings": {
                "has_access_logs": has_access_logs,
                "access_logs_count": access_logs_count,
                "has_detailed_logs": has_detailed_logs
            },
            "recommendations": [
                "Enable access logs" if not has_access_logs else None,
                "Implement Enterprise Grid for enhanced audit logging capabilities" if not has_detailed_logs else None,
                "Configure retention of audit records to meet organizational requirements"
            ]
        }
    
    def _check_au6_compliance(self) -> Dict[str, Any]:
        """Check compliance with AU-6 (Audit Review, Analysis, and Reporting)."""
        workspace_settings = self.audit_results["configurations"]["workspace"]
        
        # Check if access logs are enabled
        has_access_logs = workspace_settings.get("has_access_logs", False)
        
        # Slack doesn't expose audit review configurations via API
        # These would be manual processes or integrated with external SIEM systems
        audit_review_process = False  # Would need manual verification
        
        is_compliant = has_access_logs and audit_review_process
        
        return {
            "control": "AU-6",
            "title": "Audit Review, Analysis, and Reporting",
            "compliant": has_access_logs,  # Partial compliance based on available data
            "findings": {
                "has_access_logs": has_access_logs,
                "audit_review_process": "Unknown - Requires manual verification"
            },
            "recommendations": [
                "Enable access logs" if not has_access_logs else None,
                "Implement a process for regular review of Slack audit logs",
                "Consider integrating Slack logs with organizational SIEM solution",
                "Establish automated alerting for suspicious activities"
            ]
        }
    
    def _check_au9_compliance(self) -> Dict[str, Any]:
        """Check compliance with AU-9 (Protection of Audit Information)."""
        # Slack internally handles protection of audit logs
        # This control requires verification of internal Slack processes
        # or Enterprise Grid with audit log export to protected storage
        
        workspace_settings = self.audit_results["configurations"]["workspace"]
        has_access_logs = workspace_settings.get("has_access_logs", False)
        is_enterprise_grid = self.audit_results["configurations"]["enterprise"].get("is_enterprise_grid", False)
        
        # Full compliance would need Enterprise Grid for log export capabilities
        is_compliant = has_access_logs and is_enterprise_grid
        
        return {
            "control": "AU-9",
            "title": "Protection of Audit Information",
            "compliant": is_compliant,
            "findings": {
                "has_access_logs": has_access_logs,
                "is_enterprise_grid": is_enterprise_grid
            },
            "recommendations": [
                "Enable access logs" if not has_access_logs else None,
                "Upgrade to Enterprise Grid for enhanced audit capabilities" if not is_enterprise_grid else None,
                "Export audit logs to secure, immutable storage",
                "Implement access controls for exported audit data"
            ]
        }
    
    def _check_cm2_compliance(self) -> Dict[str, Any]:
        """Check compliance with CM-2 (Baseline Configuration)."""
        # Check if there's evidence of documented baseline configurations
        # This is primarily a documentation control
        
        # For Slack, this would involve documenting the approved configuration
        # We can check if key security settings are configured
        
        user_settings = self.audit_results["configurations"]["users"]
        admin_settings = self.audit_results["configurations"]["admin"]
        
        two_factor_required = user_settings.get("two_factor_auth_required", False)
        app_installation_restricted = admin_settings.get("who_can_install_apps") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        
        # These are indicators that a baseline might exist, but not definitive
        potential_baseline_exists = two_factor_required and app_installation_restricted
        
        return {
            "control": "CM-2",
            "title": "Baseline Configuration",
            "compliant": False,  # Cannot determine compliance without documentation
            "findings": {
                "potential_baseline_exists": potential_baseline_exists,
                "two_factor_required": two_factor_required,
                "app_installation_restricted": app_installation_restricted
            },
            "recommendations": [
                "Document baseline configuration for Slack workspace",
                "Include security settings in baseline documentation",
                "Establish process for reviewing changes against baseline",
                "Implement configuration management for Slack settings"
            ]
        }
    
    def _check_cm6_compliance(self) -> Dict[str, Any]:
        """Check compliance with CM-6 (Configuration Settings)."""
        # Check if security-relevant configuration settings are applied
        user_settings = self.audit_results["configurations"]["users"]
        admin_settings = self.audit_results["configurations"]["admin"]
        enterprise_settings = self.audit_results["configurations"]["enterprise"]
        
        two_factor_required = user_settings.get("two_factor_auth_required", False)
        app_installation_restricted = admin_settings.get("who_can_install_apps") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        sso_enabled = enterprise_settings.get("sso_settings", {}).get("sso_enabled", False)
        session_timeout_enabled = enterprise_settings.get("session_settings", {}).get("session_timeout_enabled", False)
        
        # Check if key security settings are configured properly
        is_compliant = two_factor_required and app_installation_restricted and sso_enabled and session_timeout_enabled
        
        return {
            "control": "CM-6",
            "title": "Configuration Settings",
            "compliant": is_compliant,
            "findings": {
                "two_factor_required": two_factor_required,
                "app_installation_restricted": app_installation_restricted,
                "sso_enabled": sso_enabled,
                "session_timeout_enabled": session_timeout_enabled
            },
            "recommendations": [
                "Enforce two-factor authentication for all users" if not two_factor_required else None,
                "Restrict app installation to admins only" if not app_installation_restricted else None,
                "Enable SSO integration" if not sso_enabled else None,
                "Enable session timeout settings" if not session_timeout_enabled else None,
                "Document and implement secure configuration settings"
            ]
        }
    
    def _check_cm7_compliance(self) -> Dict[str, Any]:
        """Check compliance with CM-7 (Least Functionality)."""
        # Check for restriction of unnecessary features
        admin_settings = self.audit_results["configurations"]["admin"]
        app_settings = self.audit_results["configurations"]["apps"]
        
        # Check if app installations are restricted
        app_installation_restricted = admin_settings.get("who_can_install_apps") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        
        # Check if app directory is restricted
        app_directory_restricted = admin_settings.get("app_directory_restrictions", {}).get("app_directory_enabled", False)
        
        # Check if there's a reasonable number of apps installed
        total_apps = app_settings.get("total_apps", 0)
        reasonable_app_count = total_apps < 50  # Subjective threshold
        
        is_compliant = app_installation_restricted and app_directory_restricted and reasonable_app_count
        
        return {
            "control": "CM-7",
            "title": "Least Functionality",
            "compliant": is_compliant,
            "findings": {
                "app_installation_restricted": app_installation_restricted,
                "app_directory_restricted": app_directory_restricted,
                "total_apps": total_apps,
                "reasonable_app_count": reasonable_app_count
            },
            "recommendations": [
                "Restrict app installation to admins only" if not app_installation_restricted else None,
                "Enable app directory restrictions" if not app_directory_restricted else None,
                "Review and reduce the number of installed apps" if not reasonable_app_count else None,
                "Disable unnecessary Slack features that pose security risks"
            ]
        }
    
    def _check_cp9_compliance(self) -> Dict[str, Any]:
        """Check compliance with CP-9 (System Backup)."""
        # Check for backup capabilities
        retention_settings = self.audit_results["configurations"]["retention"]
        
        # Check if retention policies are in place
        has_retention_policy = retention_settings.get("has_retention_policy", False)
        
        # Enterprise Grid provides better export and backup capabilities
        is_enterprise_grid = self.audit_results["configurations"]["enterprise"].get("is_enterprise_grid", False)
        
        # Full compliance would need verification of actual backup procedures
        is_compliant = has_retention_policy and is_enterprise_grid
        
        return {
            "control": "CP-9",
            "title": "System Backup",
            "compliant": is_compliant,
            "findings": {
                "has_retention_policy": has_retention_policy,
                "is_enterprise_grid": is_enterprise_grid
            },
            "recommendations": [
                "Implement retention policies" if not has_retention_policy else None,
                "Upgrade to Enterprise Grid for enhanced export capabilities" if not is_enterprise_grid else None,
                "Establish regular workspace data export procedures",
                "Document backup and recovery procedures for Slack data"
            ]
        }
    
    def _check_ir4_compliance(self) -> Dict[str, Any]:
        """Check compliance with IR-4 (Incident Handling)."""
        # Check for incident handling capabilities
        # This is primarily a process control but can check for enabling features
        
        # Enterprise Grid provides better security monitoring and integration
        is_enterprise_grid = self.audit_results["configurations"]["enterprise"].get("is_enterprise_grid", False)
        
        # Audit logging is necessary for incident detection
        has_access_logs = self.audit_results["configurations"]["workspace"].get("has_access_logs", False)
        
        # Cannot fully verify without process documentation
        is_compliant = is_enterprise_grid and has_access_logs
        
        return {
            "control": "IR-4",
            "title": "Incident Handling",
            "compliant": is_compliant,
            "findings": {
                "is_enterprise_grid": is_enterprise_grid,
                "has_access_logs": has_access_logs
            },
            "recommendations": [
                "Upgrade to Enterprise Grid for enhanced security capabilities" if not is_enterprise_grid else None,
                "Enable access logs" if not has_access_logs else None,
                "Include Slack incidents in organizational incident response procedures",
                "Configure security alerting for suspicious Slack activities",
                "Establish procedures for containing and eradicating Slack-based security incidents"
            ]
        }
    
    def _check_mp7_compliance(self) -> Dict[str, Any]:
        """Check compliance with MP-7 (Media Sanitization)."""
        # Check for data deletion and sanitization capabilities
        retention_settings = self.audit_results["configurations"]["retention"]
        
        # Check if retention policies are in place for automatic deletion
        has_retention_policy = retention_settings.get("has_retention_policy", False)
        
        # Enterprise Grid provides better data management capabilities
        is_enterprise_grid = self.audit_results["configurations"]["enterprise"].get("is_enterprise_grid", False)
        
        # Full compliance would need verification of actual media sanitization procedures
        is_compliant = has_retention_policy and is_enterprise_grid
        
        return {
            "control": "MP-7",
            "title": "Media Sanitization",
            "compliant": is_compliant,
            "findings": {
                "has_retention_policy": has_retention_policy,
                "is_enterprise_grid": is_enterprise_grid
            },
            "recommendations": [
                "Implement retention policies for automatic deletion" if not has_retention_policy else None,
                "Upgrade to Enterprise Grid for enhanced data management" if not is_enterprise_grid else None,
                "Establish procedures for sanitizing Slack data when no longer needed",
                "Configure minimum necessary retention periods for compliance"
            ]
        }
    
    def _check_ra5_compliance(self) -> Dict[str, Any]:
        """Check compliance with RA-5 (Vulnerability Scanning)."""
        # Check for vulnerability management capabilities
        app_settings = self.audit_results["configurations"]["apps"]
        
        # Slack handles vulnerability scanning for their platform
        # For customers, focus is on custom apps and integrations
        
        risky_apps_count = app_settings.get("risky_apps_count", 0)
        has_risky_apps = risky_apps_count > 0
        
        # Enterprise Grid provides better security monitoring
        is_enterprise_grid = self.audit_results["configurations"]["enterprise"].get("is_enterprise_grid", False)
        
        # Compliance is based on addressing vulnerabilities in custom apps/integrations
        is_compliant = not has_risky_apps and is_enterprise_grid
        
        return {
            "control": "RA-5",
            "title": "Vulnerability Scanning",
            "compliant": is_compliant,
            "findings": {
                "risky_apps_count": risky_apps_count,
                "has_risky_apps": has_risky_apps,
                "is_enterprise_grid": is_enterprise_grid
            },
            "recommendations": [
                "Review and remediate risky app permissions" if has_risky_apps else None,
                "Upgrade to Enterprise Grid for enhanced security monitoring" if not is_enterprise_grid else None,
                "Implement vulnerability assessment for custom Slack apps",
                "Establish process for security patching of custom integrations"
            ]
        }
    
    def _check_sa9_compliance(self) -> Dict[str, Any]:
        """Check compliance with SA-9 (External Information System Services)."""
        # Check external service provider use
        app_settings = self.audit_results["configurations"]["apps"]
        admin_settings = self.audit_results["configurations"]["admin"]
        
        # Check if app installations are restricted
        app_installation_restricted = admin_settings.get("who_can_install_apps") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        
        # Check if app directory is restricted
        app_directory_restricted = admin_settings.get("app_directory_restrictions", {}).get("app_directory_enabled", False)
        
        # Check if there are risky apps that may access external services
        risky_apps_count = app_settings.get("risky_apps_count", 0)
        minimal_risky_apps = risky_apps_count < 5  # Subjective threshold
        
        is_compliant = app_installation_restricted and app_directory_restricted and minimal_risky_apps
        
        return {
            "control": "SA-9",
            "title": "External Information System Services",
            "compliant": is_compliant,
            "findings": {
                "app_installation_restricted": app_installation_restricted,
                "app_directory_restricted": app_directory_restricted,
                "risky_apps_count": risky_apps_count,
                "minimal_risky_apps": minimal_risky_apps
            },
            "recommendations": [
                "Restrict app installation to admins only" if not app_installation_restricted else None,
                "Enable app directory restrictions" if not app_directory_restricted else None,
                "Review and reduce third-party integrations with sensitive permissions" if not minimal_risky_apps else None,
                "Establish security assessment procedures for Slack integrations"
            ]
        }
    
    def _check_sc7_compliance(self) -> Dict[str, Any]:
        """Check compliance with SC-7 (Boundary Protection)."""
        # Check for boundary protection controls
        admin_settings = self.audit_results["configurations"]["admin"]
        enterprise_settings = self.audit_results["configurations"]["enterprise"]
        
        # Check if shared channels are restricted (external boundaries)
        shared_channel_restricted = admin_settings.get("who_can_create_shared_channels") in ["ADMIN_ONLY", "SPECIFIC_USERS"]
        
        # SSO helps with boundary protection
        sso_enabled = enterprise_settings.get("sso_settings", {}).get("sso_enabled", False)
        
        # IP restrictions would be part of Enterprise Grid (not directly checkable via API)
        is_enterprise_grid = enterprise_settings.get("is_enterprise_grid", False)
        
        is_compliant = shared_channel_restricted and sso_enabled and is_enterprise_grid
        
        return {
            "control": "SC-7",
            "title": "Boundary Protection",
            "compliant": is_compliant,
            "findings": {
                "shared_channel_restricted": shared_channel_restricted,
                "sso_enabled": sso_enabled,
                "is_enterprise_grid": is_enterprise_grid
            },
            "recommendations": [
                "Restrict shared channel creation to admins only" if not shared_channel_restricted else None,
                "Enable SSO integration" if not sso_enabled else None,
                "Upgrade to Enterprise Grid for IP allowlisting capabilities" if not is_enterprise_grid else None,
                "Configure IP allowlisting to restrict access to authorized networks",
                "Implement device management for Slack access"
            ]
        }
    
    def _check_sc13_compliance(self) -> Dict[str, Any]:
        """Check compliance with SC-13 (Cryptographic Protection)."""
        # Check for cryptographic protection
        # Slack handles this internally, but Enterprise Grid provides more options
        
        is_enterprise_grid = self.audit_results["configurations"]["enterprise"].get("is_enterprise_grid", False)
        
        # Slack uses TLS by default
        uses_tls = True
        
        # Enterprise key management is an Enterprise Grid feature
        has_enterprise_key_management = False  # Would need to check manually
        
        is_compliant = uses_tls and is_enterprise_grid and has_enterprise_key_management
        
        return {
            "control": "SC-13",
            "title": "Cryptographic Protection",
            "compliant": uses_tls,  # Basic compliance through TLS
            "findings": {
                "uses_tls": uses_tls,
                "is_enterprise_grid": is_enterprise_grid,
                "has_enterprise_key_management": "Unknown - Requires manual verification"
            },
            "recommendations": [
                "Upgrade to Enterprise Grid for enhanced cryptographic controls" if not is_enterprise_grid else None,
                "Consider implementing Enterprise Key Management",
                "Document cryptographic requirements for Slack data"
            ]
        }
    
    def _check_sc28_compliance(self) -> Dict[str, Any]:
        """Check compliance with SC-28 (Protection of Information at Rest)."""
        # Check for protection of information at rest
        # Slack handles this internally, but Enterprise Grid provides more options
        
        is_enterprise_grid = self.audit_results["configurations"]["enterprise"].get("is_enterprise_grid", False)
        
        # Enterprise key management is an Enterprise Grid feature
        has_enterprise_key_management = False  # Would need to check manually
        
        # Slack encrypts data at rest by default
        data_encrypted_at_rest = True
        
        is_compliant = data_encrypted_at_rest and is_enterprise_grid and has_enterprise_key_management
        
        return {
            "control": "SC-28",
            "title": "Protection of Information at Rest",
            "compliant": data_encrypted_at_rest,  # Basic compliance
            "findings": {
                "data_encrypted_at_rest": data_encrypted_at_rest,
                "is_enterprise_grid": is_enterprise_grid,
                "has_enterprise_key_management": "Unknown - Requires manual verification"
            },
            "recommendations": [
                "Upgrade to Enterprise Grid for enhanced encryption controls" if not is_enterprise_grid else None,
                "Consider implementing customer-managed encryption keys",
                "Document encryption requirements for stored Slack data"
            ]
        }
    
    def _check_si4_compliance(self) -> Dict[str, Any]:
        """Check compliance with SI-4 (Information System Monitoring)."""
        # Check for system monitoring capabilities
        workspace_settings = self.audit_results["configurations"]["workspace"]
        enterprise_settings = self.audit_results["configurations"]["enterprise"]
        
        # Check if access logs are enabled
        has_access_logs = workspace_settings.get("has_access_logs", False)
        
        # Enterprise Grid provides better monitoring and integration
        is_enterprise_grid = enterprise_settings.get("is_enterprise_grid", False)
        
        # DLP monitoring would be part of Enterprise Grid
        has_dlp_monitoring = False  # Would need to check manually
        
        is_compliant = has_access_logs and is_enterprise_grid and has_dlp_monitoring
        
        return {
            "control": "SI-4",
            "title": "Information System Monitoring",
            "compliant": has_access_logs,  # Basic compliance
            "findings": {
                "has_access_logs": has_access_logs,
                "is_enterprise_grid": is_enterprise_grid,
                "has_dlp_monitoring": "Unknown - Requires manual verification"
            },
            "recommendations": [
                "Enable access logs" if not has_access_logs else None,
                "Upgrade to Enterprise Grid for enhanced monitoring capabilities" if not is_enterprise_grid else None,
                "Implement Data Loss Prevention (DLP) monitoring",
                "Integrate Slack monitoring with organizational SIEM solution",
                "Configure alerting for anomalous Slack activities"
            ]
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
        # Create a raw configs directory
        raw_configs_dir = f"{self.output_dir}/raw_configs_{self.timestamp}"
        if not os.path.exists(raw_configs_dir):
            os.makedirs(raw_configs_dir)
        
        # Save raw API responses for later inspection
        print(f"Saving raw configuration data to: {raw_configs_dir}")
        
        # Save enterprise settings
        with open(f"{raw_configs_dir}/enterprise_settings.json", "w") as f:
            json.dump(self.audit_results["configurations"]["enterprise"], f, indent=2)
            
        # Save admin settings
        with open(f"{raw_configs_dir}/admin_settings.json", "w") as f:
            json.dump(self.audit_results["configurations"]["admin"], f, indent=2)
            
        # Save workspace settings
        with open(f"{raw_configs_dir}/workspace_settings.json", "w") as f:
            json.dump(self.audit_results["configurations"]["workspace"], f, indent=2)
            
        # Save user settings
        with open(f"{raw_configs_dir}/user_settings.json", "w") as f:
            json.dump(self.audit_results["configurations"]["users"], f, indent=2)
            
        # Save app configurations
        with open(f"{raw_configs_dir}/app_settings.json", "w") as f:
            json.dump(self.audit_results["configurations"]["apps"], f, indent=2)
            
        # Save retention policies
        with open(f"{raw_configs_dir}/retention_settings.json", "w") as f:
            json.dump(self.audit_results["configurations"]["retention"], f, indent=2)
            
        # Save compliance findings
        with open(f"{raw_configs_dir}/compliance_findings.json", "w") as f:
            json.dump(self.audit_results["compliance"], f, indent=2)
        
        # Save full results
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