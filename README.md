# Slack FedRAMP Compliance Audit Tool

A tool to help organizations audit their Slack workspaces for FedRAMP compliance and gather evidence for NIST 800-53 controls.

## Overview

This tool connects to your Slack workspace via the Slack API and audits various security configurations relevant to FedRAMP compliance and NIST 800-53 controls. It helps organizations:

- Assess their current Slack configuration against FedRAMP requirements
- Generate evidence for NIST 800-53 security controls 
- Identify compliance gaps and receive recommendations for remediation
- Create documentation for auditors and compliance reviews

For a comprehensive manual evaluation approach, see the included [Slack FedRAMP and NIST 800-53 Compliance Evaluation Guide](SLACK_EVALUATION_GUIDE.md).

## Quick Start Guide

The tool is available in two versions:
- A Python script (`slack_audit.py`)
- A Bash script (`slack_audit.sh`) for users who can't run Python

### Python Version Setup

1. Ensure you have Python 3.6+ installed:
   ```
   python --version
   ```

2. Clone this repository and install dependencies:
   ```
   git clone https://github.com/your-org/slack-audit.git
   cd slack-audit
   pip install -r requirements.txt
   ```

### Bash Version Setup

1. Ensure you have `bash` and `jq` installed:
   ```
   bash --version
   jq --version
   ```

2. If `jq` is not installed, install it using your package manager:
   ```
   # Ubuntu/Debian
   sudo apt-get install jq
   
   # CentOS/RHEL
   sudo yum install jq
   
   # macOS
   brew install jq
   ```

3. Make the script executable:
   ```
   chmod +x slack_audit.sh
   ```

3. Get a Slack API token with admin privileges:
   - Go to [Slack API Apps](https://api.slack.com/apps)
   - Click "Create New App" → "From scratch"
   - Name your app (e.g., "Compliance Audit") and select your workspace
   - Navigate to "OAuth & Permissions"
   - Add the following OAuth scopes:
     - `admin`
     - `admin.teams:read`
     - `admin.users:read`
     - `channels:read`
     - `groups:read`
     - `im:read`
     - `mpim:read`
     - `team:read`
     - `users:read`
     - `files:read`
     - `apps:read`
   - Install the app to your workspace
   - Copy the OAuth User Token (starts with `xoxp-`)

   Note: For Enterprise Grid workspaces, you may need additional admin permissions.

### Running the Audit

#### Using the Python Version

Run the audit with your Slack API token:

```
python slack_audit.py --token xoxp-your-slack-api-token
```

By default, results are stored in the `./audit_results` directory. You can specify a different output directory:

```
python slack_audit.py --token xoxp-your-slack-api-token --output-dir /path/to/output
```

#### Using the Bash Version

Run the audit with your Slack API token:

```
./slack_audit.sh --token xoxp-your-slack-api-token
```

You can also specify a different output directory:

```
./slack_audit.sh --token xoxp-your-slack-api-token --output-dir /path/to/output
```

Both versions produce the same output formats and follow the same audit process.

### Understanding Results

After running the audit, the following outputs will be generated in the output directory:

1. `slack_audit_TIMESTAMP.json` - Detailed JSON with all findings
2. `slack_audit_summary_TIMESTAMP.md` - Human-readable summary report
3. `raw_configs_TIMESTAMP/` - Directory containing raw configuration files:
   - `enterprise_settings.json` - Enterprise Grid details, domains, and SSO configuration
   - `admin_settings.json` - Admin permissions and restriction settings
   - `workspace_settings.json` - Workspace metadata and channel information
   - `user_settings.json` - User counts, admin stats, and 2FA details
   - `app_settings.json` - Installed app information with permissions
   - `retention_settings.json` - Data retention policies
   - `compliance_findings.json` - Detailed compliance assessments per control

The summary report contains:
- Workspace information
- Compliance score and status
- Detailed findings for each NIST 800-53 control
- Recommendations for improving compliance

The raw configuration files preserve the detailed API responses for later inspection, evidence gathering, and more detailed analysis.

See the [sample_output/](sample_output/) directory for example reports and raw configuration files.

### Common Issues

1. **Token Permission Errors**:
   - Ensure your token has all required scopes
   - If using Enterprise Grid, ensure the token has enterprise-wide permissions

2. **API Rate Limiting**:
   - The tool respects Slack's API rate limits, but if you encounter rate limiting errors, wait a few minutes and try again

3. **Missing Enterprise Settings**:
   - Some settings only apply to Enterprise Grid workspaces
   - The tool will indicate if certain features could not be audited

## Features

The tool performs comprehensive auditing of:

- Enterprise and workspace settings
- Admin configurations and permissions
- User authentication settings (2FA, SSO)
- App integration security
- Data retention policies
- Message and file sharing controls
- Audit logging capabilities
- And more

### Next Steps After Audit

1. Review the summary report to identify compliance gaps
2. Implement the recommended changes in your Slack workspace
3. Re-run the audit to verify improvements
4. Keep the reports as evidence for your FedRAMP audit

## FedRAMP Compliance

This tool helps organizations gather evidence for FedRAMP compliance by:

1. Identifying configuration gaps that may impact FedRAMP compliance
2. Providing documentation for auditors on Slack security settings
3. Mapping Slack configurations to relevant NIST 800-53 controls
4. Suggesting remediation steps to improve compliance posture

## NIST 800-53 Controls

The tool evaluates compliance with 27 NIST 800-53 controls:

| Control | Title | What We Check |
|---------|-------|---------------|
| AC-2 | Account Management | User invitation restrictions, access logs |
| AC-3 | Access Enforcement | Channel creation/management restrictions |
| AC-4 | Information Flow Enforcement | Shared channels, DLP settings, external sharing |
| AC-6 | Least Privilege | Admin role distribution, privileged actions |
| AC-7 | Unsuccessful Login Attempts | Slack's built-in account lockout |
| AC-17 | Remote Access | SSO configuration, session timeout settings |
| AU-2 | Audit Events | Access logging capabilities |
| AU-3 | Content of Audit Records | Log detail, recorded information |
| AU-6 | Audit Review | Log analysis and reporting mechanisms |
| AU-9 | Protection of Audit Information | Log access control, export protection |
| CM-2 | Baseline Configuration | Documentation of approved settings |
| CM-6 | Configuration Settings | Implementation of security settings |
| CM-7 | Least Functionality | Restriction of unnecessary features |
| CP-9 | System Backup | Data export and recovery capabilities |
| IA-2 | Identification and Authentication | 2FA enforcement, SSO implementation |
| IA-5 | Authenticator Management | 2FA enforcement, password policies |
| IR-4 | Incident Handling | Incident response procedures, capabilities |
| MP-7 | Media Sanitization | Data deletion, retention policies |
| RA-5 | Vulnerability Scanning | App security assessment |
| SA-9 | External Information System Services | Third-party app security |
| SC-7 | Boundary Protection | IP restrictions, domain controls |
| SC-8 | Transmission Confidentiality and Integrity | TLS implementation |
| SC-12 | Cryptographic Key Management | Encryption key handling |
| SC-13 | Cryptographic Protection | Encryption algorithms, FIPS compliance |
| SC-28 | Protection of Information at Rest | Data encryption methods |
| SI-4 | Information System Monitoring | Security monitoring, alerting |
| SI-7 | Software, Firmware, and Information Integrity | App installation restrictions |

## Limitations

- The tool relies on the Slack API, which may change over time
- Some settings may not be accessible via the API and require manual verification
- FedRAMP requirements evolve, and this tool should be used as a supplementary aid, not a complete compliance solution
- Enterprise Grid workspaces may have additional settings not covered by this tool

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.