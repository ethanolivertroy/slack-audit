# Slack FedRAMP Compliance Audit Tool

A tool to help organizations audit their Slack workspaces for FedRAMP compliance and gather evidence for NIST 800-53 controls.

## Overview

This tool connects to your Slack workspace via the Slack API and audits various security configurations relevant to FedRAMP compliance and NIST 800-53 controls. It helps organizations:

- Assess their current Slack configuration against FedRAMP requirements
- Generate evidence for NIST 800-53 security controls 
- Identify compliance gaps and receive recommendations for remediation
- Create documentation for auditors and compliance reviews

## Features

- Audits enterprise and workspace settings
- Evaluates admin configurations
- Checks user authentication settings (2FA, SSO)
- Reviews app integration security
- Assesses data retention policies
- Analyzes compliance with key NIST 800-53 controls:
  - AC-2 (Account Management)
  - AC-3 (Access Enforcement)
  - AC-7 (Unsuccessful Login Attempts)
  - AC-17 (Remote Access)
  - AU-2 (Audit Events)
  - IA-2 (Identification and Authentication)
  - IA-5 (Authenticator Management)
  - SC-8 (Transmission Confidentiality and Integrity)
  - SC-12 (Cryptographic Key Establishment and Management)
  - SI-7 (Software, Firmware, and Information Integrity)
- Generates detailed JSON output for further analysis
- Creates a human-readable summary report in Markdown format

## Prerequisites

- Python 3.6 or higher
- Slack workspace with admin privileges
- Slack API token with admin scope

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/your-org/slack-audit.git
   cd slack-audit
   ```

2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Getting a Slack API Token

To use this tool, you'll need a Slack API token with admin privileges:

1. Go to [Slack API Apps](https://api.slack.com/apps)
2. Create a new app in your workspace
3. Add the following OAuth scopes:
   - `admin`
   - `admin.teams:read`
   - `admin.users:read`
   - `channels:read`
   - `team:read`
   - `users:read`
   - `users.profile:read`
4. Install the app to your workspace
5. Copy the OAuth Access Token

## Usage

Run the audit with your Slack API token:

```
python slack_audit.py --token xoxp-your-slack-api-token
```

By default, results are stored in the `./audit_results` directory. You can specify a different output directory:

```
python slack_audit.py --token xoxp-your-slack-api-token --output-dir /path/to/output
```

## Output

The tool generates two output files:

1. A detailed JSON file with all audit data: `slack_audit_TIMESTAMP.json`
2. A human-readable Markdown summary: `slack_audit_summary_TIMESTAMP.md`

The summary report includes:
- Workspace information
- Compliance score and status
- Detailed findings for each NIST 800-53 control
- Recommendations for improving compliance

## FedRAMP Compliance

This tool helps organizations gather evidence for FedRAMP compliance by:

1. Identifying configuration gaps that may impact FedRAMP compliance
2. Providing documentation for auditors on Slack security settings
3. Mapping Slack configurations to relevant NIST 800-53 controls
4. Suggesting remediation steps to improve compliance posture

## NIST 800-53 Controls

The tool specifically evaluates compliance with these NIST 800-53 controls:

| Control | Title | What We Check |
|---------|-------|---------------|
| AC-2 | Account Management | User invitation restrictions, access logs |
| AC-3 | Access Enforcement | Channel creation/management restrictions |
| AC-7 | Unsuccessful Login Attempts | Slack's built-in account lockout |
| AC-17 | Remote Access | SSO configuration, session timeout settings |
| AU-2 | Audit Events | Access logging capabilities |
| IA-2 | Identification and Authentication | 2FA enforcement, SSO implementation |
| IA-5 | Authenticator Management | 2FA enforcement, password policies |
| SC-8 | Transmission Confidentiality and Integrity | TLS implementation |
| SC-12 | Cryptographic Key Management | Encryption key handling |
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