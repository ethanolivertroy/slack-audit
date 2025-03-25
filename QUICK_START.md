# Slack FedRAMP Compliance Audit Tool - Quick Start Guide

This guide provides a quick overview of how to get started with the Slack FedRAMP Compliance Audit Tool.

## Setup

1. Ensure you have Python 3.6+ installed:
   ```
   python --version
   ```

2. Install dependencies:
   ```
   pip install -r requirements.txt
   ```

3. Get a Slack API token with admin privileges:
   - Go to [Slack API Apps](https://api.slack.com/apps)
   - Create a new app in your workspace
   - Navigate to "OAuth & Permissions"
   - Add the following OAuth scopes:
     - `admin`
     - `admin.teams:read`
     - `admin.users:read`
     - `channels:read`
     - `team:read`
     - `users:read`
     - `users.profile:read`
   - Install the app to your workspace
   - Copy the OAuth Access Token

## Running the Audit

Run the audit with your Slack API token:

```
python slack_audit.py --token xoxp-your-slack-api-token
```

## Understanding Results

After running the audit, two files will be generated in the `./audit_results` directory:

1. `slack_audit_TIMESTAMP.json` - Detailed JSON with all findings
2. `slack_audit_summary_TIMESTAMP.md` - Human-readable summary report

The summary report contains:
- Workspace information
- Compliance score
- Findings for each NIST 800-53 control
- Recommendations for improving compliance

## Common Issues

1. **Token Permission Errors**:
   - Ensure your token has all required scopes
   - If using Enterprise Grid, ensure the token has enterprise-wide permissions

2. **API Rate Limiting**:
   - The tool respects Slack's API rate limits, but if you encounter rate limiting errors, wait a few minutes and try again

3. **Missing Enterprise Settings**:
   - Some settings only apply to Enterprise Grid workspaces
   - The tool will indicate if certain features could not be audited

## Next Steps

1. Review the summary report to identify compliance gaps
2. Implement the recommended changes in your Slack workspace
3. Re-run the audit to verify improvements
4. Keep the reports as evidence for your FedRAMP audit

## Support

If you encounter issues or have questions, please create an issue on the GitHub repository.