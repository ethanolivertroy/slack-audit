# Slack FedRAMP Compliance Audit Summary

**Audit Date:** 2025-03-25 14:30:45

## Workspace Information

- **Workspace Name:** Example Org
- **Workspace Domain:** example-org
- **Total Users:** 125

## Compliance Summary

- **Compliance Score:** 70.0% (7/10 controls)

## Control Compliance Details

### ✅ AC-2: Account Management

### ✅ AC-3: Access Enforcement

### ✅ AC-7: Unsuccessful Login Attempts

**Findings:**

- Note: Slack automatically implements account lockout after multiple failed login attempts

### ❌ AC-17: Remote Access

**Findings:**

- Sso Enabled: false
- Session Timeout Enabled: true
- Session Duration Hours: 24

**Recommendations:**

- Enable SSO integration
- Reduce session duration to 12 hours or less

### ✅ AU-2: Audit Events

### ❌ IA-2: Identification and Authentication

**Findings:**

- Two Factor Auth Required: false
- Two Factor Enabled Percentage: 45.2
- Sso Enabled: false
- Sso Provider: None

**Recommendations:**

- Enforce two-factor authentication for all users
- Implement SSO integration

### ❌ IA-5: Authenticator Management

**Findings:**

- Two Factor Auth Required: false
- Sso Enabled: false

**Recommendations:**

- Enforce two-factor authentication for all users
- Implement SSO integration to leverage organizational password policies

### ✅ SC-8: Transmission Confidentiality and Integrity

**Findings:**

- Note: Slack automatically uses TLS for all communications

### ✅ SC-12: Cryptographic Key Establishment and Management

**Findings:**

- Note: Slack automatically handles cryptographic key management

### ✅ SI-7: Software, Firmware, and Information Integrity

## Overall Recommendations

- AC-17: Enable SSO integration
- AC-17: Reduce session duration to 12 hours or less
- IA-2: Enforce two-factor authentication for all users
- IA-2: Implement SSO integration
- IA-5: Enforce two-factor authentication for all users
- IA-5: Implement SSO integration to leverage organizational password policies