#!/bin/bash

# Slack FedRAMP Compliance Audit Tool (Bash version)
# This script helps organizations audit their Slack workspace configuration
# for FedRAMP compliance and gather evidence for NIST 800-53 controls.

set -e

# Default values
OUTPUT_DIR="./audit_results"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Print usage information
function show_usage {
  echo "Usage: $0 --token <slack-api-token> [--output-dir <directory>]"
  echo ""
  echo "Options:"
  echo "  --token      Slack API token with admin privileges (required)"
  echo "  --output-dir Directory to store audit results (default: ./audit_results)"
  echo "  --help       Show this help message"
  echo ""
  exit 1
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --token)
      TOKEN="$2"
      shift 2
      ;;
    --output-dir)
      OUTPUT_DIR="$2"
      shift 2
      ;;
    --help)
      show_usage
      ;;
    *)
      echo "Unknown option: $1"
      show_usage
      ;;
  esac
done

# Check if token is provided
if [ -z "$TOKEN" ]; then
  echo "Error: Slack API token is required"
  show_usage
fi

# Check if jq is installed
if ! command -v jq &> /dev/null; then
  echo "Error: jq is required but not installed."
  echo "Please install jq using your package manager:"
  echo "  - Ubuntu/Debian: sudo apt-get install jq"
  echo "  - CentOS/RHEL:   sudo yum install jq"
  echo "  - macOS:         brew install jq"
  exit 1
fi

# Create output directories
RESULTS_DIR="${OUTPUT_DIR}"
RAW_CONFIG_DIR="${OUTPUT_DIR}/raw_configs_${TIMESTAMP}"
mkdir -p "${RESULTS_DIR}" "${RAW_CONFIG_DIR}"

echo "Starting Slack FedRAMP compliance audit..."

# Validate API token
echo "Validating Slack API token..."
AUTH_TEST=$(curl -s -H "Authorization: Bearer ${TOKEN}" \
                 -H "Content-Type: application/json" \
                 "https://slack.com/api/auth.test")

if [ "$(echo "${AUTH_TEST}" | jq -r '.ok')" != "true" ]; then
  ERROR_MSG=$(echo "${AUTH_TEST}" | jq -r '.error')
  echo "Error: Invalid token or insufficient permissions. API response: ${ERROR_MSG}"
  exit 1
fi

TEAM_NAME=$(echo "${AUTH_TEST}" | jq -r '.team')
USER_NAME=$(echo "${AUTH_TEST}" | jq -r '.user')
echo "Successfully authenticated as ${USER_NAME} in workspace ${TEAM_NAME}"

# Function to make API requests
function make_api_request {
  local endpoint="$1"
  local params="$2"
  
  if [ -z "$params" ]; then
    curl -s -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            "https://slack.com/api/${endpoint}"
  else
    curl -s -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json" \
            "https://slack.com/api/${endpoint}?${params}"
  fi
}

# Audit enterprise settings
echo "Auditing enterprise settings..."
ENTERPRISE_INFO=$(make_api_request "admin.enterprise.info")
ENTERPRISE_SETTINGS="{}"

if [ "$(echo "${ENTERPRISE_INFO}" | jq -r '.ok')" == "true" ]; then
  ENTERPRISE_ID=$(echo "${ENTERPRISE_INFO}" | jq -r '.enterprise.id')
  ENTERPRISE_NAME=$(echo "${ENTERPRISE_INFO}" | jq -r '.enterprise.name')
  
  # Get domain info
  DOMAINS_INFO=$(make_api_request "admin.enterprise.domains.list")
  DOMAINS=$(echo "${DOMAINS_INFO}" | jq -r '.domains')
  
  # Get SSO settings (team settings needed for this)
  TEAM_SETTINGS=$(make_api_request "admin.team.settings.getInfo")
  SSO_ENABLED=$(echo "${TEAM_SETTINGS}" | jq -r '.team.sso_enabled // false')
  SSO_PROVIDER=$(echo "${TEAM_SETTINGS}" | jq -r '.team.sso_provider // null')
  SESSION_DURATION=$(echo "${TEAM_SETTINGS}" | jq -r '.team.session_duration // 0')
  
  # Get session settings
  SESSION_TIMEOUT_ENABLED=$(echo "${TEAM_SETTINGS}" | jq -r '.team.session_timeout_enabled // false')
  SESSION_DURATION_HOURS=$(echo "${TEAM_SETTINGS}" | jq -r '.team.session_duration // 0 | . / 3600')
  MOBILE_SESSION_DURATION_HOURS=$(echo "${TEAM_SETTINGS}" | jq -r '.team.mobile_session_duration // 0 | . / 3600')
  
  # Construct enterprise settings JSON
  ENTERPRISE_SETTINGS=$(jq -n \
    --arg id "${ENTERPRISE_ID}" \
    --arg name "${ENTERPRISE_NAME}" \
    --argjson domains "${DOMAINS}" \
    --argjson sso_enabled "${SSO_ENABLED}" \
    --arg sso_provider "${SSO_PROVIDER}" \
    --argjson session_duration "${SESSION_DURATION}" \
    --argjson session_timeout_enabled "${SESSION_TIMEOUT_ENABLED}" \
    --argjson session_duration_hours "${SESSION_DURATION_HOURS}" \
    --argjson mobile_session_duration_hours "${MOBILE_SESSION_DURATION_HOURS}" \
    '{
      "is_enterprise_grid": true,
      "enterprise_id": $id,
      "enterprise_name": $name,
      "domains": $domains,
      "sso_settings": {
        "sso_enabled": $sso_enabled,
        "sso_provider": $sso_provider,
        "session_duration": $session_duration
      },
      "session_settings": {
        "session_timeout_enabled": $session_timeout_enabled,
        "session_duration_hours": $session_duration_hours,
        "mobile_session_duration_hours": $mobile_session_duration_hours
      }
    }')
else
  echo "This workspace doesn't appear to use Enterprise Grid."
  ENTERPRISE_SETTINGS=$(jq -n '{
    "is_enterprise_grid": false,
    "enterprise_id": null,
    "enterprise_name": null,
    "domains": [],
    "sso_settings": {
      "sso_enabled": false,
      "sso_provider": null,
      "session_duration": null
    },
    "session_settings": {
      "session_timeout_enabled": false,
      "session_duration_hours": 0,
      "mobile_session_duration_hours": 0
    }
  }')
fi

# Save enterprise settings
echo "${ENTERPRISE_SETTINGS}" > "${RAW_CONFIG_DIR}/enterprise_settings.json"

# Audit admin settings
echo "Auditing admin settings..."
TEAM_SETTINGS_INFO=$(make_api_request "admin.team.settings.info")
ADMIN_SETTINGS="{}"

# Extract admin settings
if [ "$(echo "${TEAM_SETTINGS_INFO}" | jq -r '.ok')" == "true" ]; then
  TEAM_INFO=$(echo "${TEAM_SETTINGS_INFO}" | jq -r '.team')
  
  # Get values or defaults
  WHO_CAN_CREATE_CHANNELS=$(echo "${TEAM_INFO}" | jq -r '.who_can_create_channels // "EVERYONE"')
  WHO_CAN_ARCHIVE_CHANNELS=$(echo "${TEAM_INFO}" | jq -r '.who_can_archive_channels // "EVERYONE"')
  WHO_CAN_CREATE_SHARED_CHANNELS=$(echo "${TEAM_INFO}" | jq -r '.who_can_create_shared_channels // "EVERYONE"')
  WHO_CAN_CREATE_PRIVATE_CHANNELS=$(echo "${TEAM_INFO}" | jq -r '.who_can_create_private_channels // "EVERYONE"')
  WHO_CAN_DELETE_MESSAGES=$(echo "${TEAM_INFO}" | jq -r '.who_can_delete_messages // "EVERYONE"')
  WHO_CAN_EDIT_MESSAGES=$(echo "${TEAM_INFO}" | jq -r '.who_can_edit_messages // "EVERYONE"')
  WHO_CAN_INVITE=$(echo "${TEAM_INFO}" | jq -r '.who_can_invite // "EVERYONE"')
  WHO_CAN_INSTALL_APPS=$(echo "${TEAM_INFO}" | jq -r '.who_can_install_apps // "EVERYONE"')
  
  # Get app directory restrictions
  APP_RESTRICTIONS=$(make_api_request "admin.apps.restricted.list")
  APP_DIRECTORY_ENABLED=$(echo "${APP_RESTRICTIONS}" | jq -r '.ok // false')
  RESTRICTED_APPS_COUNT=$(echo "${APP_RESTRICTIONS}" | jq -r '.restricted_apps | length // 0')
  ALLOWED_APPS_COUNT=$(echo "${APP_RESTRICTIONS}" | jq -r '.allowed_apps | length // 0')
  
  # Construct admin settings JSON
  ADMIN_SETTINGS=$(jq -n \
    --arg who_can_create_channels "${WHO_CAN_CREATE_CHANNELS}" \
    --arg who_can_archive_channels "${WHO_CAN_ARCHIVE_CHANNELS}" \
    --arg who_can_create_shared_channels "${WHO_CAN_CREATE_SHARED_CHANNELS}" \
    --arg who_can_create_private_channels "${WHO_CAN_CREATE_PRIVATE_CHANNELS}" \
    --arg who_can_delete_messages "${WHO_CAN_DELETE_MESSAGES}" \
    --arg who_can_edit_messages "${WHO_CAN_EDIT_MESSAGES}" \
    --arg who_can_invite "${WHO_CAN_INVITE}" \
    --arg who_can_install_apps "${WHO_CAN_INSTALL_APPS}" \
    --argjson app_directory_enabled "${APP_DIRECTORY_ENABLED}" \
    --argjson restricted_apps_count "${RESTRICTED_APPS_COUNT}" \
    --argjson allowed_apps_count "${ALLOWED_APPS_COUNT}" \
    '{
      "who_can_create_channels": $who_can_create_channels,
      "who_can_archive_channels": $who_can_archive_channels,
      "who_can_create_shared_channels": $who_can_create_shared_channels,
      "who_can_create_private_channels": $who_can_create_private_channels,
      "who_can_delete_messages": $who_can_delete_messages,
      "who_can_edit_messages": $who_can_edit_messages,
      "who_can_invite_to_workspace": $who_can_invite,
      "who_can_install_apps": $who_can_install_apps,
      "app_directory_restrictions": {
        "app_directory_enabled": $app_directory_enabled,
        "restricted_apps_count": $restricted_apps_count,
        "allowed_apps_count": $allowed_apps_count
      }
    }')
else
  echo "Could not retrieve admin settings."
  ADMIN_SETTINGS=$(jq -n '{
    "who_can_create_channels": "UNKNOWN",
    "who_can_archive_channels": "UNKNOWN",
    "who_can_create_shared_channels": "UNKNOWN",
    "who_can_create_private_channels": "UNKNOWN",
    "who_can_delete_messages": "UNKNOWN",
    "who_can_edit_messages": "UNKNOWN",
    "who_can_invite_to_workspace": "UNKNOWN",
    "who_can_install_apps": "UNKNOWN",
    "app_directory_restrictions": {
      "app_directory_enabled": false,
      "restricted_apps_count": 0,
      "allowed_apps_count": 0
    }
  }')
fi

# Save admin settings
echo "${ADMIN_SETTINGS}" > "${RAW_CONFIG_DIR}/admin_settings.json"

# Audit workspace settings
echo "Auditing workspace settings..."
TEAM_INFO=$(make_api_request "team.info")
ACCESS_LOGS=$(make_api_request "team.accessLogs" "count=100")
WORKSPACE_SETTINGS="{}"

if [ "$(echo "${TEAM_INFO}" | jq -r '.ok')" == "true" ]; then
  TEAM=$(echo "${TEAM_INFO}" | jq -r '.team')
  TEAM_ID=$(echo "${TEAM}" | jq -r '.id')
  TEAM_NAME=$(echo "${TEAM}" | jq -r '.name')
  TEAM_DOMAIN=$(echo "${TEAM}" | jq -r '.domain')
  EMAIL_DOMAIN=$(echo "${TEAM}" | jq -r '.email_domain')
  TEAM_CREATED=$(echo "${TEAM}" | jq -r '.created')
  
  # Check access logs
  HAS_ACCESS_LOGS=$(echo "${ACCESS_LOGS}" | jq -r '.ok')
  ACCESS_LOGS_COUNT=$(echo "${ACCESS_LOGS}" | jq -r '.logins | length // 0')
  
  # Get default channels
  CHANNELS_RESPONSE=$(make_api_request "conversations.list" "exclude_archived=true&types=public_channel")
  DEFAULT_CHANNELS=$(echo "${CHANNELS_RESPONSE}" | jq -r '.channels[] | select(.is_general == true) | {id: .id, name: .name, is_general: .is_general, created: .created}')
  
  # Construct workspace settings JSON
  WORKSPACE_SETTINGS=$(jq -n \
    --arg team_id "${TEAM_ID}" \
    --arg team_name "${TEAM_NAME}" \
    --arg team_domain "${TEAM_DOMAIN}" \
    --arg email_domain "${EMAIL_DOMAIN}" \
    --argjson created "${TEAM_CREATED}" \
    --argjson has_access_logs "${HAS_ACCESS_LOGS}" \
    --argjson access_logs_count "${ACCESS_LOGS_COUNT}" \
    --argjson default_channels "[${DEFAULT_CHANNELS}]" \
    '{
      "team_id": $team_id,
      "team_name": $team_name,
      "team_domain": $team_domain,
      "email_domain": $email_domain,
      "workspace_creation_date": $created,
      "has_access_logs": $has_access_logs,
      "access_logs_count": $access_logs_count,
      "default_channels": $default_channels
    }')
else
  echo "Could not retrieve workspace information."
  WORKSPACE_SETTINGS=$(jq -n '{
    "team_id": "unknown",
    "team_name": "unknown",
    "team_domain": "unknown",
    "email_domain": "unknown",
    "workspace_creation_date": 0,
    "has_access_logs": false,
    "access_logs_count": 0,
    "default_channels": []
  }')
fi

# Save workspace settings
echo "${WORKSPACE_SETTINGS}" > "${RAW_CONFIG_DIR}/workspace_settings.json"

# Audit user settings
echo "Auditing user settings and 2FA enforcement..."
USERS_RESPONSE=$(make_api_request "users.list" "limit=1000")
USER_SETTINGS="{}"

if [ "$(echo "${USERS_RESPONSE}" | jq -r '.ok')" == "true" ]; then
  USERS=$(echo "${USERS_RESPONSE}" | jq -r '.members')
  TOTAL_USERS=$(echo "${USERS}" | jq -r '. | length')
  ADMIN_COUNT=$(echo "${USERS}" | jq -r '[.[] | select(.is_admin == true)] | length')
  OWNER_COUNT=$(echo "${USERS}" | jq -r '[.[] | select(.is_owner == true)] | length')
  BOT_COUNT=$(echo "${USERS}" | jq -r '[.[] | select(.is_bot == true)] | length')
  
  # Check 2FA enforcement
  TWO_FACTOR_REQUIRED=$(echo "${TEAM_INFO}" | jq -r '.team.two_factor_auth_required // false')
  TWO_FACTOR_ENABLED_COUNT=$(echo "${USERS}" | jq -r '[.[] | select(.has_2fa == true)] | length')
  
  # Calculate percentage (excluding bots)
  HUMAN_USERS=$((TOTAL_USERS - BOT_COUNT))
  if [ "${HUMAN_USERS}" -gt 0 ]; then
    TWO_FACTOR_PERCENTAGE=$(echo "scale=1; ${TWO_FACTOR_ENABLED_COUNT} * 100 / ${HUMAN_USERS}" | bc)
  else
    TWO_FACTOR_PERCENTAGE=0
  fi
  
  # Construct user settings JSON
  USER_SETTINGS=$(jq -n \
    --argjson total_users "${TOTAL_USERS}" \
    --argjson admin_count "${ADMIN_COUNT}" \
    --argjson owner_count "${OWNER_COUNT}" \
    --argjson bot_count "${BOT_COUNT}" \
    --argjson two_factor_required "${TWO_FACTOR_REQUIRED}" \
    --argjson two_factor_enabled_count "${TWO_FACTOR_ENABLED_COUNT}" \
    --argjson two_factor_percentage "${TWO_FACTOR_PERCENTAGE}" \
    '{
      "total_users": $total_users,
      "admin_count": $admin_count,
      "owner_count": $owner_count,
      "bot_count": $bot_count,
      "two_factor_auth_required": $two_factor_required,
      "two_factor_enabled_count": $two_factor_enabled_count,
      "two_factor_enabled_percentage": $two_factor_percentage
    }')
else
  echo "Could not retrieve user information."
  USER_SETTINGS=$(jq -n '{
    "total_users": 0,
    "admin_count": 0,
    "owner_count": 0,
    "bot_count": 0,
    "two_factor_auth_required": false,
    "two_factor_enabled_count": 0,
    "two_factor_enabled_percentage": 0
  }')
fi

# Save user settings
echo "${USER_SETTINGS}" > "${RAW_CONFIG_DIR}/user_settings.json"

# Audit app integrations
echo "Auditing app integrations..."
APPS_RESPONSE=$(make_api_request "apps.list")
APP_SETTINGS="{}"

if [ "$(echo "${APPS_RESPONSE}" | jq -r '.ok')" == "true" ]; then
  APPS=$(echo "${APPS_RESPONSE}" | jq -r '.apps')
  TOTAL_APPS=$(echo "${APPS}" | jq -r '. | length')
  
  # Count apps by category
  APP_CATEGORIES=$(echo "${APPS}" | jq -r 'group_by(.category) | map({key: .[0].category, value: length}) | from_entries')
  
  # Identify risky apps
  RISKY_APPS=$(echo "${APPS}" | jq -r '[.[] | select(.scopes | arrays | any(. == "channels:history" or . == "channels:read" or . == "chat:write" or . == "files:read" or . == "files:write" or . == "im:history" or . == "im:read" or . == "im:write" or . == "users:read" or . == "users:write" or . == "admin")) | {id: .id, name: .name, scopes: .scopes}]')
  RISKY_APPS_COUNT=$(echo "${RISKY_APPS}" | jq -r '. | length')
  
  # Construct app settings JSON
  APP_SETTINGS=$(jq -n \
    --argjson total_apps "${TOTAL_APPS}" \
    --argjson app_categories "${APP_CATEGORIES}" \
    --argjson risky_apps_count "${RISKY_APPS_COUNT}" \
    --argjson risky_apps "${RISKY_APPS}" \
    '{
      "total_apps": $total_apps,
      "app_categories": $app_categories,
      "risky_apps_count": $risky_apps_count,
      "risky_apps": $risky_apps
    }')
else
  echo "Could not retrieve app information."
  APP_SETTINGS=$(jq -n '{
    "total_apps": 0,
    "app_categories": {},
    "risky_apps_count": 0,
    "risky_apps": []
  }')
fi

# Save app settings
echo "${APP_SETTINGS}" > "${RAW_CONFIG_DIR}/app_settings.json"

# Audit retention policies
echo "Auditing retention policies..."
RETENTION_RESPONSE=$(make_api_request "admin.conversations.restrictAccess.getInfo")
RETENTION_SETTINGS="{}"

if [ "$(echo "${RETENTION_RESPONSE}" | jq -r '.ok')" == "true" ]; then
  POLICY=$(echo "${RETENTION_RESPONSE}" | jq -r '.policy')
  HAS_RETENTION_POLICY=true
  RETENTION_DURATION_DAYS=$(echo "${POLICY}" | jq -r '.duration_days')
  DEFAULT_POLICY=$(echo "${POLICY}" | jq -r '.type')
  
  # Construct retention settings JSON
  RETENTION_SETTINGS=$(jq -n \
    --argjson has_retention_policy "${HAS_RETENTION_POLICY}" \
    --argjson retention_duration_days "${RETENTION_DURATION_DAYS}" \
    --arg default_policy "${DEFAULT_POLICY}" \
    '{
      "has_retention_policy": $has_retention_policy,
      "retention_duration_days": $retention_duration_days,
      "default_policy": $default_policy
    }')
else
  echo "Could not retrieve retention policy information."
  RETENTION_SETTINGS=$(jq -n '{
    "has_retention_policy": false,
    "retention_duration_days": null,
    "default_policy": "unknown"
  }')
fi

# Save retention settings
echo "${RETENTION_SETTINGS}" > "${RAW_CONFIG_DIR}/retention_settings.json"

# Analyze compliance with NIST 800-53 controls
echo "Analyzing compliance with NIST 800-53 controls..."

# Function to evaluate compliance for each control
function check_compliance {
  local control="$1"
  local title="$2"
  local criteria="$3"
  local findings_json="$4"
  local recommendations_json="$5"
  
  local compliant=false
  if [ "${criteria}" == "true" ]; then
    compliant=true
  fi
  
  jq -n \
    --arg control "${control}" \
    --arg title "${title}" \
    --argjson compliant "${compliant}" \
    --argjson findings "${findings_json}" \
    --argjson recommendations "${recommendations_json}" \
    '{
      "control": $control,
      "title": $title,
      "compliant": $compliant,
      "findings": $findings,
      "recommendations": $recommendations
    }'
}

# Check AC-2: Account Management
WHO_CAN_INVITE=$(echo "${ADMIN_SETTINGS}" | jq -r '.who_can_invite_to_workspace')
INVITE_RESTRICTION=$([ "${WHO_CAN_INVITE}" == "ADMIN_ONLY" ] && echo "true" || echo "false")
HAS_ACCESS_LOGS=$(echo "${WORKSPACE_SETTINGS}" | jq -r '.has_access_logs')
ADMIN_COUNT=$(echo "${USER_SETTINGS}" | jq -r '.admin_count')
TOTAL_USERS=$(echo "${USER_SETTINGS}" | jq -r '.total_users')
AC2_CRITERIA=$([ "${INVITE_RESTRICTION}" == "true" ] && [ "${HAS_ACCESS_LOGS}" == "true" ] && echo "true" || echo "false")
AC2_FINDINGS=$(jq -n \
  --argjson invite_restriction "${INVITE_RESTRICTION}" \
  --argjson has_access_logs "${HAS_ACCESS_LOGS}" \
  --argjson admin_count "${ADMIN_COUNT}" \
  --argjson total_users "${TOTAL_USERS}" \
  '{
    "invite_restriction": $invite_restriction,
    "has_access_logs": $has_access_logs,
    "admin_count": $admin_count,
    "total_users": $total_users
  }')
AC2_RECOMMENDATIONS=$(jq -n \
  --argjson invite_restriction "${INVITE_RESTRICTION}" \
  --argjson has_access_logs "${HAS_ACCESS_LOGS}" \
  '[
    if $invite_restriction == false then "Restrict user invitations to admins only" else null end,
    if $has_access_logs == false then "Enable access logs to track account creation and deletion" else null end
  ] | map(select(. != null))')

AC2_COMPLIANCE=$(check_compliance "AC-2" "Account Management" "${AC2_CRITERIA}" "${AC2_FINDINGS}" "${AC2_RECOMMENDATIONS}")

# Check AC-3: Access Enforcement
WHO_CAN_CREATE_CHANNELS=$(echo "${ADMIN_SETTINGS}" | jq -r '.who_can_create_channels')
WHO_CAN_CREATE_PRIVATE_CHANNELS=$(echo "${ADMIN_SETTINGS}" | jq -r '.who_can_create_private_channels')
WHO_CAN_DELETE_MESSAGES=$(echo "${ADMIN_SETTINGS}" | jq -r '.who_can_delete_messages')
WHO_CAN_EDIT_MESSAGES=$(echo "${ADMIN_SETTINGS}" | jq -r '.who_can_edit_messages')

CHANNEL_CREATION_RESTRICTED=$([ "${WHO_CAN_CREATE_CHANNELS}" == "ADMIN_ONLY" ] || [ "${WHO_CAN_CREATE_CHANNELS}" == "SPECIFIC_USERS" ] && echo "true" || echo "false")
PRIVATE_CHANNEL_CREATION_RESTRICTED=$([ "${WHO_CAN_CREATE_PRIVATE_CHANNELS}" == "ADMIN_ONLY" ] || [ "${WHO_CAN_CREATE_PRIVATE_CHANNELS}" == "SPECIFIC_USERS" ] && echo "true" || echo "false")
MESSAGE_DELETION_RESTRICTED=$([ "${WHO_CAN_DELETE_MESSAGES}" == "ADMIN_ONLY" ] || [ "${WHO_CAN_DELETE_MESSAGES}" == "SPECIFIC_USERS" ] && echo "true" || echo "false")
MESSAGE_EDITING_RESTRICTED=$([ "${WHO_CAN_EDIT_MESSAGES}" == "ADMIN_ONLY" ] || [ "${WHO_CAN_EDIT_MESSAGES}" == "SPECIFIC_USERS" ] && echo "true" || echo "false")

AC3_CRITERIA=$([ "${CHANNEL_CREATION_RESTRICTED}" == "true" ] && 
               [ "${PRIVATE_CHANNEL_CREATION_RESTRICTED}" == "true" ] && 
               [ "${MESSAGE_DELETION_RESTRICTED}" == "true" ] && 
               [ "${MESSAGE_EDITING_RESTRICTED}" == "true" ] && 
               echo "true" || echo "false")

AC3_FINDINGS=$(jq -n \
  --argjson channel_creation_restricted "${CHANNEL_CREATION_RESTRICTED}" \
  --argjson private_channel_creation_restricted "${PRIVATE_CHANNEL_CREATION_RESTRICTED}" \
  --argjson message_deletion_restricted "${MESSAGE_DELETION_RESTRICTED}" \
  --argjson message_editing_restricted "${MESSAGE_EDITING_RESTRICTED}" \
  '{
    "channel_creation_restricted": $channel_creation_restricted,
    "private_channel_creation_restricted": $private_channel_creation_restricted,
    "message_deletion_restricted": $message_deletion_restricted,
    "message_editing_restricted": $message_editing_restricted
  }')

AC3_RECOMMENDATIONS=$(jq -n \
  --argjson channel_creation_restricted "${CHANNEL_CREATION_RESTRICTED}" \
  --argjson private_channel_creation_restricted "${PRIVATE_CHANNEL_CREATION_RESTRICTED}" \
  --argjson message_deletion_restricted "${MESSAGE_DELETION_RESTRICTED}" \
  --argjson message_editing_restricted "${MESSAGE_EDITING_RESTRICTED}" \
  '[
    if $channel_creation_restricted == false then "Restrict public channel creation to admins only" else null end,
    if $private_channel_creation_restricted == false then "Restrict private channel creation to admins only" else null end,
    if $message_deletion_restricted == false then "Restrict message deletion to admins only" else null end,
    if $message_editing_restricted == false then "Restrict message editing to admins only" else null end
  ] | map(select(. != null))')

AC3_COMPLIANCE=$(check_compliance "AC-3" "Access Enforcement" "${AC3_CRITERIA}" "${AC3_FINDINGS}" "${AC3_RECOMMENDATIONS}")

# Check AC-7: Unsuccessful Login Attempts (Slack handles automatically)
AC7_CRITERIA="true"
AC7_FINDINGS=$(jq -n '{
  "note": "Slack automatically implements account lockout after multiple failed login attempts"
}')
AC7_RECOMMENDATIONS=$(jq -n '[]')

AC7_COMPLIANCE=$(check_compliance "AC-7" "Unsuccessful Login Attempts" "${AC7_CRITERIA}" "${AC7_FINDINGS}" "${AC7_RECOMMENDATIONS}")

# More controls could be added here...

# Combine all compliance findings into a single JSON
COMPLIANCE_FINDINGS=$(jq -n \
  --argjson ac2 "${AC2_COMPLIANCE}" \
  --argjson ac3 "${AC3_COMPLIANCE}" \
  --argjson ac7 "${AC7_COMPLIANCE}" \
  '{
    "AC-2": $ac2,
    "AC-3": $ac3,
    "AC-7": $ac7
  }')

# Save compliance findings
echo "${COMPLIANCE_FINDINGS}" > "${RAW_CONFIG_DIR}/compliance_findings.json"

# Combine all results into a single JSON
ALL_RESULTS=$(jq -n \
  --arg audit_date "$(date -u +"%Y-%m-%dT%H:%M:%SZ")" \
  --argjson enterprise "${ENTERPRISE_SETTINGS}" \
  --argjson admin "${ADMIN_SETTINGS}" \
  --argjson workspace "${WORKSPACE_SETTINGS}" \
  --argjson users "${USER_SETTINGS}" \
  --argjson apps "${APP_SETTINGS}" \
  --argjson retention "${RETENTION_SETTINGS}" \
  --argjson compliance "${COMPLIANCE_FINDINGS}" \
  '{
    "metadata": {
      "audit_date": $audit_date,
      "tool_version": "1.0.0"
    },
    "configurations": {
      "enterprise": $enterprise,
      "admin": $admin,
      "workspace": $workspace,
      "users": $users,
      "apps": $apps,
      "retention": $retention
    },
    "compliance": $compliance,
    "recommendations": []
  }')

# Extract recommendations
RECOMMENDATIONS=$(jq -r '.compliance[] | select(.recommendations != null) | .recommendations[] | select(. != null) | "\(.control): \(.)"' <<< "${COMPLIANCE_FINDINGS}" | jq -R -s 'split("\n") | map(select(length > 0))')

# Add recommendations to results
ALL_RESULTS=$(jq --argjson recs "${RECOMMENDATIONS}" '.recommendations = $recs' <<< "${ALL_RESULTS}")

# Save complete results
JSON_OUTPUT="${RESULTS_DIR}/slack_audit_${TIMESTAMP}.json"
echo "${ALL_RESULTS}" > "${JSON_OUTPUT}"
echo "Full audit results saved to: ${JSON_OUTPUT}"

# Generate summary report
echo "Generating summary report..."
MARKDOWN_OUTPUT="${RESULTS_DIR}/slack_audit_summary_${TIMESTAMP}.md"

# Extract values for summary
TEAM_NAME=$(echo "${WORKSPACE_SETTINGS}" | jq -r '.team_name')
TEAM_DOMAIN=$(echo "${WORKSPACE_SETTINGS}" | jq -r '.team_domain')
TOTAL_USERS=$(echo "${USER_SETTINGS}" | jq -r '.total_users')

# Calculate compliance score
TOTAL_CONTROLS=$(echo "${COMPLIANCE_FINDINGS}" | jq -r 'keys | length')
COMPLIANT_CONTROLS=$(echo "${COMPLIANCE_FINDINGS}" | jq -r '[.[] | select(.compliant == true)] | length')
COMPLIANCE_PERCENTAGE=$(echo "scale=1; ${COMPLIANT_CONTROLS} * 100 / ${TOTAL_CONTROLS}" | bc)

# Create summary report
cat > "${MARKDOWN_OUTPUT}" << EOF
# Slack FedRAMP Compliance Audit Summary

**Audit Date:** $(date +"%Y-%m-%d %H:%M:%S")

## Workspace Information

- **Workspace Name:** ${TEAM_NAME}
- **Workspace Domain:** ${TEAM_DOMAIN}
- **Total Users:** ${TOTAL_USERS}

## Compliance Summary

- **Compliance Score:** ${COMPLIANCE_PERCENTAGE}% (${COMPLIANT_CONTROLS}/${TOTAL_CONTROLS} controls)

## Control Compliance Details

EOF

# Add control details to summary
for control in $(echo "${COMPLIANCE_FINDINGS}" | jq -r 'keys[]' | sort); do
  CONTROL_DATA=$(echo "${COMPLIANCE_FINDINGS}" | jq -r ".[\"${control}\"]")
  TITLE=$(echo "${CONTROL_DATA}" | jq -r '.title')
  COMPLIANT=$(echo "${CONTROL_DATA}" | jq -r '.compliant')
  
  if [ "${COMPLIANT}" == "true" ]; then
    STATUS="✅"
  else
    STATUS="❌"
  fi
  
  echo "### ${STATUS} ${control}: ${TITLE}" >> "${MARKDOWN_OUTPUT}"
  echo "" >> "${MARKDOWN_OUTPUT}"
  
  # Add findings if not compliant
  if [ "${COMPLIANT}" != "true" ]; then
    echo "**Findings:**" >> "${MARKDOWN_OUTPUT}"
    echo "" >> "${MARKDOWN_OUTPUT}"
    
    echo "${CONTROL_DATA}" | jq -r '.findings | to_entries[] | "- \(.key | gsub("_"; " ") | ascii_upcase | gsub("^."; .[:1] | ascii_upcase) + .[:1:]): \(.value)"' >> "${MARKDOWN_OUTPUT}"
    echo "" >> "${MARKDOWN_OUTPUT}"
    
    # Add recommendations
    RECOMMENDATIONS=$(echo "${CONTROL_DATA}" | jq -r '.recommendations[]')
    if [ -n "${RECOMMENDATIONS}" ]; then
      echo "**Recommendations:**" >> "${MARKDOWN_OUTPUT}"
      echo "" >> "${MARKDOWN_OUTPUT}"
      echo "${CONTROL_DATA}" | jq -r '.recommendations[] | "- \(.)"' >> "${MARKDOWN_OUTPUT}"
      echo "" >> "${MARKDOWN_OUTPUT}"
    fi
  fi
done

# Add overall recommendations
echo "## Overall Recommendations" >> "${MARKDOWN_OUTPUT}"
echo "" >> "${MARKDOWN_OUTPUT}"
echo "${ALL_RESULTS}" | jq -r '.recommendations[] | "- \(.)"' >> "${MARKDOWN_OUTPUT}"

echo "Summary report saved to: ${MARKDOWN_OUTPUT}"
echo "Audit completed. Results saved to ${RESULTS_DIR}"