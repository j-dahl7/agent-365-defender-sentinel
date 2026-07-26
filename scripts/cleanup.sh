#!/usr/bin/env bash
# Safely tears down only provenance-verified Agent 365 lab resources.
#
# Optional controls:
#   STATE_FILE - deployment manifest (default: <lab>/.agent365-lab-state.json)
#   PLAN_ONLY  - true performs all ownership reads but no deletions
#
# The state file is intentionally retained after cleanup so an interrupted or
# asynchronous resource-group deletion can be verified and safely retried.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
STATE_FILE="${STATE_FILE:-$LAB_DIR/.agent365-lab-state.json}"
PLAN_ONLY="${PLAN_ONLY:-false}"
OWNER_MARKER='nine-lives-zero-trust:agent-365-defender-sentinel:v1'
OWNER_TAG='nlzt-owner'
DEPLOYMENT_TAG='nlzt-deployment'
RULE_API_VERSION='2024-03-01'

EXPECTED_RULE_IDS=(
  agent365-jailbreak-burst
  agent365-xpia-ascii-smuggling
  agent365-instruction-leak
  agent365-credential-data-leak
  agent365-anomalous-tool-invocation
)
EXPECTED_RULE_NAMES=(
  'LAB - Agent Jailbreak Attempts (burst)'
  'LAB - Indirect Prompt Injection (XPIA/ASCII Smuggling) on AI Agent'
  'LAB - AI Agent Instruction Leak / Reconnaissance'
  'LAB - AI Agent Exposed Credentials or Sensitive Data'
  'LAB - AI Agent Anomalous Tool Invocation or Volume Anomaly'
)

fail() {
  echo "ERROR: $*" >&2
  exit 2
}

normalize_id() {
  printf '%s' "${1%/}" | tr '[:upper:]' '[:lower:]'
}

for command_name in az jq; do
  command -v "$command_name" >/dev/null 2>&1 || fail "Required command '$command_name' was not found."
done

case "$PLAN_ONLY" in
  true|false) ;;
  *) fail 'PLAN_ONLY must be true or false.' ;;
esac

[ -f "$STATE_FILE" ] || fail "Deployment provenance file '$STATE_FILE' is required. Refusing name-based cleanup."

RULE_IDS_JSON="$(printf '%s\n' "${EXPECTED_RULE_IDS[@]}" | jq -R . | jq -s .)"
RULE_NAMES_JSON="$(printf '%s\n' "${EXPECTED_RULE_NAMES[@]}" | jq -R . | jq -s .)"
jq -e \
  --arg owner "$OWNER_MARKER" \
  --argjson rule_ids "$RULE_IDS_JSON" \
  --argjson rule_names "$RULE_NAMES_JSON" \
  '
    .schema_version == 1 and
    .owner_marker == $owner and
    (.deployment_id | type == "string" and length >= 16) and
    (.tenant_id | type == "string" and length > 0) and
    (.subscription_id | type == "string" and length > 0) and
    (.resource_group_name | type == "string" and length > 0) and
    (.resource_group_id | type == "string" and length > 0) and
    (.sentinel_workspace_id | type == "string" and length > 0) and
    .rule_ids == $rule_ids and
    .rule_display_names == $rule_names
  ' "$STATE_FILE" >/dev/null || fail "Deployment provenance file '$STATE_FILE' is incomplete or incompatible."

DEPLOYMENT_ID="$(jq -er '.deployment_id' "$STATE_FILE")"
TENANT_ID="$(jq -er '.tenant_id' "$STATE_FILE")"
SUBSCRIPTION_ID="$(jq -er '.subscription_id' "$STATE_FILE")"
RESOURCE_GROUP="$(jq -er '.resource_group_name' "$STATE_FILE")"
RESOURCE_GROUP_ID="$(jq -er '.resource_group_id' "$STATE_FILE")"
SENTINEL_WS_ID="$(jq -er '.sentinel_workspace_id' "$STATE_FILE")"

ACCOUNT_JSON="$(az account show --output json)"
ACTIVE_SUBSCRIPTION_ID="$(jq -er '.id' <<< "$ACCOUNT_JSON")"
ACTIVE_TENANT_ID="$(jq -er '.tenantId' <<< "$ACCOUNT_JSON")"
[ "$(normalize_id "$ACTIVE_SUBSCRIPTION_ID")" = "$(normalize_id "$SUBSCRIPTION_ID")" ] || fail "Active subscription '$ACTIVE_SUBSCRIPTION_ID' does not match deployment subscription '$SUBSCRIPTION_ID'."
[ "$(normalize_id "$ACTIVE_TENANT_ID")" = "$(normalize_id "$TENANT_ID")" ] || fail "Active tenant '$ACTIVE_TENANT_ID' does not match deployment tenant '$TENANT_ID'."

EXPECTED_RG_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"
[ "$(normalize_id "$RESOURCE_GROUP_ID")" = "$(normalize_id "$EXPECTED_RG_ID")" ] || fail 'Recorded resource-group ID is inconsistent with its subscription and name.'

RG_EXISTS="$(az group exists --name "$RESOURCE_GROUP" --subscription "$SUBSCRIPTION_ID" -o tsv)"
case "$RG_EXISTS" in
  true|false) ;;
  *) fail "Could not determine whether resource group '$RESOURCE_GROUP' exists." ;;
esac
if [ "$RG_EXISTS" = 'true' ]; then
  RG_JSON="$(az group show --name "$RESOURCE_GROUP" --subscription "$SUBSCRIPTION_ID" --output json)"
  ACTUAL_RG_ID="$(jq -er '.id' <<< "$RG_JSON")"
  ACTUAL_OWNER="$(jq -r --arg key "$OWNER_TAG" '.tags[$key] // empty' <<< "$RG_JSON")"
  ACTUAL_DEPLOYMENT="$(jq -r --arg key "$DEPLOYMENT_TAG" '.tags[$key] // empty' <<< "$RG_JSON")"
  [ "$(normalize_id "$ACTUAL_RG_ID")" = "$(normalize_id "$RESOURCE_GROUP_ID")" ] || fail 'Live resource-group ID does not match the deployment manifest.'
  [ "$ACTUAL_OWNER" = "$OWNER_MARKER" ] || fail 'Live resource group is missing the exact lab ownership tag.'
  [ "$ACTUAL_DEPLOYMENT" = "$DEPLOYMENT_ID" ] || fail 'Live resource group is missing the exact deployment provenance tag.'
fi

if [ -n "${PURGE_KEYVAULT_NAME:-}" ] && [ "$RG_EXISTS" = 'true' ]; then
  fail 'Key Vault purge is only allowed after the owned resource group is confirmed absent. Run cleanup without PURGE_KEYVAULT_NAME, wait for deletion, then rerun with the exact purge confirmation.'
fi
if [ -n "${PURGE_KEYVAULT_NAME:-}" ] && [ "${CONFIRM_KEYVAULT_PURGE:-}" != "$PURGE_KEYVAULT_NAME" ]; then
  fail 'CONFIRM_KEYVAULT_PURGE must exactly equal PURGE_KEYVAULT_NAME.'
fi

echo 'Preflighting all exact Sentinel rule IDs before deletion...'
RULES_URL="$SENTINEL_WS_ID/providers/Microsoft.SecurityInsights/alertRules?api-version=$RULE_API_VERSION"

fetch_all_rules() {
  local page_url="$RULES_URL"
  local page_json page_values next_url
  local all_values='[]'
  local page_count=0

  while [ -n "$page_url" ]; do
    page_count=$((page_count + 1))
    [ "$page_count" -le 100 ] || fail 'Sentinel analytics-rule pagination exceeded 100 pages.'
    page_json="$(az rest --method GET --url "$page_url" --output json)"
    jq -e '.value | type == "array"' <<< "$page_json" >/dev/null || fail 'Sentinel returned an invalid analytics-rule inventory page.'
    page_values="$(jq -c '.value' <<< "$page_json")"
    all_values="$(jq -cn --argjson existing "$all_values" --argjson page "$page_values" '$existing + $page')"
    next_url="$(jq -r '.nextLink // empty' <<< "$page_json")"
    [ "$next_url" != "$page_url" ] || fail 'Sentinel returned a repeating analytics-rule nextLink.'
    page_url="$next_url"
  done

  jq -cn --argjson value "$all_values" '{value: $value}'
}

RULES_JSON="$(fetch_all_rules)"

OWNED_RULE_IDS=()
for index in "${!EXPECTED_RULE_IDS[@]}"; do
  rule_id="${EXPECTED_RULE_IDS[$index]}"
  expected_name="${EXPECTED_RULE_NAMES[$index]}"
  ownership_text="[Owner: $OWNER_MARKER; Deployment: $DEPLOYMENT_ID]"
  id_count="$(jq --arg id "$rule_id" '[.value[] | select((.name // "") == $id)] | length' <<< "$RULES_JSON")"
  [ "$id_count" -le 1 ] || fail "Sentinel returned duplicate resources for rule ID '$rule_id'."
  if [ "$id_count" -eq 0 ]; then
    echo "  Already absent: $rule_id"
    continue
  fi

  actual_name="$(jq -r --arg id "$rule_id" '.value[] | select(.name == $id) | .properties.displayName // ""' <<< "$RULES_JSON")"
  actual_description="$(jq -r --arg id "$rule_id" '.value[] | select(.name == $id) | .properties.description // ""' <<< "$RULES_JSON")"
  [ "$actual_name" = "$expected_name" ] || fail "Rule '$rule_id' has an unexpected display name. No resources were deleted."
  [[ "$actual_description" == *"$ownership_text"* ]] || fail "Rule '$rule_id' is not owned by deployment '$DEPLOYMENT_ID'. No resources were deleted."
  OWNED_RULE_IDS+=("$rule_id")
done

if [ "$PLAN_ONLY" = 'true' ]; then
  cat <<PLAN

Ownership preflight passed. PLAN_ONLY=true; no resources were deleted.
Deployment ID:       $DEPLOYMENT_ID
Owned rules present: ${#OWNED_RULE_IDS[@]}
Owned resource group present: $RG_EXISTS
State retained:      $STATE_FILE
PLAN
  exit 0
fi

for rule_id in "${OWNED_RULE_IDS[@]}"; do
  echo "Deleting owned analytics rule: $rule_id"
  az rest --method DELETE \
    --url "$SENTINEL_WS_ID/providers/Microsoft.SecurityInsights/alertRules/$rule_id?api-version=$RULE_API_VERSION" \
    --output none
done

if [ "${#OWNED_RULE_IDS[@]}" -gt 0 ]; then
  for attempt in 1 2 3 4 5; do
    RULES_JSON="$(fetch_all_rules)"
    remaining=0
    for rule_id in "${OWNED_RULE_IDS[@]}"; do
      if [ "$(jq --arg id "$rule_id" '[.value[] | select((.name // "") == $id)] | length' <<< "$RULES_JSON")" -ne 0 ]; then
        remaining=$((remaining + 1))
      fi
    done
    [ "$remaining" -eq 0 ] && break
    [ "$attempt" -lt 5 ] && sleep 2
  done
  [ "$remaining" -eq 0 ] || fail 'One or more Sentinel rules still exist after delete requests; resource-group deletion was not started.'
fi

if [ "$RG_EXISTS" = 'true' ]; then
  echo "Deleting exact owned resource group asynchronously: $RESOURCE_GROUP_ID"
  az group delete \
    --name "$RESOURCE_GROUP" \
    --subscription "$SUBSCRIPTION_ID" \
    --yes --no-wait
else
  echo "Owned resource group is already absent: $RESOURCE_GROUP_ID"
fi

if [ -n "${PURGE_KEYVAULT_NAME:-}" ]; then
  echo "Purging explicitly confirmed soft-deleted Key Vault: $PURGE_KEYVAULT_NAME"
  az keyvault purge --name "$PURGE_KEYVAULT_NAME" --subscription "$SUBSCRIPTION_ID" --only-show-errors
fi

cat <<SUMMARY

Cleanup requests completed for provenance-verified resources only.
The state file remains at '$STATE_FILE' for async deletion verification and safe retry.
SUMMARY
