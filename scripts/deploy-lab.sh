#!/usr/bin/env bash
# One-shot deploy for the Agent 365 Defender lab.
#
# Required env vars:
#   SENTINEL_WS_ID   - resource ID of your Sentinel-onboarded Log Analytics workspace
#   RESOURCE_GROUP   - target RG (default: agent365-lab-rg)
#   LOCATION         - Azure region (default: eastus2)
#   CONFIRM_SUBSCRIPTION_SCOPE - set to ENABLE-DEFENDER-FOR-AI-SERVICES only
#                                when the paid Standard plan is not already active
# Optional safety controls:
#   STATE_FILE       - deployment provenance file (default: <lab>/.agent365-lab-state.json)
#   PLAN_ONLY        - true performs all ownership/collision reads and no mutations

set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-agent365-lab-rg}"
LOCATION="${LOCATION:-eastus2}"
PLAN_ONLY="${PLAN_ONLY:-false}"
: "${SENTINEL_WS_ID:?Set SENTINEL_WS_ID to your Sentinel workspace resource ID}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"
STATE_FILE="${STATE_FILE:-$LAB_DIR/.agent365-lab-state.json}"
OWNER_MARKER='nine-lives-zero-trust:agent-365-defender-sentinel:v1'
OWNER_TAG='nlzt-owner'
DEPLOYMENT_TAG='nlzt-deployment'
RULE_API_VERSION='2024-03-01'

RULE_IDS=(
  agent365-jailbreak-burst
  agent365-xpia-ascii-smuggling
  agent365-instruction-leak
  agent365-credential-data-leak
  agent365-anomalous-tool-invocation
)
RULE_DISPLAY_NAMES=(
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

for command_name in az jq python3; do
  command -v "$command_name" >/dev/null 2>&1 || fail "Required command '$command_name' was not found."
done

case "$PLAN_ONLY" in
  true|false) ;;
  *) fail 'PLAN_ONLY must be true or false.' ;;
esac

SENTINEL_WS_ID="${SENTINEL_WS_ID%/}"
IFS='/' read -r -a workspace_parts <<< "${SENTINEL_WS_ID#/}"
if [ "${#workspace_parts[@]}" -ne 8 ] ||
   [ "${workspace_parts[0],,}" != 'subscriptions' ] ||
   [ "${workspace_parts[2],,}" != 'resourcegroups' ] ||
   [ "${workspace_parts[4],,}" != 'providers' ] ||
   [ "${workspace_parts[5],,}" != 'microsoft.operationalinsights' ] ||
   [ "${workspace_parts[6],,}" != 'workspaces' ]; then
  fail 'SENTINEL_WS_ID must be an exact Log Analytics workspace resource ID.'
fi
WORKSPACE_SUBSCRIPTION_ID="${workspace_parts[1]}"
WORKSPACE_RG="${workspace_parts[3]}"
WORKSPACE_NAME="${workspace_parts[7]}"

echo '=== [0/8] Reading account, billing, and ownership state ==='
ACCOUNT_JSON="$(az account show --output json)"
SUBSCRIPTION_ID="$(jq -er '.id | strings | select(length > 0)' <<< "$ACCOUNT_JSON")"
TENANT_ID="$(jq -er '.tenantId | strings | select(length > 0)' <<< "$ACCOUNT_JSON")"
if [ "$(normalize_id "$WORKSPACE_SUBSCRIPTION_ID")" != "$(normalize_id "$SUBSCRIPTION_ID")" ]; then
  fail "The Sentinel workspace belongs to subscription '$WORKSPACE_SUBSCRIPTION_ID', but Azure CLI is using '$SUBSCRIPTION_ID'."
fi

if ! CURRENT_TIER="$(az security pricing show --name AI --subscription "$SUBSCRIPTION_ID" --query pricingTier -o tsv 2>/dev/null)"; then
  fail 'Unable to determine the Defender for AI Services pricing tier; no changes were made.'
fi
[ -n "$CURRENT_TIER" ] || fail 'Defender for AI Services returned an empty pricing tier; no changes were made.'

RULE_IDS_JSON="$(printf '%s\n' "${RULE_IDS[@]}" | jq -R . | jq -s .)"
RULE_NAMES_JSON="$(printf '%s\n' "${RULE_DISPLAY_NAMES[@]}" | jq -R . | jq -s .)"
EXPECTED_RG_ID="/subscriptions/$SUBSCRIPTION_ID/resourceGroups/$RESOURCE_GROUP"
RG_EXISTS="$(az group exists --name "$RESOURCE_GROUP" --subscription "$SUBSCRIPTION_ID" -o tsv)"
case "$RG_EXISTS" in
  true|false) ;;
  *) fail "Could not determine whether resource group '$RESOURCE_GROUP' exists." ;;
esac

STATE_VERIFIED=false
NEW_RESOURCE_GROUP=false
if [ "$RG_EXISTS" = 'true' ]; then
  [ -f "$STATE_FILE" ] || fail "Resource group '$RESOURCE_GROUP' already exists, but provenance file '$STATE_FILE' is missing. Refusing to adopt it."
  jq -e \
    --arg owner "$OWNER_MARKER" \
    --arg tenant "$TENANT_ID" \
    --arg subscription "$SUBSCRIPTION_ID" \
    --arg rg_name "$RESOURCE_GROUP" \
    --arg workspace_id "$(normalize_id "$SENTINEL_WS_ID")" \
    --argjson rule_ids "$RULE_IDS_JSON" \
    --argjson rule_names "$RULE_NAMES_JSON" \
    '
      .schema_version == 1 and
      .owner_marker == $owner and
      ((.tenant_id | ascii_downcase) == ($tenant | ascii_downcase)) and
      ((.subscription_id | ascii_downcase) == ($subscription | ascii_downcase)) and
      .resource_group_name == $rg_name and
      ((.sentinel_workspace_id | ascii_downcase) == $workspace_id) and
      (.deployment_id | type == "string" and length >= 16) and
      .rule_ids == $rule_ids and
      .rule_display_names == $rule_names
    ' "$STATE_FILE" >/dev/null || fail "Provenance file '$STATE_FILE' does not match this deployment request."

  DEPLOYMENT_ID="$(jq -er '.deployment_id' "$STATE_FILE")"
  RECORDED_RG_ID="$(jq -er '.resource_group_id' "$STATE_FILE")"
  RG_JSON="$(az group show --name "$RESOURCE_GROUP" --subscription "$SUBSCRIPTION_ID" --output json)"
  ACTUAL_RG_ID="$(jq -er '.id' <<< "$RG_JSON")"
  ACTUAL_OWNER="$(jq -r --arg key "$OWNER_TAG" '.tags[$key] // empty' <<< "$RG_JSON")"
  ACTUAL_DEPLOYMENT="$(jq -r --arg key "$DEPLOYMENT_TAG" '.tags[$key] // empty' <<< "$RG_JSON")"
  [ "$(normalize_id "$ACTUAL_RG_ID")" = "$(normalize_id "$RECORDED_RG_ID")" ] || fail 'Existing resource-group ID does not match the provenance file.'
  [ "$(normalize_id "$ACTUAL_RG_ID")" = "$(normalize_id "$EXPECTED_RG_ID")" ] || fail 'Existing resource-group ID is inconsistent with the active subscription and requested name.'
  [ "$ACTUAL_OWNER" = "$OWNER_MARKER" ] || fail "Existing resource group is missing the exact '$OWNER_TAG' ownership tag."
  [ "$ACTUAL_DEPLOYMENT" = "$DEPLOYMENT_ID" ] || fail "Existing resource group is missing the exact '$DEPLOYMENT_TAG' provenance tag."
  STATE_VERIFIED=true
  echo "  Verified owned rerun: $ACTUAL_RG_ID"
else
  [ ! -e "$STATE_FILE" ] || fail "Provenance file '$STATE_FILE' exists but resource group '$RESOURCE_GROUP' does not. Refusing to reuse stale state."
  DEPLOYMENT_ID="$(python3 -c 'import uuid; print(uuid.uuid4())')"
  [ -n "$DEPLOYMENT_ID" ] || fail 'Could not generate a deployment identifier.'
  NEW_RESOURCE_GROUP=true
  echo "  New resource group planned: $EXPECTED_RG_ID"
fi

echo '=== [1/8] Preflighting all Sentinel rule identities ==='
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

verify_rule_inventory() {
  local inventory="$1"
  local require_owned="$2"
  local index rule_id display_name ownership_text id_count name_collision_count actual_name actual_description

  for index in "${!RULE_IDS[@]}"; do
    rule_id="${RULE_IDS[$index]}"
    display_name="${RULE_DISPLAY_NAMES[$index]}"
    ownership_text="[Owner: $OWNER_MARKER; Deployment: $DEPLOYMENT_ID]"
    id_count="$(jq --arg id "$rule_id" '[.value[] | select((.name // "") == $id)] | length' <<< "$inventory")"
    name_collision_count="$(jq --arg id "$rule_id" --arg name "$display_name" '[.value[] | select((.properties.displayName // "") == $name and (.name // "") != $id)] | length' <<< "$inventory")"

    [ "$id_count" -le 1 ] || fail "Sentinel returned duplicate resources for rule ID '$rule_id'."
    [ "$name_collision_count" -eq 0 ] || fail "A different Sentinel rule already uses display name '$display_name'. Refusing to shadow or overwrite it."

    if [ "$id_count" -eq 1 ]; then
      [ "$STATE_VERIFIED" = 'true' ] || fail "Sentinel rule ID '$rule_id' already exists without a verified deployment manifest. Refusing to adopt it."
      actual_name="$(jq -r --arg id "$rule_id" '.value[] | select(.name == $id) | .properties.displayName // ""' <<< "$inventory")"
      actual_description="$(jq -r --arg id "$rule_id" '.value[] | select(.name == $id) | .properties.description // ""' <<< "$inventory")"
      [ "$actual_name" = "$display_name" ] || fail "Sentinel rule '$rule_id' has an unexpected display name. Refusing to overwrite it."
      [[ "$actual_description" == *"$ownership_text"* ]] || fail "Sentinel rule '$rule_id' is missing this deployment's ownership marker. Refusing to overwrite it."
    elif [ "$require_owned" = 'true' ]; then
      fail "Sentinel deployment did not return expected owned rule '$rule_id'."
    fi
  done
}

verify_rule_inventory "$RULES_JSON" false

if [ "$PLAN_ONLY" = 'true' ]; then
  cat <<PLAN

Ownership and collision preflight passed. PLAN_ONLY=true; no resources, settings,
files, packages, agents, or Sentinel rules were changed.

Planned deployment ID: $DEPLOYMENT_ID
Resource group:        $EXPECTED_RG_ID
Sentinel workspace:    $SENTINEL_WS_ID
Sentinel rules:        ${#RULE_IDS[@]} deterministic owner-marked rules
Defender AI tier:      $CURRENT_TIER
PLAN
  exit 0
fi

if [ "$CURRENT_TIER" != 'Standard' ] && [ "${CONFIRM_SUBSCRIPTION_SCOPE:-}" != 'ENABLE-DEFENDER-FOR-AI-SERVICES' ]; then
  fail 'This deployment would enable the paid Defender for AI Services Standard plan. Review the active subscription, then set CONFIRM_SUBSCRIPTION_SCOPE=ENABLE-DEFENDER-FOR-AI-SERVICES.'
fi

if [ "$NEW_RESOURCE_GROUP" = 'true' ]; then
  echo '=== [2/8] Creating and recording the owned resource group ==='
  az group create \
    --name "$RESOURCE_GROUP" \
    --location "$LOCATION" \
    --subscription "$SUBSCRIPTION_ID" \
    --tags "$OWNER_TAG=$OWNER_MARKER" "$DEPLOYMENT_TAG=$DEPLOYMENT_ID" \
    --only-show-errors -o none

  RG_JSON="$(az group show --name "$RESOURCE_GROUP" --subscription "$SUBSCRIPTION_ID" --output json)"
  ACTUAL_RG_ID="$(jq -er '.id' <<< "$RG_JSON")"
  ACTUAL_OWNER="$(jq -r --arg key "$OWNER_TAG" '.tags[$key] // empty' <<< "$RG_JSON")"
  ACTUAL_DEPLOYMENT="$(jq -r --arg key "$DEPLOYMENT_TAG" '.tags[$key] // empty' <<< "$RG_JSON")"
  [ "$(normalize_id "$ACTUAL_RG_ID")" = "$(normalize_id "$EXPECTED_RG_ID")" ] || fail 'Azure returned an unexpected resource-group ID after creation.'
  [ "$ACTUAL_OWNER" = "$OWNER_MARKER" ] || fail 'Azure did not persist the resource-group ownership tag.'
  [ "$ACTUAL_DEPLOYMENT" = "$DEPLOYMENT_ID" ] || fail 'Azure did not persist the resource-group deployment tag.'

  STATE_TMP="${STATE_FILE}.tmp.$$"
  trap 'rm -f "${STATE_TMP:-}"' EXIT
  umask 077
  jq -n \
    --arg owner_marker "$OWNER_MARKER" \
    --arg deployment_id "$DEPLOYMENT_ID" \
    --arg tenant_id "$TENANT_ID" \
    --arg subscription_id "$SUBSCRIPTION_ID" \
    --arg resource_group_name "$RESOURCE_GROUP" \
    --arg resource_group_id "$ACTUAL_RG_ID" \
    --arg sentinel_workspace_id "$SENTINEL_WS_ID" \
    --arg sentinel_resource_group "$WORKSPACE_RG" \
    --arg sentinel_workspace_name "$WORKSPACE_NAME" \
    --argjson rule_ids "$RULE_IDS_JSON" \
    --argjson rule_display_names "$RULE_NAMES_JSON" \
    '{
      schema_version: 1,
      owner_marker: $owner_marker,
      deployment_id: $deployment_id,
      tenant_id: $tenant_id,
      subscription_id: $subscription_id,
      resource_group_name: $resource_group_name,
      resource_group_id: $resource_group_id,
      sentinel_workspace_id: $sentinel_workspace_id,
      sentinel_resource_group: $sentinel_resource_group,
      sentinel_workspace_name: $sentinel_workspace_name,
      rule_ids: $rule_ids,
      rule_display_names: $rule_display_names
    }' > "$STATE_TMP"
  mv -f "$STATE_TMP" "$STATE_FILE"
  trap - EXIT
  STATE_VERIFIED=true
  echo "  Provenance recorded: $STATE_FILE"
else
  echo '=== [2/8] Reusing the exact provenance-verified resource group ==='
fi

echo '=== [3/8] Registering resource providers and configuring Defender ==='
for provider_name in Microsoft.CognitiveServices Microsoft.MachineLearningServices Microsoft.Security Microsoft.ContainerRegistry; do
  az provider register --namespace "$provider_name" --subscription "$SUBSCRIPTION_ID" --only-show-errors >/dev/null
done
if [ "$CURRENT_TIER" != 'Standard' ]; then
  az security pricing create --name AI --tier Standard --subscription "$SUBSCRIPTION_ID" --only-show-errors >/dev/null
  echo '  Defender for AI Services -> Standard'
else
  echo '  Defender for AI Services already Standard'
fi

OPERATOR_OID="$(az ad signed-in-user show --query id -o tsv)"
[ -n "$OPERATOR_OID" ] || fail 'Could not determine the signed-in Entra user object ID.'

echo '=== [4/8] Deploying infra (Foundry hub + project + OpenAI + ACR) ==='
DEPLOY_OUT="$(az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --subscription "$SUBSCRIPTION_ID" \
  --template-file "$LAB_DIR/infra/main.bicep" \
  --parameters sentinelWorkspaceId="$SENTINEL_WS_ID" operatorObjectId="$OPERATOR_OID" \
  --query properties.outputs \
  -o json)"

AI_SERVICES_ENDPOINT="$(jq -er '.aiServicesEndpoint.value | strings | select(length > 0)' <<< "$DEPLOY_OUT")"
MODEL_DEPLOYMENT="$(jq -er '.openAIDeploymentName.value | strings | select(length > 0)' <<< "$DEPLOY_OUT")"
echo "  AI_SERVICES_ENDPOINT=$AI_SERVICES_ENDPOINT"
echo "  MODEL_DEPLOYMENT=$MODEL_DEPLOYMENT"

echo '=== [5/8] Writing agent config from hash-locked dependencies ==='
VENV="${VENV:-$LAB_DIR/.venv}"
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --require-hashes -r "$LAB_DIR/requirements.lock"
pushd "$LAB_DIR/agent" >/dev/null
AI_SERVICES_ENDPOINT="$AI_SERVICES_ENDPOINT" MODEL_DEPLOYMENT="$MODEL_DEPLOYMENT" "$VENV/bin/python" create_agent.py
popd >/dev/null

echo '=== [6/8] Deploying owner-marked Sentinel analytics rules ==='
az deployment group create \
  --resource-group "$WORKSPACE_RG" \
  --subscription "$SUBSCRIPTION_ID" \
  --template-file "$LAB_DIR/infra/sentinel-rules.bicep" \
  --parameters workspaceName="$WORKSPACE_NAME" ownerMarker="$OWNER_MARKER" deploymentId="$DEPLOYMENT_ID" \
  --only-show-errors -o none

echo '=== [7/8] Verifying Sentinel ownership postconditions ==='
RULES_JSON="$(fetch_all_rules)"
verify_rule_inventory "$RULES_JSON" true
echo "  Verified ${#RULE_IDS[@]} exact owner-marked analytics rules"

echo '=== [8/8] Summary ==='
cat <<SUMMARY

  Lab deployed successfully with provenance ID $DEPLOYMENT_ID.
  Cleanup state: $STATE_FILE

  Next steps:

    export AI_SERVICES_ENDPOINT="$AI_SERVICES_ENDPOINT"
    export MODEL_DEPLOYMENT="$MODEL_DEPLOYMENT"

    # Run a single attack:
    $VENV/bin/python $LAB_DIR/attacks/run_attack.py jailbreak

    # Or run every scenario (takes ~5 minutes):
    $VENV/bin/python $LAB_DIR/attacks/run_attack.py all

    # Defender alerts appear in 5-15 minutes. Check Sentinel:
    #   SecurityAlert | where AlertName has "Agentic" or has "Jailbreak"

SUMMARY
