#!/usr/bin/env bash
# One-shot deploy for the Agent 365 Defender lab.
#
# Required env vars:
#   SENTINEL_WS_ID   - resource ID of your Sentinel-onboarded Log Analytics workspace
#   RESOURCE_GROUP   - target RG (default: agent365-lab-rg)
#   LOCATION         - Azure region (default: eastus2)

set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-agent365-lab-rg}"
LOCATION="${LOCATION:-eastus2}"
: "${SENTINEL_WS_ID:?Set SENTINEL_WS_ID to your Sentinel workspace resource ID}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(dirname "$SCRIPT_DIR")"

echo "=== [1/7] Registering resource providers ==="
for p in Microsoft.CognitiveServices Microsoft.MachineLearningServices Microsoft.Security Microsoft.ContainerRegistry; do
  az provider register --namespace "$p" --only-show-errors >/dev/null
done

echo "=== [2/7] Ensuring Defender for AI Services plan is enabled ==="
current_tier=$(az security pricing show --name AI --query pricingTier -o tsv 2>/dev/null || echo "Free")
if [ "$current_tier" != "Standard" ]; then
  az security pricing create --name AI --tier Standard --only-show-errors >/dev/null
  echo "  Defender for AI Services -> Standard"
else
  echo "  Defender for AI Services already Standard"
fi

echo "=== [3/7] Creating resource group ==="
az group create --name "$RESOURCE_GROUP" --location "$LOCATION" --only-show-errors -o none

OPERATOR_OID=$(az ad signed-in-user show --query id -o tsv)

echo "=== [4/7] Deploying infra (Foundry hub + project + OpenAI + ACR) ==="
DEPLOY_OUT=$(az deployment group create \
  --resource-group "$RESOURCE_GROUP" \
  --template-file "$LAB_DIR/infra/main.bicep" \
  --parameters sentinelWorkspaceId="$SENTINEL_WS_ID" operatorObjectId="$OPERATOR_OID" \
  --query properties.outputs \
  -o json)

AI_SERVICES_ENDPOINT=$(echo "$DEPLOY_OUT" | jq -r .aiServicesEndpoint.value)
MODEL_DEPLOYMENT=$(echo "$DEPLOY_OUT" | jq -r .openAIDeploymentName.value)
echo "  AI_SERVICES_ENDPOINT=$AI_SERVICES_ENDPOINT"
echo "  MODEL_DEPLOYMENT=$MODEL_DEPLOYMENT"

echo "=== [5/7] Writing agent config ==="
VENV="$LAB_DIR/.venv"
if [ ! -d "$VENV" ]; then
  python3 -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade "azure-identity>=1.19.0" "openai>=1.59.0"
pushd "$LAB_DIR/agent" >/dev/null
AI_SERVICES_ENDPOINT="$AI_SERVICES_ENDPOINT" MODEL_DEPLOYMENT="$MODEL_DEPLOYMENT" "$VENV/bin/python" create_agent.py
popd >/dev/null

echo "=== [6/7] Deploying Sentinel analytics rules ==="
WORKSPACE_NAME=$(basename "$SENTINEL_WS_ID")
WORKSPACE_RG=$(echo "$SENTINEL_WS_ID" | awk -F/ '{print $5}')
az deployment group create \
  --resource-group "$WORKSPACE_RG" \
  --template-file "$LAB_DIR/infra/sentinel-rules.bicep" \
  --parameters workspaceName="$WORKSPACE_NAME" \
  --only-show-errors -o none
echo "  5 analytics rules deployed"

echo "=== [7/7] Summary ==="
cat <<SUMMARY

  Lab deployed successfully.

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
