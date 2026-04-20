#!/usr/bin/env bash
# Tear down the Agent 365 Defender lab.

set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-agent365-lab-rg}"
SENTINEL_RG="${SENTINEL_RG:-sentinel-urbac-lab-rg}"
WORKSPACE_NAME="${WORKSPACE_NAME:-sentinel-urbac-lab-law}"

echo "Deleting 5 analytics rules..."
for rule in agent365-jailbreak-burst agent365-xpia-ascii-smuggling agent365-instruction-leak agent365-credential-data-leak agent365-anomalous-tool-invocation; do
  az sentinel alert-rule delete \
    --resource-group "$SENTINEL_RG" \
    --workspace-name "$WORKSPACE_NAME" \
    --rule-id "$rule" \
    --yes 2>/dev/null || true
done

echo "Deleting resource group $RESOURCE_GROUP (async)..."
az group delete --name "$RESOURCE_GROUP" --yes --no-wait

echo "Purging soft-deleted Key Vaults..."
for kv in $(az keyvault list-deleted --query "[?contains(name,'agent365kv')].name" -o tsv 2>/dev/null); do
  az keyvault purge --name "$kv" --only-show-errors 2>/dev/null || true
done

echo "Done. RG deletion may take several minutes."
