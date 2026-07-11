#!/usr/bin/env bash
# Tear down the Agent 365 Defender lab.

set -euo pipefail

RESOURCE_GROUP="${RESOURCE_GROUP:-agent365-lab-rg}"
: "${SENTINEL_RG:?Set SENTINEL_RG to the Sentinel workspace resource group}"
: "${WORKSPACE_NAME:?Set WORKSPACE_NAME to the Sentinel workspace name}"

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

if [ "${PURGE_KEYVAULT_NAME:-}" ]; then
  if [ "${CONFIRM_KEYVAULT_PURGE:-}" != "$PURGE_KEYVAULT_NAME" ]; then
    echo "Skipping Key Vault purge. Set CONFIRM_KEYVAULT_PURGE=$PURGE_KEYVAULT_NAME to permanently purge it." >&2
  else
    echo "Purging soft-deleted Key Vault $PURGE_KEYVAULT_NAME..."
    az keyvault purge --name "$PURGE_KEYVAULT_NAME" --only-show-errors 2>/dev/null || true
  fi
fi

echo "Done. RG deletion may take several minutes."
