"""Read-only validation of Azure's location model catalogue; no Azure transport."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import sys


def validate_selection(records, name, version, sku, capacity):
    if not isinstance(records, list):
        raise ValueError('Model catalogue must be an array')
    candidates = [entry.get('model') for entry in records if isinstance(entry, dict)]
    matches = [model for model in candidates if isinstance(model, dict)
               and model.get('format') == 'OpenAI' and model.get('name') == name
               and model.get('version') == version]
    if not matches:
        raise ValueError('Selected OpenAI model/version is absent from this location catalogue')
    for model in matches:
        if model.get('lifecycleStatus') != 'GenerallyAvailable':
            continue
        capabilities = model.get('capabilities') or {}
        if str(capabilities.get('chatCompletion', '')).lower() != 'true':
            continue
        retirement = (model.get('deprecation') or {}).get('inference')
        if retirement:
            expires = datetime.fromisoformat(retirement.replace('Z', '+00:00'))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            if expires <= datetime.now(timezone.utc):
                continue
        for offer in model.get('skus') or []:
            if not isinstance(offer, dict) or offer.get('name') != sku:
                continue
            limits = offer.get('capacity') or {}
            minimum, maximum, step = limits.get('minimum', 1), limits.get('maximum'), limits.get('step', 1)
            if capacity < minimum or (maximum is not None and capacity > maximum) or step <= 0 or (capacity - minimum) % step:
                continue
            return
    raise ValueError('Selected model must be GA, support Chat Completions, and offer the requested SKU/capacity; deprecated models are refused')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--version', required=True)
    parser.add_argument('--sku', required=True)
    parser.add_argument('--capacity', required=True, type=int)
    args = parser.parse_args()
    try:
        validate_selection(json.load(sys.stdin), args.name, args.version, args.sku, args.capacity)
    except (ValueError, TypeError, KeyError) as error:
        raise SystemExit(f'Model preflight refused: {error}')
    print('Model catalogue preflight passed. This does not reserve quota or prove tool-call/Defender behavior.')
