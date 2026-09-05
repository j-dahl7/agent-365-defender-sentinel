"""Bind credential-bearing requests to the public-Azure account recorded by deploy."""

import json
import os
import re
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlsplit
from uuid import UUID

OWNER = 'nine-lives-zero-trust:agent-365-defender-sentinel:v2'


def _endpoint(value, account_name):
    if not isinstance(value, str) or any(c.isspace() or ord(c) < 32 for c in value):
        raise ValueError('AI Services endpoint must be an unambiguous HTTPS account origin.')
    parsed = urlsplit(value)
    allowed = {f'{account_name}.{suffix}' for suffix in (
        'cognitiveservices.azure.com', 'services.ai.azure.com', 'openai.azure.com')}
    if (parsed.scheme != 'https' or parsed.hostname not in allowed or
            parsed.username is not None or parsed.password is not None or
            parsed.port not in (None, 443) or parsed.path not in ('', '/') or
            parsed.query or parsed.fragment or '?' in value or '#' in value or '\\' in value):
        raise ValueError('AI Services endpoint does not match the owned public-Azure account origin.')
    return f'https://{parsed.hostname}'


def validate_owned_endpoint(endpoint, state):
    if not isinstance(state, dict) or state.get('schema_version') != 1 or state.get('owner_marker') != OWNER:
        raise ValueError('A compatible deployment provenance manifest is required.')
    try:
        for key in ('subscription_id', 'tenant_id', 'deployment_id'):
            UUID(state[key])
        name = state['ai_services_name']
        group = state['resource_group_name']
        if not isinstance(name, str) or not re.fullmatch(r'agent365ais[a-z0-9]{6}', name):
            raise ValueError('Unexpected deployed AI account name.')
        if not isinstance(group, str) or not re.fullmatch(r'[A-Za-z0-9_.()-]+', group):
            raise ValueError('Invalid recorded resource group.')
        group_id = f"/subscriptions/{state['subscription_id']}/resourceGroups/{group}"
        account_id = group_id + '/providers/Microsoft.CognitiveServices/accounts/' + name
        if state['resource_group_id'].lower() != group_id.lower() or state['ai_services_id'].lower() != account_id.lower():
            raise ValueError('AI account identity is outside the recorded resource group.')
        recorded = _endpoint(state['ai_services_endpoint'], name)
        requested = _endpoint(endpoint, name)
        if requested != recorded:
            raise ValueError('Requested endpoint differs from the deployed endpoint.')
        return recorded
    except (KeyError, TypeError, AttributeError) as exc:
        raise ValueError('Deployment manifest lacks verified AI account identity; rerun the owned deployment.') from exc


def record_endpoint(state_path, endpoint, account_id, account_name):
    state_path = Path(state_path)
    state = json.loads(state_path.read_text(encoding='utf-8'))
    state.update(ai_services_endpoint=endpoint, ai_services_id=account_id, ai_services_name=account_name)
    state['ai_services_endpoint'] = validate_owned_endpoint(endpoint, state)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8', dir=state_path.parent,
                                         prefix=state_path.name + '.', delete=False) as handle:
            temporary = Path(handle.name)
            os.chmod(temporary, 0o600)
            json.dump(state, handle, indent=2)
            handle.write('\n')
        os.replace(temporary, state_path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    record_endpoint(*sys.argv[1:])
