import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from test_attack_redaction import LAB_ROOT, _load_attack_module


class EndpointSafetyTests(unittest.TestCase):
    def setUp(self):
        self.attack = _load_attack_module()
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state_path = Path(self.temp.name) / 'state.json'
        self.endpoint = 'https://agent365ais123456.cognitiveservices.azure.com'
        self.state = {
            'schema_version': 1,
            'owner_marker': 'nine-lives-zero-trust:agent-365-defender-sentinel:v2',
            'deployment_id': '33333333-3333-4333-8333-333333333333',
            'subscription_id': '11111111-1111-4111-8111-111111111111',
            'tenant_id': '22222222-2222-4222-8222-222222222222',
            'resource_group_name': 'agent365-test-rg',
            'resource_group_id': '/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/agent365-test-rg',
            'ai_services_name': 'agent365ais123456',
            'ai_services_endpoint': self.endpoint,
            'ai_services_id': '/subscriptions/11111111-1111-4111-8111-111111111111/resourceGroups/agent365-test-rg/providers/Microsoft.CognitiveServices/accounts/agent365ais123456',
        }

    def build(self, endpoint, state):
        if state is not None:
            self.state_path.write_text(json.dumps(state), encoding='utf-8')
        credential, client = Mock(), Mock()
        with patch.dict(os.environ, {'STATE_FILE': str(self.state_path)}), \
             patch.object(self.attack, 'AI_SERVICES_ENDPOINT', endpoint), \
             patch.object(self.attack, 'DefaultAzureCredential', credential), \
             patch.object(self.attack, 'AzureOpenAI', client):
            try:
                result = self.attack._build_client()
            except (ValueError, OSError):
                credential.assert_not_called()
                client.assert_not_called()
                raise
        return result, credential, client

    def test_unowned_or_ambiguous_endpoint_refuses_before_credentials(self):
        for endpoint in [
            'https://attacker.example', 'http://agent365ais123456.cognitiveservices.azure.com',
            'https://agent365ais123456.cognitiveservices.azure.com.attacker.example',
            'https://user@agent365ais123456.cognitiveservices.azure.com',
            self.endpoint + ':444', self.endpoint + '/other', self.endpoint + '?key=value',
            self.endpoint + '#fragment', self.endpoint + '\\@attacker.example',
            'https://other.cognitiveservices.azure.com', '\n' + self.endpoint,
        ]:
            with self.subTest(endpoint=endpoint), self.assertRaises(ValueError):
                self.build(endpoint, self.state)

    def test_missing_or_inconsistent_resource_proof_refuses_before_credentials(self):
        for key, value in [('owner_marker', 'other'), ('schema_version', 2),
                           ('ai_services_name', 'other'), ('ai_services_id', self.state['ai_services_id'].replace('agent365-test-rg', 'foreign')),
                           ('ai_services_endpoint', 'https://attacker.example'), ('tenant_id', ''),
                           ('deployment_id', ''), ('resource_group_id', '/subscriptions/other/resourceGroups/agent365-test-rg')]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.build(self.endpoint, {**self.state, key: value})
        with self.assertRaises((ValueError, OSError)):
            self.state_path.unlink(missing_ok=True)
            self.build(self.endpoint, None)

    def test_owned_endpoint_keeps_normal_client_contract(self):
        _, credential, client = self.build(self.endpoint + '/', self.state)
        credential.assert_called_once()
        self.assertEqual(client.call_args.kwargs['azure_endpoint'], self.endpoint)
        self.assertEqual(client.call_args.kwargs['api_version'], '2024-10-01-preview')

    def test_recording_deployment_output_preserves_provenance_and_rejects_foreign_account(self):
        from endpoint_ownership import record_endpoint
        previous = {key: value for key, value in self.state.items() if not key.startswith('ai_services_')}
        self.state_path.write_text(json.dumps(previous), encoding='utf-8')
        before = self.state_path.read_bytes()
        with self.assertRaises(ValueError):
            record_endpoint(self.state_path, self.endpoint,
                            self.state['ai_services_id'].replace('agent365-test-rg', 'foreign'),
                            self.state['ai_services_name'])
        self.assertEqual(self.state_path.read_bytes(), before)
        record_endpoint(self.state_path, self.endpoint, self.state['ai_services_id'], self.state['ai_services_name'])
        self.assertEqual(json.loads(self.state_path.read_text(encoding='utf-8')), self.state)


class RetiredPurgeTests(unittest.TestCase):
    def test_legacy_purge_controls_refuse_before_dependency_or_cloud_calls(self):
        bash = 'C:/Program Files/Git/bin/bash.exe' if os.name == 'nt' else 'bash'
        for key in ['PURGE_KEYVAULT_NAME', 'CONFIRM_KEYVAULT_PURGE']:
            with self.subTest(key=key):
                result = subprocess.run([bash, str(LAB_ROOT / 'scripts/cleanup.sh')],
                                        env={**os.environ, key: 'foreign-vault'}, text=True, capture_output=True)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('Automated Key Vault purge is no longer supported', result.stderr)


if __name__ == '__main__':
    unittest.main()
