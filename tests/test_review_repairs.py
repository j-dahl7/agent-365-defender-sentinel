import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReviewRepairs(unittest.TestCase):
    def test_model_catalogue_rejects_deprecated_missing_and_incompatible_offers(self):
        module = load('model_preflight_test', ROOT / 'scripts/validate-model-selection.py')
        model = {'format': 'OpenAI', 'name': 'fixture-chat', 'version': '2026-01-01',
                 'lifecycleStatus': 'GenerallyAvailable', 'capabilities': {'chatCompletion': 'true'},
                 'skus': [{'name': 'Standard', 'capacity': {'minimum': 1, 'maximum': 50, 'step': 1}}]}
        module.validate_selection([{'model': model}], 'fixture-chat', '2026-01-01', 'Standard', 10)
        for change in ({'lifecycleStatus': 'Deprecated'}, {'capabilities': {}}, {'skus': []},
                       {'deprecation': {'inference': '2020-01-01T00:00:00Z'}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                module.validate_selection([{'model': {**model, **change}}], 'fixture-chat', '2026-01-01', 'Standard', 10)
        with self.assertRaises(ValueError):
            module.validate_selection([{'model': model}], 'fixture-chat', '2026-01-01', 'Standard', 51)

    def test_model_controlled_document_titles_are_literal_and_confined(self):
        tools = load('real_agent_tools_review', ROOT / 'agent/tools.py')
        for title in ('', '/etc/passwd', '../README', 'C:/x', '**/', 'rel*', None):
            with self.subTest(title=title):
                self.assertIn('error', tools.search_docs(title))
        self.assertEqual(tools.search_docs('release-notes')['title'], 'release-notes-TAMPERED')

    def test_billing_follows_infrastructure_and_local_dependency_checks(self):
        source = (ROOT / 'scripts/deploy-lab.sh').read_text()
        self.assertLess(source.index('validate-model-selection.py'), source.index('az group create'))
        self.assertLess(source.index('pip" install'), source.index('az group create'))
        self.assertLess(source.index('OPERATOR_OID='), source.index('az group create'))
        self.assertLess(source.index('AI_SERVICES_ENDPOINT="$(jq'), source.index('az security pricing create'))
        self.assertIn('defender_ai_prior_tier', source)

    def test_shared_rule_deployment_name_is_owned_and_scoped(self):
        source = (ROOT / 'scripts/deploy-lab.sh').read_text()
        self.assertIn('--name "agent365-rules-${DEPLOYMENT_ID}"', source)
        self.assertIn('scope: workspace', (ROOT / 'infra/sentinel-rules.bicep').read_text())

    def test_rule_freshness_keeps_context_and_deduplicates_system_alerts(self):
        import re
        source = (ROOT / 'infra/sentinel-rules.bicep').read_text()
        queries = re.findall(r"query: '''\n([\s\S]*?)\n'''", source)
        self.assertEqual(len(queries), 5)
        for query in queries:
            self.assertIn('FirstIngested=min(IngestedAt)', query)
            self.assertIn('by SystemAlertId', query)
            self.assertIn('coalesce(ingestion_time(), TimeGenerated)', query)
        self.assertIn('LastIngested > ago(5m)', queries[0])
        self.assertIn('LastIngested > ago(15m)', queries[2])
