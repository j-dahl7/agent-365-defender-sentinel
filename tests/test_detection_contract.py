import re
import unittest
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parents[1]
KQL_PATH = LAB_ROOT / "detection" / "analytics-rules.kql"
BICEP_PATH = LAB_ROOT / "infra" / "sentinel-rules.bicep"
README_PATH = LAB_ROOT / "README.md"

DOCUMENTED_MODEL_ALERT_IDS = {
    "AI.Azure_Jailbreak.ContentFiltering.BlockedAttempt",
    "AI.Azure_Jailbreak.ContentFiltering.DetectedAttempt",
    "AI.Azure_ASCIISmuggling",
    "AI.Azure_LLMReconnaissance",
    "AI.Azure_CredentialTheftAttempt",
    "AI.Azure_AnomalousToolInvocation",
    "AI.Azure_DOWDuplicateRequests",
    "AI.Azure_DOWVolumeAnomaly",
    "AI.Azure_AccessFromSuspiciousUserAgent",
    "AI.Azure_AccessFromAnonymizedIP",
    "AI.Azure_AccessFromSuspiciousIP",
    "AI.Azure_AccessAnomaly",
}


def quoted_alert_ids(source: str) -> set[str]:
    return set(re.findall(r'"(AI\.Azure_[^"]+)"', source))


class DefenderDetectionContractTests(unittest.TestCase):
    def test_deployable_queries_use_only_current_documented_model_alert_ids(self):
        for path in (KQL_PATH, BICEP_PATH):
            source = path.read_text(encoding="utf-8")
            self.assertEqual(quoted_alert_ids(source), DOCUMENTED_MODEL_ALERT_IDS, path)
            self.assertNotRegex(source, r'"(?:AI\.)?Azure_Agentic_[^"]+"')
            self.assertNotIn("AlertName has_any", source)

    def test_kql_and_bicep_expose_the_same_five_model_level_rules(self):
        kql = KQL_PATH.read_text(encoding="utf-8")
        bicep = BICEP_PATH.read_text(encoding="utf-8")
        self.assertEqual(kql.count("// Rule "), 5)
        self.assertEqual(bicep.count("// ---- Rule "), 5)
        self.assertIn("output ruleCount int = 5", bicep)
        self.assertEqual(quoted_alert_ids(kql), quoted_alert_ids(bicep))

    def test_compromised_resource_ids_use_the_sentinel_azure_resource_entity(self):
        bicep = BICEP_PATH.read_text(encoding="utf-8")
        self.assertEqual(bicep.count("entityType: 'AzureResource'"), 5)
        self.assertEqual(bicep.count("identifier: 'ResourceId'"), 5)
        self.assertEqual(bicep.count("columnName: 'CompromisedEntity'"), 5)
        self.assertNotIn("entityType: 'CloudApplication'", bicep)

    def test_standalone_rule_bodies_match_every_deployed_query(self):
        kql = KQL_PATH.read_text(encoding="utf-8")
        bicep = BICEP_PATH.read_text(encoding="utf-8")
        standalone = re.findall(r"// Rule \d+:[^\n]*\n(.*?)(?=\n// (?:Rule|Hunting):?|\Z)", kql, re.S)
        deployed = re.findall(r"query:\s*'''(.*?)'''", bicep, re.S)
        self.assertEqual(len(standalone), 5)
        self.assertEqual(len(deployed), 5)
        for number, (left, right) in enumerate(zip(standalone, deployed), 1):
            with self.subTest(rule=number):
                self.assertEqual(" ".join(left.split()), " ".join(right.split()))

    def test_readme_separates_model_and_agent_365_coverage(self):
        readme = README_PATH.read_text(encoding="utf-8")
        self.assertIn("Foundry **agent-level** discovery", readme)
        self.assertIn("Agent 365-eligible license", readme)
        self.assertIn("Defender for AI Services plan continues", readme)
        self.assertIn("This lab does **not**", readme)
        self.assertIn("onboard its local chat-completions loop to Agent 365", readme)


if __name__ == "__main__":
    unittest.main()
