import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch


LAB_ROOT = Path(__file__).resolve().parents[1]
ATTACK_SCRIPT = LAB_ROOT / "attacks" / "run_attack.py"


def _load_attack_module():
    azure = sys.modules.setdefault("azure", types.ModuleType("azure"))
    identity = types.ModuleType("azure.identity")
    identity.DefaultAzureCredential = type("DefaultAzureCredential", (), {})
    identity.get_bearer_token_provider = lambda *_args, **_kwargs: object()
    azure.identity = identity
    sys.modules["azure.identity"] = identity

    openai = types.ModuleType("openai")
    openai.AzureOpenAI = type("AzureOpenAI", (), {})
    openai.BadRequestError = type("BadRequestError", (Exception,), {})
    sys.modules["openai"] = openai

    tools_module = types.ModuleType("tools")
    tools_module.TOOL_REGISTRY = {}
    sys.modules["tools"] = tools_module
    os.environ["AI_SERVICES_ENDPOINT"] = "https://example.cognitiveservices.azure.com"

    spec = importlib.util.spec_from_file_location("agent_365_attack_harness", ATTACK_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class AttackRedactionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.attack = _load_attack_module()

    def test_nested_sensitive_values_are_redacted(self):
        secret = "super-secret-value"
        redacted = self.attack._redact_value(
            {
                "api_key": secret,
                "nested": [{"ssh_private_key": secret}, {"content": secret}],
                "safe": "visible",
            }
        )

        rendered = json.dumps(redacted)
        self.assertNotIn(secret, rendered)
        self.assertEqual(redacted["api_key"], "[redacted]")
        self.assertEqual(redacted["safe"], "visible")

    def test_sensitive_key_matching_is_case_insensitive_and_hyphen_agnostic(self):
        secret = "never-render-this-credential"
        redacted = self.attack._redact_value(
            {
                "API-Key": secret,
                "Authorization": secret,
                "nested": {"Client-Secret": secret, "Refresh_Token": secret},
                "safe": "visible",
            }
        )

        rendered = json.dumps(redacted)
        self.assertNotIn(secret, rendered)
        self.assertEqual(redacted["API-Key"], "[redacted]")
        self.assertEqual(redacted["nested"]["Client-Secret"], "[redacted]")
        self.assertEqual(redacted["safe"], "visible")

    def test_main_never_prints_model_response_content(self):
        secret = "CTO_SVC_KEY_must_never_reach_stdout"
        stdout = io.StringIO()
        with (
            patch.object(self.attack, "_build_client", return_value=object()),
            patch.object(self.attack, "_load_agent", return_value={}),
            patch.object(self.attack, "run_prompt", return_value=secret),
            patch.object(sys, "argv", ["run_attack.py", "credential-exfil"]),
            patch("sys.stdout", stdout),
        ):
            self.assertEqual(self.attack.main(), 0)

        rendered = stdout.getvalue()
        self.assertNotIn(secret, rendered)
        self.assertIn("response received (utf8_bytes=", rendered)
        self.assertIn("sha256=", rendered)

    def test_evidence_and_console_paths_do_not_use_raw_tool_payloads(self):
        secret = "never-write-this-secret"
        with tempfile.TemporaryDirectory() as temp_dir:
            with patch.object(self.attack, "EVIDENCE_DIR", Path(temp_dir)):
                self.attack._write_tool_evidence(
                    "credential-exfil",
                    "lookup_customer",
                    {"body": secret},
                    {"api_key": secret, "ssh_private_key": secret},
                )
            evidence = (Path(temp_dir) / "tool-calls.jsonl").read_text(encoding="utf-8")
        self.assertNotIn(secret, evidence)

        source = ATTACK_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("safe_args = _redact_value(args)", source)
        self.assertIn("safe_result = _redact_value(result)", source)
        self.assertNotIn("json.dumps(result)[:180]", source)

    def test_runtime_dependencies_are_bounded_hash_locked_and_used_by_deployment(self):
        requirements = (LAB_ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        lock = (LAB_ROOT / "requirements.lock").read_text(encoding="utf-8")
        deploy_source = (LAB_ROOT / "scripts" / "deploy-lab.sh").read_text(encoding="utf-8")
        readme = (LAB_ROOT / "README.md").read_text(encoding="utf-8")

        self.assertEqual(
            requirements,
            ["azure-identity>=1.25.3,<2.0.0", "openai>=2.50.0,<3.0.0"],
        )
        self.assertIn('--require-hashes -r "$LAB_DIR/requirements.lock"', deploy_source)
        self.assertNotIn('"azure-identity>=', deploy_source)
        self.assertIn("azure-identity==1.25.3", lock)
        self.assertIn("openai==2.53.0", lock)
        self.assertGreaterEqual(lock.count("--hash=sha256:"), 20)
        self.assertIn("subscription-level Defender for AI Services Standard", readme)
        self.assertIn("can affect billing", readme)

    @unittest.skipIf(os.name == "nt", "billing-gate runtime test runs under Bash in Linux CI")
    def test_deploy_billing_gate_fails_closed_before_mutations(self):
        deploy_script = LAB_ROOT / "scripts" / "deploy-lab.sh"
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            call_log = temp_path / "az-calls.log"
            fake_az = temp_path / "az"
            fake_az.write_text(
                """#!/usr/bin/env bash
printf '%s\\n' \"$*\" >> \"$AZ_CALL_LOG\"
if [ \"${1:-} ${2:-}\" = \"account show\" ]; then
  printf '%s\\n' '{\"id\":\"00000000-0000-0000-0000-000000000000\",\"tenantId\":\"11111111-1111-4111-8111-111111111111\",\"name\":\"Mock\"}'
  exit 0
fi
if [ \"${1:-} ${2:-} ${3:-}\" = \"security pricing show\" ]; then
  printf '%s\\n' \"$MOCK_TIER\"
  exit 0
fi
if [ \"${1:-} ${2:-}\" = \"group exists\" ]; then
  printf '%s\\n' 'false'
  exit 0
fi
if [ \"${1:-}\" = \"rest\" ]; then
  printf '%s\\n' '{\"value\":[]}'
  exit 0
fi
if [ \"${1:-} ${2:-}\" = \"group create\" ]; then
  exit 88
fi
exit 99
""",
                encoding="utf-8",
            )
            fake_az.chmod(0o700)

            base_env = os.environ.copy()
            base_env.update(
                {
                    "AZ_CALL_LOG": str(call_log),
                    "MOCK_TIER": "Free",
                    "PATH": str(temp_path) + os.pathsep + base_env["PATH"],
                    "SENTINEL_WS_ID": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/sentinel-rg/providers/Microsoft.OperationalInsights/workspaces/sentinel-law",
                    "STATE_FILE": str(temp_path / "deployment-state.json"),
                }
            )
            base_env.pop("CONFIRM_SUBSCRIPTION_SCOPE", None)

            blocked = subprocess.run(
                [shutil.which("bash") or "bash", str(deploy_script)],
                env=base_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(blocked.returncode, 2)
            blocked_calls = call_log.read_text(encoding="utf-8")
            self.assertIn("security pricing show", blocked_calls)
            self.assertNotIn("provider register", blocked_calls)
            self.assertNotIn("security pricing create", blocked_calls)
            self.assertNotIn("group create", blocked_calls)

            call_log.write_text("", encoding="utf-8")
            confirmed_env = dict(base_env)
            confirmed_env["CONFIRM_SUBSCRIPTION_SCOPE"] = "ENABLE-DEFENDER-FOR-AI-SERVICES"
            confirmed = subprocess.run(
                [shutil.which("bash") or "bash", str(deploy_script)],
                env=confirmed_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(confirmed.returncode, 88)
            confirmed_calls = call_log.read_text(encoding="utf-8")
            self.assertIn("group create", confirmed_calls)
            self.assertNotIn("provider register", confirmed_calls)
            self.assertNotIn("security pricing create", confirmed_calls)

            call_log.write_text("", encoding="utf-8")
            already_standard_env = dict(base_env)
            already_standard_env["MOCK_TIER"] = "Standard"
            already_standard = subprocess.run(
                [shutil.which("bash") or "bash", str(deploy_script)],
                env=already_standard_env,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(already_standard.returncode, 88)
            standard_calls = call_log.read_text(encoding="utf-8")
            self.assertIn("group create", standard_calls)
            self.assertNotIn("security pricing create", standard_calls)


if __name__ == "__main__":
    unittest.main()
