import json
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


LAB_ROOT = Path(__file__).resolve().parents[1]
DEPLOY_SCRIPT = LAB_ROOT / "scripts" / "deploy-lab.sh"
CLEANUP_SCRIPT = LAB_ROOT / "scripts" / "cleanup.sh"
BICEP_FILE = LAB_ROOT / "infra" / "sentinel-rules.bicep"

SUBSCRIPTION_ID = "11111111-1111-4111-8111-111111111111"
TENANT_ID = "22222222-2222-4222-8222-222222222222"
DEPLOYMENT_ID = "33333333-3333-4333-8333-333333333333"
RESOURCE_GROUP = "agent365-test-rg"
RESOURCE_GROUP_ID = f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/{RESOURCE_GROUP}"
WORKSPACE_ID = (
    f"/subscriptions/{SUBSCRIPTION_ID}/resourceGroups/sentinel-rg/"
    "providers/Microsoft.OperationalInsights/workspaces/sentinel-law"
)
OWNER_MARKER = "nine-lives-zero-trust:agent-365-defender-sentinel:v1"
RULE_IDS = [
    "agent365-jailbreak-burst",
    "agent365-xpia-ascii-smuggling",
    "agent365-instruction-leak",
    "agent365-credential-data-leak",
    "agent365-anomalous-tool-invocation",
]
RULE_NAMES = [
    "LAB - Agent Jailbreak Attempts (burst)",
    "LAB - Indirect Prompt Injection (XPIA/ASCII Smuggling) on AI Agent",
    "LAB - AI Agent Instruction Leak / Reconnaissance",
    "LAB - AI Agent Exposed Credentials or Sensitive Data",
    "LAB - AI Agent Anomalous Tool Invocation or Volume Anomaly",
]


class Agent365StaticSafetyTests(unittest.TestCase):
    def test_bicep_marks_every_rule_with_deployment_ownership(self):
        source = BICEP_FILE.read_text(encoding="utf-8")
        self.assertIn("param ownerMarker string", source)
        self.assertIn("param deploymentId string", source)
        self.assertEqual(source.count("${ownershipSuffix}"), 5)

    def test_scripts_require_provenance_and_never_suppress_azure_failures(self):
        deploy = DEPLOY_SCRIPT.read_text(encoding="utf-8")
        cleanup = CLEANUP_SCRIPT.read_text(encoding="utf-8")
        self.assertIn("Refusing to adopt it", deploy)
        self.assertIn("STATE_VERIFIED", deploy)
        self.assertIn("verify_rule_inventory", deploy)
        self.assertIn("Refusing name-based cleanup", cleanup)
        self.assertIn("No resources were deleted", cleanup)
        self.assertNotIn("|| true", deploy)
        self.assertNotIn("|| true", cleanup)


@unittest.skipUnless(
    os.name != "nt" and shutil.which("bash") and shutil.which("jq"),
    "ownership runtime tests require Linux Bash and jq",
)
class Agent365OwnershipRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin_dir = self.root / "bin"
        self.bin_dir.mkdir()
        self.state_path = self.root / "azure-state.json"
        self.log_path = self.root / "az-calls.log"
        self.manifest_path = self.root / "deployment-state.json"
        self.venv_path = self.root / "venv"
        self._write_azure_state(rg_exists=False, rules=[])
        self._write_fake_az()
        self._write_fake_python()

        self.base_env = os.environ.copy()
        self.base_env.update(
            {
                "PATH": f"{self.bin_dir}{os.pathsep}{self.base_env['PATH']}",
                "MOCK_AZ_STATE": str(self.state_path),
                "MOCK_AZ_LOG": str(self.log_path),
                "MOCK_SUBSCRIPTION_ID": SUBSCRIPTION_ID,
                "MOCK_TENANT_ID": TENANT_ID,
                "MOCK_DEPLOYMENT_ID": DEPLOYMENT_ID,
                "MOCK_TIER": "Standard",
                "RESOURCE_GROUP": RESOURCE_GROUP,
                "SENTINEL_WS_ID": WORKSPACE_ID,
                "STATE_FILE": str(self.manifest_path),
                "VENV": str(self.venv_path),
            }
        )

    def _write_azure_state(self, *, rg_exists, rules, owner=None, deployment=None):
        self.state_path.write_text(
            json.dumps(
                {
                    "rg_exists": rg_exists,
                    "rg_owner": owner,
                    "rg_deployment": deployment,
                    "rules": rules,
                }
            ),
            encoding="utf-8",
        )

    def _read_azure_state(self):
        return json.loads(self.state_path.read_text(encoding="utf-8"))

    def _write_fake_az(self):
        template = r'''#!/usr/bin/python3
import json
import os
import re
import sys
from pathlib import Path

RULE_IDS = __RULE_IDS__
RULE_NAMES = __RULE_NAMES__
args = sys.argv[1:]
state_path = Path(os.environ["MOCK_AZ_STATE"])
log_path = Path(os.environ["MOCK_AZ_LOG"])
subscription_id = os.environ["MOCK_SUBSCRIPTION_ID"]
tenant_id = os.environ["MOCK_TENANT_ID"]
resource_group = os.environ.get("RESOURCE_GROUP", "agent365-test-rg")
resource_group_id = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group}"

with log_path.open("a", encoding="utf-8") as handle:
    handle.write(" ".join(args) + "\n")

state = json.loads(state_path.read_text(encoding="utf-8"))

def save():
    state_path.write_text(json.dumps(state), encoding="utf-8")

def option(name, default=None):
    if name not in args:
        return default
    index = args.index(name)
    return args[index + 1] if index + 1 < len(args) else default

if args[:2] == ["account", "show"]:
    print(json.dumps({"id": subscription_id, "tenantId": tenant_id, "name": "Mock Subscription"}))
elif args[:3] == ["security", "pricing", "show"]:
    print(os.environ.get("MOCK_TIER", "Standard"))
elif args[:3] == ["security", "pricing", "create"]:
    if os.environ.get("MOCK_FAIL_PRICING") == "true":
        sys.exit(17)
elif args[:2] == ["provider", "register"]:
    pass
elif args[:2] == ["group", "exists"]:
    print("true" if state["rg_exists"] else "false")
elif args[:2] == ["group", "show"]:
    if not state["rg_exists"]:
        sys.exit(3)
    print(json.dumps({
        "id": resource_group_id,
        "name": resource_group,
        "tags": {
            "nlzt-owner": state.get("rg_owner"),
            "nlzt-deployment": state.get("rg_deployment"),
        },
    }))
elif args[:2] == ["group", "create"]:
    tags = {}
    if "--tags" in args:
        index = args.index("--tags") + 1
        while index < len(args) and not args[index].startswith("--"):
            key, value = args[index].split("=", 1)
            tags[key] = value
            index += 1
    state["rg_exists"] = True
    state["rg_owner"] = tags.get("nlzt-owner")
    state["rg_deployment"] = tags.get("nlzt-deployment")
    save()
elif args[:2] == ["group", "delete"]:
    if os.environ.get("MOCK_FAIL_GROUP_DELETE") == "true":
        sys.exit(18)
    state["rg_exists"] = False
    save()
elif args[:3] == ["ad", "signed-in-user", "show"]:
    print("44444444-4444-4444-8444-444444444444")
elif args[:3] == ["deployment", "group", "create"]:
    template_file = option("--template-file", "")
    if template_file.endswith("sentinel-rules.bicep"):
        owner = next(value.split("=", 1)[1] for value in args if value.startswith("ownerMarker="))
        deployment = next(value.split("=", 1)[1] for value in args if value.startswith("deploymentId="))
        suffix = f"[Owner: {owner}; Deployment: {deployment}]"
        state["rules"] = [
            {"name": rule_id, "properties": {"displayName": name, "description": f"Mock rule. {suffix}"}}
            for rule_id, name in zip(RULE_IDS, RULE_NAMES)
        ]
        save()
    else:
        print(json.dumps({
            "aiServicesEndpoint": {"value": "https://mock.services.ai.azure.com"},
            "openAIDeploymentName": {"value": "mock-model"},
        }))
elif args and args[0] == "rest":
    method = option("--method", "GET").upper()
    url = option("--url", "")
    if method == "GET" and ("/alertRules?" in url or "mock-next-page" in url):
        if os.environ.get("MOCK_PAGINATE_RULES") == "true" and "mock-next-page" not in url:
            print(json.dumps({"value": [], "nextLink": "https://management.azure.com/mock-next-page"}))
        else:
            print(json.dumps({"value": state["rules"]}))
    elif method == "DELETE":
        match = re.search(r"/alertRules/([^?]+)", url)
        if not match:
            sys.exit(19)
        rule_id = match.group(1)
        if os.environ.get("MOCK_FAIL_DELETE_RULE") == rule_id:
            sys.exit(23)
        state["rules"] = [rule for rule in state["rules"] if rule.get("name") != rule_id]
        save()
    else:
        sys.exit(20)
elif args[:2] == ["keyvault", "purge"]:
    if os.environ.get("MOCK_FAIL_PURGE") == "true":
        sys.exit(24)
else:
    print(f"Unexpected mocked az call: {args}", file=sys.stderr)
    sys.exit(99)
'''
        source = template.replace("__RULE_IDS__", repr(RULE_IDS)).replace(
            "__RULE_NAMES__", repr(RULE_NAMES)
        )
        path = self.bin_dir / "az"
        path.write_text(source, encoding="utf-8")
        path.chmod(0o700)

    def _write_fake_python(self):
        path = self.bin_dir / "python3"
        path.write_text(
            textwrap.dedent(
                r'''#!/usr/bin/env bash
                set -euo pipefail
                if [ "${1:-}" = '-c' ]; then
                  printf '%s\n' "$MOCK_DEPLOYMENT_ID"
                  exit 0
                fi
                if [ "${1:-}" = '-m' ] && [ "${2:-}" = 'venv' ]; then
                  target="$3"
                  mkdir -p "$target/bin"
                  printf '#!/usr/bin/env bash\nexit 0\n' > "$target/bin/pip"
                  printf '#!/usr/bin/env bash\nexit 0\n' > "$target/bin/python"
                  chmod 700 "$target/bin/pip" "$target/bin/python"
                  exit 0
                fi
                exit 91
                '''
            ).lstrip(),
            encoding="utf-8",
        )
        path.chmod(0o700)

    def _run(self, script, **extra_env):
        env = {**self.base_env, **extra_env}
        return subprocess.run(
            ["bash", str(script)],
            env=env,
            text=True,
            capture_output=True,
            check=False,
        )

    def _calls(self):
        if not self.log_path.exists():
            return []
        return self.log_path.read_text(encoding="utf-8").splitlines()

    @staticmethod
    def _mutations(calls):
        mutation_fragments = (
            "provider register",
            "security pricing create",
            "group create",
            "group delete",
            "deployment group create",
            "rest --method DELETE",
            "keyvault purge",
        )
        return [call for call in calls if any(fragment in call for fragment in mutation_fragments)]

    def test_plan_and_collisions_fail_before_any_mutation(self):
        plan = self._run(DEPLOY_SCRIPT, PLAN_ONLY="true", MOCK_TIER="Free")
        self.assertEqual(plan.returncode, 0, plan.stderr or plan.stdout)
        self.assertIn("no resources, settings", plan.stdout)
        self.assertFalse(self.manifest_path.exists())
        self.assertEqual(self._mutations(self._calls()), [])

        self.log_path.write_text("", encoding="utf-8")
        self._write_azure_state(rg_exists=True, rules=[], owner="foreign", deployment="foreign")
        unowned = self._run(DEPLOY_SCRIPT)
        self.assertNotEqual(unowned.returncode, 0)
        self.assertIn("Refusing to adopt", unowned.stderr)
        self.assertEqual(self._mutations(self._calls()), [])

        self.log_path.write_text("", encoding="utf-8")
        self._write_azure_state(
            rg_exists=False,
            rules=[
                {
                    "name": RULE_IDS[0],
                    "properties": {"displayName": RULE_NAMES[0], "description": "foreign"},
                }
            ],
        )
        collision = self._run(
            DEPLOY_SCRIPT,
            PLAN_ONLY="true",
            MOCK_PAGINATE_RULES="true",
        )
        self.assertNotEqual(collision.returncode, 0)
        self.assertIn("without a verified deployment manifest", collision.stderr)
        self.assertEqual(self._mutations(self._calls()), [])

    def test_first_deploy_and_owned_rerun_use_one_identity(self):
        first = self._run(DEPLOY_SCRIPT)
        self.assertEqual(first.returncode, 0, first.stderr or first.stdout)
        manifest = json.loads(self.manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["deployment_id"], DEPLOYMENT_ID)
        self.assertEqual(manifest["resource_group_id"].lower(), RESOURCE_GROUP_ID.lower())
        self.assertEqual(stat.S_IMODE(self.manifest_path.stat().st_mode), 0o600)
        self.assertEqual(len(self._read_azure_state()["rules"]), 5)

        rerun = self._run(DEPLOY_SCRIPT)
        self.assertEqual(rerun.returncode, 0, rerun.stderr or rerun.stdout)
        self.assertIn("Verified owned rerun", rerun.stdout)
        group_creates = [call for call in self._calls() if call.startswith("group create ")]
        self.assertEqual(len(group_creates), 1)

    def test_cleanup_preflights_every_rule_and_recovers_from_partial_failure(self):
        deployed = self._run(DEPLOY_SCRIPT)
        self.assertEqual(deployed.returncode, 0, deployed.stderr or deployed.stdout)

        plan_start = len(self._calls())
        plan = self._run(CLEANUP_SCRIPT, PLAN_ONLY="true")
        self.assertEqual(plan.returncode, 0, plan.stderr or plan.stdout)
        self.assertEqual(self._mutations(self._calls()[plan_start:]), [])

        azure_state = self._read_azure_state()
        azure_state["rules"][4]["properties"]["description"] = "foreign rule"
        self.state_path.write_text(json.dumps(azure_state), encoding="utf-8")
        collision_start = len(self._calls())
        collision = self._run(CLEANUP_SCRIPT)
        self.assertNotEqual(collision.returncode, 0)
        self.assertIn("not owned by deployment", collision.stderr)
        self.assertEqual(self._mutations(self._calls()[collision_start:]), [])

        ownership = f"[Owner: {OWNER_MARKER}; Deployment: {DEPLOYMENT_ID}]"
        azure_state = self._read_azure_state()
        azure_state["rules"][4]["properties"]["description"] = f"Mock rule. {ownership}"
        self.state_path.write_text(json.dumps(azure_state), encoding="utf-8")

        failure_start = len(self._calls())
        partial = self._run(CLEANUP_SCRIPT, MOCK_FAIL_DELETE_RULE=RULE_IDS[2])
        self.assertEqual(partial.returncode, 23, partial.stderr or partial.stdout)
        after_partial = self._read_azure_state()
        self.assertEqual([rule["name"] for rule in after_partial["rules"]], RULE_IDS[2:])
        self.assertTrue(after_partial["rg_exists"])
        self.assertFalse(
            any(call.startswith("group delete ") for call in self._calls()[failure_start:])
        )

        retry = self._run(CLEANUP_SCRIPT)
        self.assertEqual(retry.returncode, 0, retry.stderr or retry.stdout)
        final_state = self._read_azure_state()
        self.assertEqual(final_state["rules"], [])
        self.assertFalse(final_state["rg_exists"])
        self.assertTrue(self.manifest_path.exists())


if __name__ == "__main__":
    unittest.main()
