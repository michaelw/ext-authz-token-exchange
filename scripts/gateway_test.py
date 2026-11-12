import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import subprocess
import sys
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("gateway", Path(__file__).with_name("gateway.py"))
gateway = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gateway)


class GatewayTests(unittest.TestCase):
    def test_dependency_forwards_disabled_host_integration(self):
        rendered = subprocess.check_output([sys.executable, str(Path(__file__).with_name("gateway.py")), "dependency", "--selected", "none", "--local-path", "example-starter", "--host-integration", "false"], text=True)
        dependency = json.loads(rendered)["infra"]
        self.assertEqual(dependency["vars"]["HOST_INTEGRATION"], "false")
        self.assertEqual(dependency["path"], "example-starter")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root_patch = patch.object(gateway, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def args(self, provider="apigee", infrastructure="existing", apigee_mode="existing"):
        return argparse.Namespace(gateway=provider, infrastructure=infrastructure,
                                  apigee=apigee_mode, inputs=None, daily_budget=None,
                                  starter_pack=None)

    def test_matrix_keeps_kubernetes_and_apigee_independent(self):
        for infrastructure in ("existing", "provision"):
            for mode in ("existing", "evaluation"):
                args = self.args(infrastructure=infrastructure, apigee_mode=mode)
                args.daily_budget = 25
                config = gateway.resolve(args, {"project": "example", "context": "example-context"})
                self.assertEqual(config["infrastructure"], infrastructure)
                self.assertEqual(config["apigee_mode"], mode)
        for infrastructure in ("existing", "provision"):
            config = gateway.resolve(self.args("gke-gateway", infrastructure, None), {})
            self.assertEqual(config["gateway"], "gke-gateway")

    def test_rejects_irrelevant_apigee_choice(self):
        for args in (self.args("gke-gateway"),):
            with self.assertRaises(ValueError):
                gateway.resolve(args, {})

    def test_fresh_defaults_to_evaluation_and_preserves_saved_mode(self):
        args = self.args(apigee_mode=None)
        args.daily_budget = 25
        self.assertEqual(gateway.resolve(args, {})["apigee_mode"], "evaluation")
        self.assertEqual(gateway.resolve(args, {"apigee_mode":"existing"})["apigee_mode"], "existing")
        args.apigee = "existing"
        self.assertEqual(gateway.resolve(args, {"apigee_mode":"evaluation"})["apigee_mode"], "existing")
        args.apigee = None
        args.daily_budget = None
        self.assertEqual(gateway.resolve(args, {"apigee_mode":"evaluation", "daily_budget":25})["apigee_mode"], "evaluation")

    def test_evaluation_requires_explicit_budget(self):
        with self.assertRaisesRegex(ValueError, "budget"):
            gateway.resolve(self.args(apigee_mode="evaluation"), {})

    def test_inputs_reject_embedded_credentials(self):
        for key in ("access_token", "client_secret", "private_key", "password"):
            with self.assertRaisesRegex(ValueError, "credential"):
                gateway.validate_nonsecret({"nested": {key: "not-a-real-secret"}})
        gateway.validate_nonsecret({"certificate_file": "ca.pem", "private_key_file": "key.pem"})

    def test_existing_cluster_never_calls_starter_pack(self):
        with patch.object(gateway, "run") as command:
            with patch.object(gateway, "check_context"):
                config = {"gateway": "apigee", "infrastructure": "existing", "project": "example", "context": "ctx", "region": "region", "registry": "registry.example/repo"}
                gateway.kubernetes(config)
        command.assert_not_called()

    def test_provisioning_passes_generic_inputs_to_recorded_checkout(self):
        config = {"gateway": "gke-gateway", "infrastructure": "provision", "region": "us-east1", "manage_gateway": True,
                  "starter_vars": {"GCP_BILLING_ACCOUNT_ID": "000000-000000-000000"}}
        values = {key: {"value": item} for key, item in {"project_id": "example", "region": "us-east1", "cluster_name": "cluster", "dev_registry": "example.invalid/dev", "dns_domain": "example.test."}.items()}
        with patch.object(gateway, "starter_pack", return_value=self.root):
            with patch.object(gateway, "run") as command, patch.object(gateway, "output", return_value=json.dumps(values)), patch.object(gateway, "check_context"):
                gateway.kubernetes(config)
        args = command.call_args.args[0]
        self.assertIn("GKE_REGION=us-east1", args)
        self.assertIn("GCP_BILLING_ACCOUNT_ID=000000-000000-000000", args)
        self.assertEqual(command.call_args.kwargs["cwd"], self.root)
        self.assertEqual(config["context"], "gke_example_us-east1_cluster")

    def test_context_mismatch_stops_before_mutation(self):
        with patch.object(gateway, "output", return_value="other"):
            with self.assertRaisesRegex(ValueError, "context"):
                gateway.check_context({"context": "expected"})

    def test_image_tag_depends_on_content_not_time(self):
        source = self.root / "cmd/example/main.go"
        source.parent.mkdir(parents=True)
        source.write_text("first")
        with patch.object(gateway.subprocess, "check_output", return_value=b"cmd/example/main.go\0"):
            first = gateway.image_tag()
            source.touch()
            self.assertEqual(first, gateway.image_tag())
            source.write_text("second")
            self.assertNotEqual(first, gateway.image_tag())

    def test_evaluation_refuses_supplied_existing_organization(self):
        import apigee_infra
        client = unittest.mock.Mock()
        client.request.return_value = {"organizations": [{"organization": "example"}]}
        with patch.object(apigee_infra, "gateway", gateway):
            with self.assertRaisesRegex(ValueError, "not owned"):
                apigee_infra.evaluation({"project": "example", "region": "region"}, client)
        self.assertEqual(client.request.call_count, 1)

    def test_evaluation_does_not_repeat_an_ambiguous_request(self):
        import apigee_infra
        gateway.persist(self.root / ".devspace/apigee-infra/evaluation.json", {"attempted": True})
        client = unittest.mock.Mock()
        client.request.return_value = {"organizations": []}
        with patch.object(apigee_infra, "gateway", gateway):
            with self.assertRaisesRegex(ValueError, "expired or"):
                apigee_infra.evaluation({"project": "example", "region": "region"}, client)
        self.assertEqual(client.request.call_count, 1)

    def test_private_keycloak_cleanup_on_failed_consumer(self):
        import developer_runtime
        process = unittest.mock.Mock()
        with patch.object(developer_runtime.subprocess, "Popen", return_value=process):
            with patch.object(developer_runtime.urllib.request, "urlopen"), patch.object(developer_runtime.socket, "create_connection"):
                with self.assertRaisesRegex(RuntimeError, "synthetic"):
                    with developer_runtime.private_keycloak("context", "namespace"):
                        raise RuntimeError("synthetic")
        process.terminate.assert_called_once()
        process.wait.assert_called_once_with(timeout=10)

    def test_data_path_readiness_waits_for_401_after_rollout(self):
        import developer_runtime
        replies = [unittest.mock.Mock(returncode=0, stdout="500"), unittest.mock.Mock(returncode=0, stdout="401")]
        with patch.object(developer_runtime.subprocess, "run", side_effect=replies) as command:
            with patch.object(developer_runtime.time, "sleep"):
                developer_runtime.wait_gateway({"url": "https://example.test", "certificate": "ca.crt", "address": "192.0.2.10"})
        self.assertEqual(command.call_count, 2)
        self.assertIn("--cacert", command.call_args.args[0])
        self.assertNotIn("--insecure", command.call_args.args[0])

    def test_cleanup_rejects_attached_psc_before_any_deletion(self):
        with patch.object(gateway.apigee, "read_state", return_value={"attachments": ["owned-attachment"]}):
            with self.assertRaisesRegex(ValueError, "endpoint attachments"):
                gateway.cleanup_check({"synthetic_demo": True})

    def test_destructive_commands_require_exact_proxy_confirmation(self):
        with patch.object(gateway.apigee, "read_state", return_value={"owns_proxy": True, "revisions": ["7"]}):
            with patch.object(gateway.apigee, "Client") as client:
                with self.assertRaisesRegex(ValueError, "exact owned proxy"):
                    gateway.destructive({"proxy": "txe-test"}, "delete-proxy-resources", ["--confirm-resource", "other"])
        client.assert_not_called()

    def test_stage_reexecutes_for_live_readiness_and_records_failure(self):
        config = {"gateway": "apigee", "project": "example"}
        calls = []
        gateway.stage(config, "probe", lambda: calls.append(1))
        gateway.stage(config, "probe", lambda: calls.append(2))
        self.assertEqual(calls, [1, 2])
        with self.assertRaises(RuntimeError):
            gateway.stage(config, "probe", lambda: (_ for _ in ()).throw(RuntimeError("secret raw error")))
        state = json.loads((self.root / ".devspace/gateway-setup-state.json").read_text())
        self.assertEqual(state["stages"]["probe"]["status"], "failed")
        self.assertNotIn("secret raw error", json.dumps(state))

    def test_daily_dispatch_has_no_provisioning_path(self):
        for action in ("preflight", "smoke", "test-e2e", "diagnostics", "proxy"):
            with patch.object(gateway, "load", return_value={"gateway": "apigee", "apigee_config": "config.json"}):
                with patch.object(gateway, "apigee_config", return_value={"project": "example", "context": "ctx"}):
                    with patch.object(gateway, "check_context"):
                        with patch.object(gateway, "run"):
                            with patch.object(gateway, "kubernetes") as cluster:
                                with patch.object(gateway, "provision_apigee") as cloud:
                                    gateway.dispatch(action, [])
            cluster.assert_not_called()
            cloud.assert_not_called()


if __name__ == "__main__":
    unittest.main()
