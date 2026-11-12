import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import gateway
import apigee_lifecycle as lifecycle


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.patcher = patch.object(gateway, "ROOT", self.root)
        self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def test_supplied_infrastructure_is_never_destroyed(self):
        with self.assertRaisesRegex(ValueError, "owned"):
            lifecycle.validate({"gateway": "apigee", "infrastructure": "existing"}, "example")

    def test_wrong_confirmation_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "confirmation"):
            lifecycle.validate({"gateway": "apigee", "infrastructure": "provision", "apigee_mode": "evaluation", "project": "example"}, "other")

    def test_completed_stage_is_not_repeated(self):
        path = self.root / "journal.json"
        state = {"stages": {}}
        action = Mock()
        lifecycle.step(path, state, "delete", action)
        lifecycle.step(path, state, "delete", action)
        action.assert_called_once()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_failed_stage_is_resumable_without_raw_error(self):
        path = self.root / "journal.json"
        state = {"stages": {}}
        with self.assertRaises(RuntimeError):
            lifecycle.step(path, state, "delete", Mock(side_effect=RuntimeError("secret-canary")))
        self.assertNotIn("secret-canary", path.read_text())
        lifecycle.step(path, state, "delete", Mock())
        self.assertEqual(json.loads(path.read_text())["stages"]["delete"], "done")

    def test_evaluation_deletion_checks_ownership_and_billing(self):
        a = {"project": "example", "organization": "example"}
        client = Mock()
        with self.assertRaisesRegex(ValueError, "ownership"):
            lifecycle.delete_evaluation(a, client)
        gateway.persist(self.root / ".devspace/apigee-infra/evaluation.json", {"project": "example", "attempted": True})
        client.request.return_value = {"organizations": [{"organization": "example"}]}
        with self.assertRaisesRegex(ValueError, "evaluation"):
            lifecycle.delete_evaluation(a, client)
        self.assertFalse(any(call.args[0] == "DELETE" for call in client.request.call_args_list))

    def test_evaluation_deletion_resumes_recorded_operation(self):
        path = self.root / ".devspace/apigee-infra/evaluation.json"
        gateway.persist(path, {"project": "example", "attempted": True, "delete_operation": "operations/delete"})
        client = Mock()
        client.request.side_effect = [{"done": True}, {"organizations": []}]
        lifecycle.delete_evaluation({"project": "example", "organization": "example"}, client)
        self.assertTrue(json.loads(path.read_text())["deleted"])
        self.assertFalse(any(call.args[0] == "DELETE" for call in client.request.call_args_list))

    def test_archive_removes_old_active_inputs_but_keeps_tool_cache(self):
        directory = self.root / ".devspace"
        gateway.persist(directory / "gateway.json", {"project": "example"})
        gateway.persist(directory / "apigee-infra/evaluation.json", {"deleted": True})
        gateway.persist(directory / "toolchain-cache/keep.json", {})
        lifecycle.archive({"project": "example"})
        self.assertFalse((directory / "gateway.json").exists())
        self.assertTrue((directory / "environments/example/apigee-infra/evaluation.json").exists())
        self.assertTrue((directory / "toolchain-cache/keep.json").exists())

    def test_lost_delete_response_does_not_repeat_delete(self):
        gateway.persist(self.root / ".devspace/apigee-infra/evaluation.json", {"project": "example", "attempted": True, "delete_attempted": True})
        client = Mock()
        client.request.side_effect = [{"organizations": [{"organization": "example"}]}, {"organizations": []}, {"organizations": []}]
        with patch.object(lifecycle.time, "sleep"):
            lifecycle.delete_evaluation({"project": "example", "organization": "example"}, client)
        self.assertTrue(all(call.args[0] == "GET" for call in client.request.call_args_list))

    def test_leftover_ingress_blocks_generic_project_destruction(self):
        with patch.object(lifecycle, "wait_network"), patch.object(lifecycle, "cloud_list", return_value=[{"name": "devspace-apigee"}]):
            with self.assertRaisesRegex(RuntimeError, "still present"):
                lifecycle.verify_absence({"project": "example"}, {})

    def test_cleanup_refuses_release_override(self):
        a = {"synthetic_demo": True, "kubernetes": {"namespace": "owned"}, "demo": {"system_namespace": "owned-system"}}
        with patch.object(gateway.apigee, "read_state", return_value={}), patch.dict(gateway.os.environ, {"APIGEE_RELEASE": "shared-release"}):
            with self.assertRaisesRegex(ValueError, "ownership"):
                gateway.cleanup_check(a)

    def test_provisioning_never_selects_an_unrelated_active_gke(self):
        with patch.object(gateway, "starter_pack", return_value=self.root), patch.object(gateway, "output", return_value="gke_other_us-central1_shared"), patch.object(gateway, "run") as mutate:
            with self.assertRaisesRegex(ValueError, "unrelated"):
                gateway.kubernetes({"infrastructure": "provision"})
        mutate.assert_not_called()

    def test_callout_probe_requires_grpc_unauthenticated_over_verified_tls(self):
        import apigee_keycloak_test as checks
        config = {"context": "offline", "kubernetes": {"namespace": "owned"},
                  "callout": {"server_name": "callout.example.test", "certificate": "ca.crt"}}
        with patch.object(checks, "port_forward") as forward, patch.object(checks.apigee, "ROOT", self.root), patch.object(checks.subprocess, "run") as run:
            (self.root / ".devspace").mkdir()
            forward.return_value.__enter__.return_value = 12345
            run.return_value.stdout = b"HTTP/2 200\r\ngrpc-status: 16\r\n"
            checks.callout_authentication(config)
            self.assertEqual(run.call_count, 2)
            self.assertIn("--cacert", run.call_args.args[0])
            self.assertNotIn("--insecure", run.call_args.args[0])
            self.assertEqual(run.call_args.kwargs["input"], b"\0" * 5)
            run.return_value.stdout = b"HTTP/2 200\r\ngrpc-status: 0\r\n"
            with self.assertRaisesRegex(RuntimeError, "did not reject"):
                checks.callout_authentication(config)

    def test_provisioning_rejects_unexpected_paid_billing_type(self):
        import apigee_infra
        client = Mock()
        client.request.side_effect = [{"organizations": []}, {"name": "operations/provision"}, {"done": True}, {"billingType": "PAYG"}]
        with patch.object(apigee_infra, "gateway", gateway):
            with self.assertRaisesRegex(RuntimeError, "no paid fallback"):
                apigee_infra.evaluation({"project": "example", "region": "us-central1"}, client)

    def test_nested_deployment_discards_starting_gateway_variables(self):
        with patch.object(gateway, "output", return_value='["GATEWAY_PROVIDER", "REGISTRY", "APIGEE_FIXTURES_DISABLED"]'), patch.object(gateway, "run") as run:
            with patch.dict(gateway.os.environ, {"GATEWAY_PROVIDER": "local-istio", "REGISTRY": "wrong.invalid/repo", "APIGEE_FIXTURES_DISABLED": "true", "DEVSPACE_CONFIG": "old.yaml"}):
                gateway.application_deploy({"context": "selected"})
        env = run.call_args.kwargs["env"]
        for key in ("GATEWAY_PROVIDER", "REGISTRY", "APIGEE_FIXTURES_DISABLED", "DEVSPACE_CONFIG"):
            self.assertNotIn(key, env)
        self.assertEqual(env["DEVSPACE_CONTEXT"], "selected")

    def test_private_bootstrap_does_not_turn_placeholders_into_certificate_ips(self):
        import apigee
        config = {"project": "example", "organization": "example", "environment": "eval", "proxy": "txe-test", "region": "us-central1",
                  "callout": {"host": "127.0.0.1"}, "backend": {"host": "PENDING_BACKEND_SERVICE"},
                  "psc": {role: "projects/example/regions/us-central1/serviceAttachments/" + role for role in ("callout", "backend")}}
        attachments = ["txe-test-" + role + "-" + apigee.hashlib.sha256(config["psc"][role].encode()).hexdigest()[:10] for role in ("callout", "backend")]
        client = Mock()
        client.request.return_value = {"state": "ACTIVE", "connectionState": "ACCEPTED", "host": "10.0.0.2"}
        with patch.object(apigee, "read_state", return_value={"attachments": attachments}):
            apigee.psc(client, config)
        self.assertNotIn("public_targets", config)
        self.assertTrue(config["private_active"])

    def test_backend_readiness_requires_success_not_just_denial(self):
        import developer_runtime
        responses = [Mock(returncode=0, stdout="401"), Mock(returncode=0, stdout="200")]
        with patch.object(developer_runtime.subprocess, "run", side_effect=responses) as run, patch.object(developer_runtime.time, "sleep"):
            developer_runtime.wait_gateway({"url": "https://example.test", "certificate": "ca.crt"}, synthetic_exchange=True)
        self.assertEqual(run.call_count, 2)
        self.assertIn("Authorization: Bearer synthetic-subject", run.call_args.args[0])
        self.assertNotIn("--insecure", run.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
