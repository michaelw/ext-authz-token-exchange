import importlib.util
import io
import json
from pathlib import Path
import tempfile
import subprocess
import urllib.error
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET
import zipfile

spec = importlib.util.spec_from_file_location("apigee", Path(__file__).with_name("apigee.py"))
apigee = importlib.util.module_from_spec(spec)
spec.loader.exec_module(apigee)


class ApigeeToolTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.certificate = self.root / "ca.pem"
        self.certificate.write_text("synthetic certificate")
        self.config = {"project": "example-project", "context": "example-context", "organization": "example-project", "environment": "eval", "proxy": "txe-test", "proxy_service_account": "proxy@example-project.iam.gserviceaccount.com", "callout": {"host": "callout.example", "port": 443, "certificate": str(self.certificate), "audience": "callout-audience"}, "backend": {"host": "backend.example", "port": 8080, "certificate": str(self.certificate)}}

    def test_existing_paid_preflight_does_not_provision_or_enable_demo(self):
        c = dict(self.config, synthetic_demo=False, private_active=True, proxy_subject="123", acceptance_probe={"path":"/canary", "status":401}, ingress={"url":"https://api.example", "certificate":str(self.certificate)})
        permissions = ["apigee.deployments.create", "apigee.deployments.get", "apigee.deployments.delete"]
        replies = [{"state":"ACTIVE", "billingType":"SUBSCRIPTION"}, {"name":"production"}, {"permissions":permissions}]
        client = unittest.mock.Mock()
        client.request.side_effect = replies
        with patch.object(apigee.subprocess, "check_output", return_value='{"uniqueId":"123"}'), patch.object(apigee.subprocess, "run"):
            apigee.preflight(client, c)
        self.assertTrue(all(call.args[0] == "GET" or call.args[1].endswith(":testIamPermissions") for call in client.request.call_args_list))
        self.assertFalse(c["synthetic_demo"])
        client.request.side_effect = replies[:2] + [{"permissions":[]}]
        with self.assertRaisesRegex(ValueError, "permissions"):
            apigee.preflight(client, c)

    def test_operator_probe_uses_supplied_trust_and_no_demo_credentials(self):
        c = dict(self.config, ingress={"url":"https://api.example", "certificate":str(self.certificate)}, acceptance_probe={"path":"/canary", "status":401})
        with patch.object(apigee.subprocess, "check_output", return_value="401") as request:
            apigee.smoke(c)
        self.assertIn("--cacert", request.call_args.args[0])
        self.assertNotIn("--insecure", request.call_args.args[0])
        self.assertNotIn("Authorization", " ".join(request.call_args.args[0]))
        c["acceptance_probe"]["path"] = "//attacker.example/path"
        with self.assertRaises(ValueError):
            apigee.smoke(c)

    def test_overlap_trust_imports_each_anchor_as_an_independent_alias(self):
        certificates = [b"-----BEGIN CERTIFICATE-----\nT0xE\n-----END CERTIFICATE-----", b"-----BEGIN CERTIFICATE-----\nTkVX\n-----END CERTIFICATE-----"]
        self.certificate.write_bytes(b"\n".join(certificates))
        client = unittest.mock.Mock()
        client.request.return_value = None
        with patch.object(apigee, "save_state"):
            apigee.configure_targets(client, self.config, {"targets":[], "truststores":[], "references":[]})
        uploads = [call.args[2] for call in client.request.call_args_list if call.args[0] == "POST" and "/aliases?" in call.args[1]]
        self.assertEqual(len(uploads), 4)
        self.assertTrue(all(data.count(b"-----BEGIN CERTIFICATE-----") == 1 for data in uploads))
        self.assertTrue(all(any(cert in upload for upload in uploads) for cert in certificates))

    def test_bundle_is_deterministic_and_fail_closed(self):
        first = apigee.bundle(self.config)
        self.assertEqual(first, apigee.bundle(self.config))
        with zipfile.ZipFile(io.BytesIO(first)) as archive:
            policy = ET.fromstring(archive.read("apiproxy/policies/EC-TokenExchange.xml"))
            self.assertEqual(policy.attrib["continueOnError"], "false")
            self.assertEqual(policy.findtext("GrpcConnection/Authentication/GoogleIDToken/Audience"), "callout-audience")
            self.assertEqual(policy.findtext("Configurations/Property[@name='with.request.content']"), "false")
            proxy = ET.fromstring(archive.read("apiproxy/proxies/default.xml"))
            self.assertEqual(proxy.findall("PreFlow/Request/Step/Name")[-1].text, "RF-InvalidDecision")
            self.assertIn("request.uri", archive.read("apiproxy/policies/AM-Initialize.xml").decode())

    def test_export_comparison_ignores_only_generated_proxy_metadata(self):
        expected = apigee.bundle(self.config)
        buffer = io.BytesIO()
        with zipfile.ZipFile(io.BytesIO(expected)) as source, zipfile.ZipFile(buffer, "w") as result:
            for name in source.namelist():
                data = source.read(name)
                if name == "apiproxy/txe-test.xml":
                    doc = ET.fromstring(data)
                    doc.set("revision", "8")
                    ET.SubElement(doc, "CreatedAt").text = "123"
                    ET.SubElement(doc, "Policies")
                    data = ET.tostring(doc)
                result.writestr(name, data)
        self.assertEqual(apigee.bundle_contents(expected), apigee.bundle_contents(buffer.getvalue()))
        changed = dict(self.config, timeout_ms=1234)
        self.assertNotEqual(apigee.bundle_contents(expected), apigee.bundle_contents(apigee.bundle(changed)))

    def test_temporary_inspection_requires_matching_context_and_ownership(self):
        self.config["kubernetes"] = {"namespace": "txe-test", "release": "txe-test"}
        with patch.object(apigee.subprocess, "check_output", return_value="wrong-context"):
            with patch.object(apigee, "kubectl") as command:
                with self.assertRaisesRegex(ValueError, "context"):
                    apigee.inspection(self.config, True)
                command.assert_not_called()
        for enabled in (True, False):
            calls = []
            def record(_config, *args):
                calls.append(args)
                return json.dumps({"metadata": {"labels": {"app.kubernetes.io/instance": "txe-test"}}})
            with patch.object(apigee.subprocess, "check_output", return_value="example-context"):
                with patch.object(apigee, "kubectl", side_effect=record):
                    apigee.inspection(self.config, enabled)
            settings = calls[1]
            self.assertIn("APIGEE_INSPECT_MESSAGES=" + str(enabled).lower(), settings)
            self.assertNotIn("TOKEN_EXCHANGE_INSECURE_LOG_TOKENS=true", settings)
            if not enabled:
                self.assertIn("TOKEN_EXCHANGE_INSECURE_LOG_TOKENS=false", settings)

    def test_logging_qa_restores_settings_on_failure(self):
        spec = importlib.util.spec_from_file_location("logging_qa", Path(__file__).with_name("apigee_logging_test.py"))
        qa = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(qa)
        self.config.update(synthetic_demo=True, kubernetes={"namespace": "txe-test", "release": "txe-test"})
        original_env = [{"name": "TOKEN_EXCHANGE_LOG_FORMAT", "value": "text"}]
        calls = []
        def record(_config, *args):
            calls.append(args)
            if args[:2] == ("get", "namespace"):
                return json.dumps({"metadata": {"labels": {"txe-apigee-demo": "owned"}}})
            if "get" in args:
                return json.dumps({"metadata": {"labels": {"app.kubernetes.io/instance": "txe-test"}}, "spec": {"template": {"spec": {"containers": [{"env": original_env}]}}}})
            return ""
        with patch.object(qa, "apigee", apigee), patch.object(apigee, "wait_gateway"):
            with patch.object(apigee.subprocess, "check_output", return_value="example-context"):
                with patch.object(apigee, "kubectl", side_effect=record):
                    with patch.object(apigee, "smoke", side_effect=RuntimeError("synthetic failure")):
                        with self.assertRaisesRegex(RuntimeError, "synthetic failure"):
                            qa.run(self.config)
        patches = [json.loads(args[-1]) for args in calls if "patch" in args]
        self.assertEqual(len(patches), 2)
        self.assertEqual(patches[-1][0]["value"], original_env)

    def test_log_format_changes_only_its_setting(self):
        with patch.object(apigee, "logging_settings") as update:
            for value in ("json", "text"):
                apigee.log_format(self.config, value)
                update.assert_called_with(self.config, ["TOKEN_EXCHANGE_LOG_FORMAT=" + value])
            update.reset_mock()
            with self.assertRaises(ValueError):
                apigee.log_format(self.config, "invalid")
            update.assert_not_called()

    def test_developer_binary_build_uses_the_shared_container(self):
        with patch.object(apigee, "ROOT", self.root), patch.dict(apigee.os.environ, {"TXE_TOOLCHAIN_ACTIVE": "false"}):
            with patch.object(apigee.platform, "system", return_value="Darwin"):
                with patch.object(apigee.platform, "machine", return_value="arm64"):
                    with patch.object(apigee.subprocess, "run") as command:
                        apigee.build_go_binary("./test/e2e", self.root / ".devspace/bin/e2e.test", test=True)
        args = command.call_args.args[0]
        self.assertEqual(args[:4], ["docker", "run", "--rm", "--pull=never"])
        self.assertIn("GOOS=darwin", args)
        self.assertIn("GOARCH=arm64", args)
        self.assertIn("go generate ./...", " ".join(args))
        self.assertEqual(args[-6:], ["go", "test", "-c", "-o", "/workspace/.devspace/bin/e2e.test", "./test/e2e"])

    def test_developer_binary_reuses_the_running_toolchain(self):
        with patch.object(apigee, "ROOT", self.root), patch.dict(apigee.os.environ, {"TXE_TOOLCHAIN_ACTIVE": "true"}), \
             patch.object(apigee.subprocess, "run") as command:
            destination = (self.root / ".devspace/bin/e2e.test").resolve()
            self.assertEqual(apigee.build_go_binary("./test/e2e", destination, test=True), destination)
        args = command.call_args.args[0]
        self.assertNotIn("docker", args)
        self.assertIn("go generate ./...", " ".join(args))
        self.assertEqual(args[-6:], ["go", "test", "-c", "-o", str(destination), "./test/e2e"])
        self.assertEqual(command.call_args.kwargs["cwd"], self.root)

    def test_target_identity_changes_with_address_or_certificate(self):
        original = apigee.target_name(self.config, "callout")
        self.config["callout"]["host"] = "private.example"
        self.assertNotEqual(original, apigee.target_name(self.config, "callout"))
        original = apigee.target_name(self.config, "callout")
        self.certificate.write_text("rotated synthetic certificate")
        self.assertNotEqual(original, apigee.target_name(self.config, "callout"))

    def test_external_targets_and_base_path_do_not_require_ownership(self):
        self.config["manage_targets"] = False
        self.config["base_path"] = "/isolated"
        self.config["callout"]["name"] = "platform-callout"
        self.config["backend"]["name"] = "platform-backend"
        with zipfile.ZipFile(io.BytesIO(apigee.bundle(self.config))) as archive:
            proxy = ET.fromstring(archive.read("apiproxy/proxies/default.xml"))
            self.assertEqual(proxy.findtext("HTTPProxyConnection/BasePath"), "/isolated")
            callout = ET.fromstring(archive.read("apiproxy/policies/EC-TokenExchange.xml"))
            self.assertEqual(callout.find("GrpcConnection/Server").get("name"), "platform-callout")

    def test_load_config_rejects_non_dedicated_proxy(self):
        self.config["proxy"] = "shared-proxy"
        path = self.root / "config.json"
        path.write_text(json.dumps(self.config))
        with self.assertRaises(ValueError):
            apigee.load_config(path)

    def test_supplied_ownership_state_must_identify_exact_proxy(self):
        path = self.root / "ownership.json"
        path.write_text(json.dumps({"owns_proxy": True, "revisions": ["7"]}))
        config = dict(self.config, ownership_state=str(path))
        with self.assertRaisesRegex(ValueError, "ownership state"):
            apigee.read_state(config)
        target = {key: self.config[key] for key in ("organization", "environment", "proxy")}
        path.write_text(json.dumps({"target": target, "revisions": ["7"]}))
        self.assertEqual(apigee.read_state(config)["revisions"], ["7"])

    def test_refuses_unowned_existing_proxy_before_mutation(self):
        class ExistingProxy:
            def request(self, method, *_args, **_kwargs):
                if method != "GET":
                    raise AssertionError("must not mutate")
                if _args[0].endswith("/instances"):
                    return {"instances": [{"state": "ACTIVE"}]}
                return {"name": "txe-test"}
        with patch.object(apigee, "state_path", return_value=self.root / "state.json"):
            with self.assertRaisesRegex(RuntimeError, "ownership"):
                apigee.deploy(ExistingProxy(), self.config)

    def test_cleanup_only_removes_recorded_resources(self):
        calls = []
        class Recorder:
            def request(self, method, resource, **_kwargs):
                if method == "GET":
                    return {"deployments": [{"revision": "7"}]}
                calls.append((method, resource))
                return {}
        state = {"revisions": ["7"], "targets": ["txe-owned"], "truststores": ["txe-ca"], "attachments": ["txe-psc"]}
        path = self.root / "state.json"
        path.write_text(json.dumps(state))
        with patch.object(apigee, "state_path", return_value=path):
            apigee.cleanup(Recorder(), self.config)
        self.assertEqual(len(calls), 5)
        self.assertTrue(all(method == "DELETE" for method, _ in calls))
        self.assertFalse(any(resource.endswith("/apis/txe-test") for _, resource in calls))
        self.assertFalse(path.exists())

    def test_psc_uses_bounded_names_and_preserves_public_targets(self):
        self.config["region"] = "example-region"
        self.config["callout"]["host"] = "192.0.2.1"
        self.config["backend"]["host"] = "192.0.2.2"
        self.config["psc"] = {role: "projects/example/regions/example/serviceAttachments/" + role for role in ("callout", "backend")}
        class PSC:
            def request(self, method, resource, *args, **kwargs):
                self_name = resource.rsplit("/", 1)[-1]
                self.assert_valid(self_name)
                return {"state": "ACTIVE", "connectionState": "ACCEPTED", "host": "10.0.0.2"}
            def assert_valid(self, name):
                if len(name) > 32:
                    raise AssertionError("endpoint attachment ID exceeds Apigee limit")
        state = {"revisions": [], "targets": [], "truststores": [], "attachments": ["txe-test-callout-" + apigee.hashlib.sha256(self.config["psc"]["callout"].encode()).hexdigest()[:10], "txe-test-backend-" + apigee.hashlib.sha256(self.config["psc"]["backend"].encode()).hexdigest()[:10]]}
        with patch.object(apigee, "read_state", return_value=state):
            apigee.psc(PSC(), self.config)
        self.assertEqual(self.config["public_targets"]["callout"], "192.0.2.1")
        self.assertTrue(self.config["private_active"])

    def test_pending_revision_is_resumed_without_another_import(self):
        calls = []
        class Deployment:
            def request(self, method, resource, *_args, **_kwargs):
                calls.append((method, resource))
                if resource.endswith("/instances"):
                    return {"instances": [{"state": "ACTIVE"}]}
                return {"revision": ["7"]}
        digest = apigee.hashlib.sha256(apigee.bundle(self.config)).hexdigest()
        state = {"revisions": ["7"], "pending": {"revision": "7", "digest": digest}}
        with patch.object(apigee, "read_state", return_value=state), patch.object(apigee, "save_state"), patch.object(apigee, "configure_targets"), patch.object(apigee, "wait_ready"):
            apigee.deploy(Deployment(), self.config)
        self.assertFalse(any("action=import" in resource for _, resource in calls))
        self.assertEqual(state["current"], "7")
        self.assertNotIn("pending", state)

    def test_provider_error_is_private_and_does_not_shadow_request_path(self):
        error = urllib.error.HTTPError("https://example.invalid", 400, "bad request", {}, io.BytesIO(b'{"secret":"synthetic-secret"}'))
        with patch.object(apigee, "ROOT", self.root), patch.object(apigee.subprocess, "check_output", return_value="synthetic-token"), patch.object(apigee.urllib.request, "urlopen", side_effect=error):
            with self.assertRaisesRegex(RuntimeError, "GET organizations/example returned HTTP 400") as caught:
                apigee.Client(self.config).request("GET", "organizations/example")
        self.assertNotIn("secret", str(caught.exception))
        saved = self.root / ".devspace/apigee-debug/api-error.json"
        self.assertEqual(saved.stat().st_mode & 0o777, 0o600)

    def test_failed_deployment_rolls_back_previous_revision(self):
        calls = []
        class Deployment:
            def request(self, method, resource, *_args, **_kwargs):
                calls.append((method, resource))
                if resource.endswith("/instances"):
                    return {"instances": [{"state": "ACTIVE"}]}
                if "action=import" in resource:
                    return {"revision": "8"}
                if method == "POST" and "/revisions/8/" in resource:
                    raise RuntimeError("synthetic deployment failure")
                return {"revision": ["7"]}
        state = {"revisions": ["7"], "current": "7"}
        with patch.object(apigee, "read_state", return_value=state), patch.object(apigee, "save_state"), patch.object(apigee, "configure_targets"), patch.object(apigee, "wait_ready"):
            with self.assertRaisesRegex(RuntimeError, "synthetic deployment failure"):
                apigee.deploy(Deployment(), self.config)
        self.assertTrue(any(method == "POST" and "/revisions/7/" in resource for method, resource in calls))
        self.assertEqual(state["current"], "7")

    def test_explicit_rollback_updates_hash_only_after_readiness(self):
        state = {"revisions": ["6", "7"], "current": "7", "digest": "new", "revision_digests": {"6": "old", "7": "new"}}
        client = unittest.mock.Mock()
        with patch.object(apigee, "read_state", return_value=state), patch.object(apigee, "save_state") as save:
            with patch.object(apigee, "wait_ready", side_effect=RuntimeError("not ready")):
                with self.assertRaisesRegex(RuntimeError, "not ready"):
                    apigee.rollback(client, self.config, "6")
            self.assertEqual(state["current"], "7")
            save.assert_not_called()
            with patch.object(apigee, "wait_ready"):
                apigee.rollback(client, self.config, "6")
            self.assertEqual(state["current"], "6")
            self.assertEqual(state["digest"], "old")

    def test_psc_resumes_recorded_operation_without_creating_attachment(self):
        self.config.update(region="us-central1", psc={role: "projects/example/regions/us-central1/serviceAttachments/" + role for role in ("callout", "backend")})
        names = ["txe-test-" + role + "-" + apigee.hashlib.sha256(self.config["psc"][role].encode()).hexdigest()[:10] for role in ("callout", "backend")]
        state = {"attachments": names, "attachment_operations": {names[0]: "organizations/example/operations/resume"}}
        client = unittest.mock.Mock()
        client.request.side_effect = lambda method, path, **kwargs: {"done": True} if path.endswith("/resume") else {"state": "ACTIVE", "connectionState": "ACCEPTED", "host": "10.0.0.2"}
        with patch.object(apigee, "read_state", return_value=state), patch.object(apigee, "save_state"):
            apigee.psc(client, self.config)
        self.assertFalse(any(call.args[0] == "POST" for call in client.request.call_args_list))
        self.assertFalse(state["attachment_operations"])

    def test_lost_import_response_reconciles_unique_matching_bundle(self):
        data = apigee.bundle(self.config)
        digest = apigee.hashlib.sha256(data).hexdigest()
        state = {"owns_proxy": True, "revisions": ["7"], "pending": {"digest": digest, "before": ["7"]}}
        calls = []
        class Client:
            def request(self, method, resource, *args, **kwargs):
                calls.append((method, resource))
                if resource.endswith("/instances"):
                    return {"instances": [{"state": "ACTIVE"}]}
                if "format=bundle" in resource:
                    return data
                return {"revision": ["7", "8"]}
        with patch.object(apigee, "read_state", return_value=state), patch.object(apigee, "save_state"), patch.object(apigee, "configure_targets"), patch.object(apigee, "wait_ready"):
            apigee.deploy(Client(), self.config)
        self.assertEqual(state["current"], "8")
        self.assertFalse(any("action=import" in resource for _, resource in calls))

    def test_lost_import_response_refuses_ambiguous_revisions(self):
        digest = apigee.hashlib.sha256(apigee.bundle(self.config)).hexdigest()
        state = {"owns_proxy": True, "revisions": ["7"], "pending": {"digest": digest, "before": ["7"]}}
        class Client:
            def request(self, method, resource, *args, **kwargs):
                if method != "GET":
                    raise AssertionError("must not import")
                return {"instances": [{"state": "ACTIVE"}]} if resource.endswith("/instances") else {"revision": ["7", "8", "9"]}
        with patch.object(apigee, "read_state", return_value=state), patch.object(apigee, "configure_targets"):
            with self.assertRaisesRegex(RuntimeError, "ambiguous"):
                apigee.deploy(Client(), self.config)

    def test_only_reads_retry_ambiguous_transport_failures(self):
        for method in ("GET", "POST"):
            with self.subTest(method=method), patch.object(apigee.subprocess, "check_output", return_value="synthetic-token"), patch.object(apigee.time, "sleep"), patch.object(apigee.urllib.request, "urlopen", side_effect=[urllib.error.URLError("synthetic disconnect"), io.BytesIO(b"{}")]) as request:
                if method == "GET":
                    self.assertEqual(apigee.Client(self.config).request(method, "organizations/example"), {})
                    self.assertEqual(request.call_count, 2)
                else:
                    with self.assertRaisesRegex(RuntimeError, "inspect state"):
                        apigee.Client(self.config).request(method, "organizations/example", {})
                    self.assertEqual(request.call_count, 1)

    def test_certificate_rotation_includes_endpoint_ip_sans(self):
        import sys
        with patch.dict(sys.modules, {"apigee": apigee}):
            demo_spec = importlib.util.spec_from_file_location("apigee_demo", Path(__file__).with_name("apigee_demo.py"))
            demo = importlib.util.module_from_spec(demo_spec)
            demo_spec.loader.exec_module(demo)
        cert, _ = demo.certificate(self.root, "synthetic.example", addresses=["192.0.2.1", "10.0.0.2"])
        sans = subprocess.check_output(["openssl", "x509", "-in", cert, "-noout", "-ext", "subjectAltName"], text=True)
        self.assertIn("DNS:synthetic.example", sans)
        self.assertIn("IP Address:192.0.2.1", sans)
        self.assertIn("IP Address:10.0.0.2", sans)


if __name__ == "__main__":
    unittest.main()
