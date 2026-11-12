"""Resolve real DevSpace profiles using an unreachable synthetic cluster."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


@unittest.skipUnless(shutil.which("devspace") and shutil.which("yq"), "shared tooling container required")
class ProfileTests(unittest.TestCase):
    def test_provider_isolation_without_cloud_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "project"
            workspace.mkdir()
            root = Path(__file__).resolve().parents[1]
            for name in ("devspace.yaml", "scripts", "charts"):
                (workspace / name).symlink_to(root / name)
            kubeconfig = Path(directory) / "kubeconfig"
            kubeconfig.write_text(json.dumps({"apiVersion": "v1", "kind": "Config", "current-context": "gke_example_us-central1_cluster",
                "contexts": [{"name": "gke_example_us-central1_cluster", "context": {"cluster": "offline", "user": "offline"}}],
                "clusters": [{"name": "offline", "cluster": {"server": "https://127.0.0.1:9"}}], "users": [{"name": "offline", "user": {}}]}))
            for provider, fixtures, keycloak in (("local-istio", False, False), ("gke-gateway", False, False),
                                                ("apigee", True, True), ("apigee", True, False), ("apigee", False, False)):
                with self.subTest(provider=provider, fixtures=fixtures, keycloak=keycloak):
                    args = ["devspace", "--kubeconfig", str(kubeconfig), "--namespace", "default"]
                    variables = {"GATEWAY_PROVIDER": provider, "REGISTRY": "example.invalid/dev", "DEV_REGISTRY": "example.invalid/dev",
                        "GKE_PROJECT_ID": "example", "GKE_REGION": "us-central1", "DEPLOYMENT_DOMAIN": "example.test",
                        "GATEWAY_NAMESPACE": "gateway", "GKE_GATEWAY_NAME": "dedicated-gateway", "DEV_REGISTRY_IMAGE_PREFIX": "example.invalid/dev", "GKE_MANAGE_GATEWAY": "false", "KEYCLOAK_ENABLED": "false",
                        "IMAGE_TAG": "offline", "APIGEE_NAMESPACE": "txe-test", "APIGEE_RELEASE": "txe-test",
                        "APIGEE_SYSTEM_NAMESPACE": "txe-test-system", "APIGEE_PLUGIN_VALUES": "plugin.yaml",
                        "APIGEE_DEMO_VALUES": "demo.yaml", "APIGEE_KEYCLOAK_VALUES": "keycloak.yaml",
                        "APIGEE_FIXTURES_DISABLED": str(not fixtures).lower(), "APIGEE_KEYCLOAK_DISABLED": str(not keycloak).lower()}
                    variables["GATEWAY_SETUP_PROVIDER"] = "none" if provider == "local-istio" else provider
                    if provider != "local-istio":
                        args += ["--profile", "with-infra"]
                    for key, value in variables.items():
                        args += ["--var", key + "=" + value]
                    env = dict(os.environ, KUBECONFIG=str(kubeconfig), DEVSPACE_CONTEXT="gke_example_us-central1_cluster")
                    rendered = subprocess.check_output(args + ["print", "--skip-info"], cwd=workspace, env=env, text=True, timeout=60)
                    config = json.loads(subprocess.check_output(["yq", "-o=json", "."], input=rendered, text=True))
                    if provider == "apigee":
                        self.assertFalse(config.get("dependencies"))
                        self.assertEqual(config["deployments"]["ext-authz-token-exchange"]["helm"]["releaseName"], "txe-test")
                        self.assertNotIn("run_dependencies", config["pipelines"]["deploy"]["run"])
                        self.assertNotIn("purge_deployments", config["pipelines"]["purge"]["run"])
                        self.assertEqual("keycloak" in config["deployments"], keycloak)
                        self.assertEqual("ext-authz-token-exchange-e2e" in config["deployments"], fixtures)
                        dev = config["dev"]["ext-authz-token-exchange"]
                        self.assertEqual(dev["resources"]["limits"]["ephemeral-storage"], "4Gi")
                        self.assertNotEqual(dev["workingDir"], "/tmp/txe-source")
                    else:
                        values = config["deployments"]["ext-authz-token-exchange"]["helm"]["values"]
                        self.assertEqual(values["gatewayProvider"], provider)
                        fixtures_values = config["deployments"]["ext-authz-token-exchange-e2e"]["helm"]["values"]
                        for section in ("platformRoutes", "demoRoute", "inferencePool"):
                            self.assertEqual(fixtures_values[section]["gatewayNamespace"], "gateway")
                            self.assertEqual(fixtures_values[section]["gatewayName"], "dedicated-gateway")
                        self.assertNotIn("keycloak", config["deployments"])
                        self.assertFalse(config.get("dependencies"))


if __name__ == "__main__":
    unittest.main()
