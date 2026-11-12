#!/usr/bin/env python3
"""Run the existing Keycloak specs through Apigee without public issuer ingress."""

import argparse
import json
import re
import os
from pathlib import Path
import subprocess

import apigee
from developer_runtime import private_keycloak, port_forward


def callout_authentication(c):
    k = c["kubernetes"]
    results = []
    with port_forward(c["context"], k["namespace"], k.get("release", "txe-apigee") + "-apigee", 443) as port:
        host = c["callout"]["server_name"]
        for name, authorization in (("missing", None), ("invalid", "Bearer synthetic-invalid-google-token")):
            command = ["curl", "--silent", "--show-error", "--max-time", "15", "--http2", "--noproxy", "*", "--cacert", c["callout"]["certificate"],
                       "--resolve", f"{host}:{port}:127.0.0.1", "-D", "-", "-o", "/dev/null", "-H", "content-type: application/grpc", "-H", "te: trailers", "--data-binary", "@-"]
            if authorization:
                command += ["-H", "Authorization: " + authorization]
            response = subprocess.run(command + [f"https://{host}:{port}/apigee.ExternalCalloutService/ProcessMessage"], input=b"\0" * 5, capture_output=True, check=True)
            statuses = re.findall(rb"(?im)^grpc-status:\s*(\d+)\s*$", response.stdout)
            if statuses != [b"16"]:
                raise RuntimeError("callout did not reject " + name + " gateway credentials")
            results.append({"credentials": name, "grpc_status": 16})
    (apigee.ROOT / ".devspace/apigee-callout-auth.json").write_text(json.dumps(results, indent=2) + "\n")
    print("Private TLS callout rejected missing and invalid gateway credentials")


def run(c):
    if not c.get("synthetic_demo"):
        raise ValueError("Keycloak tests require synthetic fixtures")
    current = subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip()
    if current != c["context"]:
        raise ValueError("select the configured cluster context before running tests")
    binary = apigee.build_go_binary("./test/e2e", apigee.ROOT / ".devspace/bin/apigee-keycloak.test", test=True)
    ns = c["demo"]["system_namespace"]
    with private_keycloak(c["context"], ns) as base:
        report = apigee.ROOT / ".devspace/apigee-keycloak-report.json"
        report.touch(mode=0o600, exist_ok=True)
        os.chmod(report, 0o600)
        env = dict(os.environ, E2E_BASE_URL=c["ingress"]["url"], E2E_NAMESPACE=c["kubernetes"]["namespace"], E2E_RELEASE=c["kubernetes"].get("release", "txe-apigee"), E2E_DEMO_NAMESPACE=ns, E2E_NAMESPACE_PREFIX=c["demo"]["backend_namespace"].removesuffix("-yellow"), E2E_SKIP_INSTALL="true", E2E_SKIP_CLEANUP="true", E2E_KEYCLOAK_BASE_URL=base, E2E_KEYCLOAK_ISSUER="http://keycloak." + ns + ".svc.cluster.local:8080/realms/token-exchange-e2e", E2E_DIRECT_ADDRESS=c["ingress"].get("address", ""), E2E_KEYCLOAK_DIRECT_ADDRESS="127.0.0.1", E2E_INSECURE_SKIP_VERIFY="false", E2E_EXPECT_INSECURE_TOKEN_LOGS="false", SSL_CERT_FILE=str(Path(c["ingress"]["certificate"]).resolve()))
        env["E2E_ISSUER_PROFILES_CONFIGMAP"] = c["kubernetes"].get("issuer_profiles_configmap", c["kubernetes"].get("release", "txe-apigee") + "-issuer-profiles")
        env["E2E_CA_CERT_FILE"] = env["SSL_CERT_FILE"]
        env["E2E_GATEWAY_CONTRACT"] = "true"
        apigee.wait_gateway(c)
        subprocess.run([str(binary), "-test.run=TestGatewayContract", "-test.v", "-test.count=1"], cwd=apigee.ROOT, env=env, check=True)
        callout_authentication(c)
        env["E2E_GATEWAY_CONTRACT"] = "false"
        subprocess.run([str(binary), "-test.count=1", "-test.timeout=10m", "-ginkgo.focus=keycloak token exchange", "-ginkgo.json-report=" + str(report)], cwd=apigee.ROOT, env=env, check=True)
        os.chmod(report, 0o600)
        data = json.loads(report.read_text())
        passed = sum(spec["State"] == "passed" and "keycloak token exchange" in (spec.get("ContainerHierarchyTexts") or []) for suite in data for spec in suite["SpecReports"])
        if passed < 8:
            raise RuntimeError("Keycloak specs were skipped or incomplete")
        print("Existing Keycloak specs passed:", passed)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=".devspace/apigee.json")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    config = apigee.load_config(args.config)
    apigee.confirmed(config, args)
    run(config)
