#!/usr/bin/env python3
"""Run the same dashboard and Go tests for local and GKE Gateway development."""

import contextlib
import os
import subprocess
import sys

import apigee
import gateway
from developer_runtime import private_keycloak


def run(command, args):
    if gateway.load().get("gateway") == "apigee":
        gateway.dispatch("dashboard" if command == "dashboard" else "test-e2e", args)
        return
    env = dict(os.environ)
    context = subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip()
    prefix = "DEMO" if command == "dashboard" else "E2E"
    selected = gateway.load()
    ingress = selected.get("ingress", {})
    if selected.get("gateway") == "gke-gateway" and ingress:
        env[prefix + "_BASE_URL"] = ingress["url"]
        env[prefix + "_DIRECT_ADDRESS"] = ingress["address"]
        env[prefix + "_CA_CERT_FILE"] = str(gateway.ROOT / ingress["certificate"])
        env[prefix + "_INSECURE_SKIP_VERIFY"] = "false"
    namespace = env.get(prefix + "_SYSTEM_NAMESPACE", env.get("E2E_DEMO_NAMESPACE", "ext-authz-token-exchange-e2e"))
    private = context.startswith("gke_") and env.get(prefix + "_KEYCLOAK_ACCESS", "private") == "private"
    if private:
        exists = subprocess.run(["kubectl", "--context=" + context, "-n", namespace, "get", "service", "keycloak"], capture_output=True).returncode == 0
        private = exists
        if not exists:
            env[prefix + "_KEYCLOAK_BASE_URL"] = ""
    access = private_keycloak(context, namespace) if private else contextlib.nullcontext(None)
    with access as issuer:
        if issuer:
            env[prefix + "_KEYCLOAK_BASE_URL"] = issuer
            env[prefix + "_KEYCLOAK_DIRECT_ADDRESS"] = "127.0.0.1"
        if command == "dashboard":
            binary = apigee.build_go_binary("./cmd/demo-dashboard", apigee.ROOT / ".devspace/bin/demo-dashboard")
            subprocess.run([str(binary), *args], env=env, check=True)
        else:
            binary = apigee.build_go_binary("./test/e2e", apigee.ROOT / ".devspace/bin/gateway-e2e.test", test=True)
            flags = ["-ginkgo." + arg[2:] if arg.startswith("--") else arg for arg in args]
            if not any("label-filter" in flag for flag in flags):
                flags.append("-ginkgo.label-filter=!stress")
            env.setdefault("E2E_SKIP_INSTALL", "true")
            env.setdefault("E2E_SKIP_CLEANUP", "true")
            env["E2E_GATEWAY_CONTRACT"] = "false" if any("focus" in flag or "label-filter=stress" in flag for flag in flags) else "true"
            subprocess.run([str(binary), "-test.count=1", "-test.timeout=15m", *flags], env=env, check=True)


if __name__ == "__main__":
    arguments = sys.argv[2:]
    if arguments and arguments[0] == "--":
        arguments.pop(0)
    try:
        run(sys.argv[1], arguments)
    except KeyboardInterrupt:
        sys.exit(130)
    except subprocess.CalledProcessError as error:
        sys.exit(error.returncode)
