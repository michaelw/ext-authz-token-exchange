#!/usr/bin/env python3
"""Start the local QA dashboard against existing Apigee demo infrastructure."""

import argparse
import json
import os
from pathlib import Path
import socket
import subprocess

import apigee
from developer_runtime import private_keycloak


def scenarios(c):
    source = json.loads(subprocess.check_output(["yq", "-o=json", ".", str(apigee.ROOT / "test/e2e/demo-scenarios.yaml")], text=True))
    overlay = json.loads(subprocess.check_output(["yq", "-o=json", ".", str(apigee.ROOT / c["demo"].get("scenario_settings", "test/e2e/demo-apigee.yaml"))], text=True))
    selected = []
    for item in source["scenarios"]:
        if item["name"] not in overlay["include"]:
            continue
        if item["name"] in overlay.get("policyRefs", {}):
            item["policy"] = overlay["policyRefs"][item["name"]]
        item["request"].setdefault("headers", {}).update(overlay.get("requestHeaders", {}))
        selected.append(item)
    source["scenarios"] = selected
    path = apigee.ROOT / ".devspace/apigee-dashboard-scenarios.json"
    path.write_text(json.dumps(source, indent=2) + "\n")
    return path


def run(c, args):
    if not c.get("synthetic_demo"):
        raise ValueError("the dashboard initializer is for owned synthetic fixtures")
    current = subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip()
    if current != c["context"]:
        raise ValueError("select the configured Kubernetes context first")
    host, port = args.listen.rsplit(":", 1)
    if host != "127.0.0.1":
        raise ValueError("keep the QA dashboard on 127.0.0.1")
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((host, int(port)))
    ns = c["demo"]["system_namespace"]
    with private_keycloak(c["context"], ns) as keycloak:
        k = c["kubernetes"]
        env = dict(os.environ, DEMO_BASE_URL=c["ingress"]["url"], DEMO_DIRECT_ADDRESS=c["ingress"].get("address", ""), DEMO_CA_CERT_FILE=str(Path(c["ingress"]["certificate"]).resolve()), DEMO_INSECURE_SKIP_VERIFY="false", DEMO_DASHBOARD_ADDR=args.listen, DEMO_PLUGIN_NAMESPACE=k["namespace"], DEMO_PLUGIN_DEPLOYMENT=k.get("release", "txe-apigee"), DEMO_SYSTEM_NAMESPACE=ns, DEMO_NAMESPACE_PREFIX=c["demo"]["backend_namespace"].removesuffix("-yellow"), DEMO_SCENARIO_CONFIG=str(scenarios(c)), DEMO_KEYCLOAK_BASE_URL=keycloak, DEMO_KEYCLOAK_ISSUER="http://keycloak." + ns + ".svc.cluster.local:8080/realms/token-exchange-e2e", DEMO_KEYCLOAK_DIRECT_ADDRESS="127.0.0.1")
        binary = Path(args.binary).resolve() if args.binary else apigee.build_go_binary("./cmd/demo-dashboard", apigee.ROOT / ".devspace/bin/demo-dashboard")
        command = [str(binary), *getattr(args, "dashboard_args", [])]
        env["DEMO_GATEWAY_KIND"] = "apigee"
        subprocess.run(command, cwd=apigee.ROOT, env=env, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=".devspace/apigee.json")
    parser.add_argument("--confirm", required=True)
    parser.add_argument("--listen", default="127.0.0.1:8088")
    parser.add_argument("--binary")
    args, args.dashboard_args = parser.parse_known_args()
    if args.dashboard_args and args.dashboard_args[0] == "--":
        args.dashboard_args.pop(0)
    config = apigee.load_config(args.config)
    apigee.confirmed(config, args)
    try:
        run(config, args)
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except (ValueError, RuntimeError, OSError, subprocess.CalledProcessError) as error:
        print("E:", error)
        raise SystemExit(1) from None
