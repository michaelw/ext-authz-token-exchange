#!/usr/bin/env python3
"""Developer-only logging QA; temporarily changes an owned synthetic plugin."""

import argparse
import json
from pathlib import Path
import subprocess
import urllib.parse

import apigee


def run(c):
    if not c.get("synthetic_demo"):
        raise ValueError("logging QA requires owned synthetic fixtures")
    current = subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip()
    if current != c["context"]:
        raise ValueError("select the configured Kubernetes context explicitly")
    k = c["kubernetes"]
    release = k.get("release", "txe-apigee")
    if not release.startswith("txe-"):
        raise ValueError("logging QA requires a dedicated txe- deployment")
    namespace = json.loads(apigee.kubectl(c, "get", "namespace", k["namespace"], "-o", "json"))
    if namespace["metadata"].get("labels", {}).get("txe-apigee-demo") != "owned":
        raise ValueError("refusing to change an unowned namespace")
    deployment = "deployment/" + release
    original = json.loads(apigee.kubectl(c, "-n", k["namespace"], "get", deployment, "-o", "json"))
    if original["metadata"].get("labels", {}).get("app.kubernetes.io/instance") != release:
        raise ValueError("plugin deployment ownership does not match")
    original_env = original["spec"]["template"]["spec"]["containers"][0].get("env", [])
    overrides = {"TOKEN_EXCHANGE_LOG_FORMAT": "json", "APIGEE_INSPECT_MESSAGES": "true", "TOKEN_EXCHANGE_INSECURE_LOG_TOKENS": "false"}
    temporary_env = [item for item in original_env if item["name"] not in overrides]
    temporary_env += [{"name": key, "value": value} for key, value in overrides.items()]

    def apply(env):
        patch = [{"op": "add", "path": "/spec/template/spec/containers/0/env", "value": env}]
        apigee.kubectl(c, "-n", k["namespace"], "patch", deployment, "--type=json", "-p", json.dumps(patch))
        apigee.kubectl(c, "-n", k["namespace"], "rollout", "status", deployment, "--timeout=300s")

    try:
        apply(temporary_env)
        apigee.smoke(c)
        ingress = c["ingress"]
        host = urllib.parse.urlparse(ingress["url"]).hostname
        command = ["curl", "--silent", "--show-error", "--max-time", "15", "--cacert", ingress["certificate"], "-o", "/dev/null", "-w", "%{http_code}", "-H", "Authorization: Bearer SUBJECT_LOG_CANARY", "-H", "Cookie: COOKIE_LOG_CANARY", "--data", "BODY_LOG_CANARY"]
        if ingress.get("address"):
            command += ["--resolve", host + ":443:" + ingress["address"]]
        command += [ingress["url"].rstrip("/") + "/anything/yellow/LOCATION_LOG_CANARY?token=QUERY_LOG_CANARY"]
        if subprocess.check_output(command, text=True) != "200":
            raise RuntimeError("synthetic canary request failed")
        pods = json.loads(apigee.kubectl(c, "-n", k["namespace"], "get", "pods", "-l", "app.kubernetes.io/instance=" + release, "-o", "json"))
        candidates = [pod for pod in pods["items"] if not pod["metadata"].get("deletionTimestamp") and {item["name"]: item.get("value") for item in pod["spec"]["containers"][0].get("env", [])}.get("TOKEN_EXCHANGE_LOG_FORMAT") == "json"]
        if len(candidates) != 1:
            raise RuntimeError("expected one ready JSON logging test pod")
        pod = candidates[0]
        logs = apigee.kubectl(c, "-n", k["namespace"], "logs", pod["metadata"]["name"])
        if "LOG_CANARY" in logs or "subject_token" in logs or "exchanged_token" in logs:
            raise RuntimeError("secret canary or token field appeared in logs")
        events = []
        for line in logs.splitlines():
            if len(line) > 16384:
                raise RuntimeError("unbounded log event")
            events.append(json.loads(line))
        decisions = [event for event in events if event["event"] == "request_decision"]
        if len(decisions) < 10 or len({event["evaluation_id"] for event in decisions}) != len(decisions):
            raise RuntimeError("missing or duplicate decision events")
        expected = {"allow_exchange", "deny_missing_bearer", "deny_explicit_policy", "deny_exchange_error"}
        if not expected.issubset({event["reason"] for event in decisions}):
            raise RuntimeError("missing decision diagnostics")
        if any(event["adapter"] != "apigee" or (event["decision"] == "allow" and "http_status" in event) for event in decisions):
            raise RuntimeError("inconsistent decision schema")
        if not any(event["event"] == "message_inspection" for event in events):
            raise RuntimeError("missing opt-in inspection")
        report = {"json_events": len(events), "decisions": len(decisions), "reasons": sorted({event["reason"] for event in decisions}), "canaries_absent": True, "settings_restored": False, "image_digests": [item.get("imageID", "") for item in pod["status"].get("containerStatuses", [])]}
    finally:
        apply(original_env)
        apigee.wait_gateway(c)
    report["settings_restored"] = True
    path = apigee.ROOT / ".devspace/apigee-logging-report.json"
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=".devspace/apigee.json")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    c = apigee.load_config(args.config)
    apigee.confirmed(c, args)
    run(c)


if __name__ == "__main__":
    main()
