#!/usr/bin/env python3
"""Developer-only failure tests. Temporarily changes owned synthetic fixtures."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.parse

import apigee


def request(c, token=True):
    ingress = c["ingress"]
    host = urllib.parse.urlparse(ingress["url"]).hostname
    with tempfile.NamedTemporaryFile() as headers:
        command = ["curl", "--silent", "--show-error", "--max-time", "15", "--cacert", ingress["certificate"], "-D", headers.name, "-w", "\n%{http_code}", "-H", "X-Txe-Debug: synthetic"]
        if ingress.get("address"):
            command += ["--resolve", host + ":443:" + ingress["address"]]
        if token:
            command += ["-H", "Authorization: Bearer synthetic-subject"]
        result = subprocess.run(command + [ingress["url"].rstrip("/") + "/anything/yellow"], text=True, capture_output=True, check=True)
        body, _, status = result.stdout.rpartition("\n")
        return int(status), body, Path(headers.name).read_text()


def eventually(c, expected, token=True):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        result = request(c, token)
        if result[0] == expected:
            return result
        time.sleep(3)
    raise RuntimeError("gateway did not reach expected status " + str(expected))


def run(c):
    if not c.get("synthetic_demo"):
        raise ValueError("failure tests require owned synthetic fixtures")
    for ns in (c["kubernetes"]["namespace"], c["demo"]["backend_namespace"], c["demo"]["system_namespace"]):
        value = json.loads(apigee.kubectl(c, "get", "namespace", ns, "-o", "json"))
        if value["metadata"].get("labels", {}).get("txe-apigee-demo") != "owned":
            raise ValueError("refusing to change unowned fixtures")
    dev = json.loads(apigee.kubectl(c, "-n", c["kubernetes"]["namespace"], "get", "deployments", "-o", "json"))
    if any(item["metadata"]["name"].endswith("-devspace") for item in dev["items"]):
        raise ValueError("reset development pods before running failure tests")
    apigee.smoke(c)
    results = []
    _, _, headers = request(c, token=False)
    if "www-authenticate: bearer " not in headers.lower():
        raise RuntimeError("missing bearer challenge")
    results.append("denial-challenge")
    before = apigee.kubectl(c, "-n", c["demo"]["system_namespace"], "logs", "deployment/fake-token-endpoint").count("token request route=")
    if request(c)[0] != 200:
        raise RuntimeError("single-exchange probe failed")
    time.sleep(2)
    logs = apigee.kubectl(c, "-n", c["demo"]["system_namespace"], "logs", "deployment/fake-token-endpoint")
    if logs.count("token request route=") - before != 1:
        raise RuntimeError("expected exactly one token endpoint request")
    results.append("exactly-one-exchange")
    ns = c["demo"]["backend_namespace"]
    policy = json.loads(apigee.kubectl(c, "-n", ns, "get", "configmap", "yellow-policy", "-o", "json"))
    original = policy["data"]
    broken = {key: value.replace('issuerRef: "fake-issuer"', 'issuerRef: "missing-synthetic-issuer"') for key, value in original.items()}
    if broken == original:
        raise ValueError("unexpected fixture policy; refusing mutation")
    try:
        apigee.kubectl(c, "-n", ns, "patch", "configmap", "yellow-policy", "--type=merge", "-p", json.dumps({"data": broken}))
        eventually(c, 500)
        results.append("unhealthy-policy-fail-closed")
    finally:
        apigee.kubectl(c, "-n", ns, "patch", "configmap", "yellow-policy", "--type=merge", "-p", json.dumps({"data": original}))
    eventually(c, 200)
    fake_ns = c["demo"]["system_namespace"]
    fake = json.loads(apigee.kubectl(c, "-n", fake_ns, "get", "configmap", "fake-token-endpoint-routes", "-o", "json"))
    delayed = {"routes": [{"name": "synthetic-delay", "match": {"audience": "httpbin-yellow"}, "response": {"type": "delay", "delayMilliseconds": 3000}}]}
    k = c["kubernetes"]
    deployment = "deployment/" + k.get("release", "txe-apigee")
    original_env = json.loads(apigee.kubectl(c, "-n", k["namespace"], "get", deployment, "-o", "json"))["spec"]["template"]["spec"]["containers"][0]["env"]
    try:
        apigee.kubectl(c, "-n", fake_ns, "patch", "configmap", "fake-token-endpoint-routes", "--type=merge", "-p", json.dumps({"data": {"config.yaml": json.dumps(delayed)}}))
        apigee.kubectl(c, "-n", fake_ns, "rollout", "restart", "deployment/fake-token-endpoint")
        apigee.kubectl(c, "-n", fake_ns, "rollout", "status", "deployment/fake-token-endpoint", "--timeout=300s")
        # The normal 500 ms issuer timeout wins before the gateway's 1 s limit.
        # Extend it only for this owned fixture so the gateway deadline is tested.
        apigee.kubectl(c, "-n", k["namespace"], "set", "env", deployment, "TOKEN_ENDPOINT_REQUEST_TIMEOUT=5s", "TOKEN_ENDPOINT_RESPONSE_HEADER_TIMEOUT=5s")
        apigee.kubectl(c, "-n", k["namespace"], "rollout", "status", deployment, "--timeout=300s")
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            started = time.monotonic()
            status, body, _ = request(c)
            elapsed = time.monotonic() - started
            if status == 500 and 0.8 <= elapsed < 2.5:
                break
            time.sleep(2)
        else:
            raise RuntimeError("did not observe the configured one-second callout timeout")
        if json.loads(body) != {"error": "server_error"}:
            (apigee.ROOT / ".devspace/apigee-timeout-body.json").write_text(body)
            raise RuntimeError("callout timeout exposed internal details")
        results.append("callout-timeout-fail-closed-sanitized")
    finally:
        patch = [{"op": "replace", "path": "/spec/template/spec/containers/0/env", "value": original_env}]
        apigee.kubectl(c, "-n", k["namespace"], "patch", deployment, "--type=json", "-p", json.dumps(patch))
        apigee.kubectl(c, "-n", k["namespace"], "rollout", "status", deployment, "--timeout=300s")
        apigee.kubectl(c, "-n", fake_ns, "patch", "configmap", "fake-token-endpoint-routes", "--type=merge", "-p", json.dumps({"data": fake["data"]}))
        apigee.kubectl(c, "-n", fake_ns, "rollout", "restart", "deployment/fake-token-endpoint")
        apigee.kubectl(c, "-n", fake_ns, "rollout", "status", "deployment/fake-token-endpoint", "--timeout=300s")
    eventually(c, 200)
    value = json.loads(apigee.kubectl(c, "-n", k["namespace"], "get", deployment, "-o", "json"))
    replicas = value["spec"]["replicas"]
    try:
        apigee.kubectl(c, "-n", k["namespace"], "scale", deployment, "--replicas=0")
        _, body, _ = eventually(c, 500)
        if json.loads(body) != {"error": "server_error"}:
            raise RuntimeError("transport fault exposed internal details")
        results.append("callout-unavailable-fail-closed-sanitized")
    finally:
        apigee.kubectl(c, "-n", k["namespace"], "scale", deployment, "--replicas=" + str(replicas))
        apigee.kubectl(c, "-n", k["namespace"], "rollout", "status", deployment, "--timeout=300s")
    eventually(c, 200)
    apigee.smoke(c)
    evidence = {"deployment": apigee.read_state(c), "results": results}
    (apigee.ROOT / ".devspace/apigee-e2e.json").write_text(json.dumps(evidence, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=".devspace/apigee.json")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    config = apigee.load_config(args.config)
    apigee.confirmed(config, args)
    run(config)
