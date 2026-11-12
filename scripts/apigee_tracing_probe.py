"""Verify live trace-header continuity without changing export configuration."""

import json
import secrets
import subprocess
import urllib.parse

import apigee
import gateway


def run(c):
    if not c.get("synthetic_demo"):
        raise ValueError("live tracing probe requires owned synthetic fixtures")
    gateway.check_context(c)
    with gateway.lock(), apigee.operation_lock(c):
        namespace = json.loads(apigee.kubectl(c, "get", "namespace", c["kubernetes"]["namespace"], "-o", "json"))
        if namespace["metadata"].get("labels", {}).get("txe-apigee-demo") != "owned":
            raise ValueError("fixture namespace ownership is missing")
        trace_id, parent_id = secrets.token_hex(16), secrets.token_hex(8)
        parent = "00-" + trace_id + "-" + parent_id + "-01"
        command = ["curl", "--silent", "--show-error", "--fail-with-body", "--max-time", "15", "--cacert", c["ingress"]["certificate"],
                   "-H", "Authorization: Bearer synthetic-subject", "-H", "traceparent: " + parent, "-H", "tracestate: txe=readiness"]
        if c["ingress"].get("address"):
            command += ["--resolve", urllib.parse.urlparse(c["ingress"]["url"]).hostname + ":443:" + c["ingress"]["address"]]
        response = json.loads(subprocess.check_output(command + [c["ingress"]["url"].rstrip("/") + "/anything/yellow"], text=True))
        headers = {key.lower(): value for key, value in response.get("headers", {}).items()}
        forwarded = headers.get("traceparent", "")
        if isinstance(forwarded, list):
            forwarded = forwarded[0] if len(forwarded) == 1 else ""
        if not forwarded.startswith("00-" + trace_id + "-"):
            raise RuntimeError("gateway did not preserve the trace ID on the backend leg")
        logs = apigee.kubectl(c, "-n", c["kubernetes"]["namespace"], "logs", "deployment/" + c["kubernetes"].get("release", "txe-apigee"), "--since=2m")
        decisions = []
        for line in logs.splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event") == "request_decision" and event.get("trace_id") == trace_id and event.get("adapter") == "apigee":
                decisions.append(event)
        if len(decisions) != 1 or decisions[0].get("decision") != "allow" or not decisions[0].get("gateway_id"):
            raise RuntimeError("expected one correlated plugin decision for the synthetic trace")
        report = {"backend_trace_preserved": True, "correlated_plugin_decisions": 1, "proxy_revision": decisions[0].get("proxy_revision"),
                  "export_configuration_changed": False,
                  "limitation": "Header continuity does not establish Apigee policy-span parentage or exporter delivery. Local span parentage is covered by recorded-span tests."}
        gateway.persist(gateway.ROOT / ".devspace/apigee-tracing-report.json", report)
        print(json.dumps(report, indent=2))
