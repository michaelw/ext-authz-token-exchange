"""Apigee-only setup stages. Never called by daily deployment or tests."""

import argparse
import json
import os
from pathlib import Path
import time

import apigee
import gateway


def terraform(c, module, values, destroy=False):
    root = gateway.ROOT
    directory = root / "infra/apigee" / module
    data = root / ".devspace/apigee-infra" / module
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    data.parent.chmod(0o700)
    data.chmod(0o700)
    variables = data / "inputs.json"
    target = {key: values.get(key) for key in ("project_id", "region", "network")}
    target_path = data / "target.json"
    if target_path.exists() and json.loads(target_path.read_text()) != target:
        raise ValueError("Terraform state belongs to another target; use a separate workspace")
    gateway.persist(target_path, target)
    gateway.persist(variables, values)
    env = dict(os.environ, TF_DATA_DIR=str(data / ".terraform"))
    gateway.run(["terraform", "-chdir=" + str(directory), "init", "-input=false"], env=env)
    state = str(data / "terraform.tfstate")
    gateway.run(["terraform", "-chdir=" + str(directory), "destroy" if destroy else "apply", "-input=false", "-auto-approve", "-state=" + state, "-var-file=" + str(variables)], env=env)
    if destroy:
        return {}
    result = json.loads(gateway.output(["terraform", "-chdir=" + str(directory), "output", "-state=" + state, "-json"], env=env))
    return {key: item["value"] for key, item in result.items()}


def evaluation(c, client):
    path = gateway.ROOT / ".devspace/apigee-infra/evaluation.json"
    state = json.loads(path.read_text()) if path.exists() else {}
    visible = client.request("GET", "organizations").get("organizations", [])
    exists = any(item.get("organization") == c["project"] for item in visible)
    org = "organizations/" + c["project"]
    if exists:
        if not state.get("attempted"):
            raise ValueError("existing organization is not owned by evaluation setup; select --apigee existing")
        organization = client.request("GET", org)
        if organization.get("billingType") != "EVALUATION":
            raise ValueError("refusing to modify a non-evaluation organization")
    elif not state.get("operation"):
        if state.get("attempted"):
            raise ValueError("trial expired or provisioning response was lost; inspect before retrying")
        state = {"attempted": True, "project": c["project"], "region": c["region"]}
        gateway.persist(path, state)
        operation = client.request("POST", "projects/" + c["project"] + ":provisionOrganization", {"analyticsRegion": c["region"], "runtimeLocation": c["region"], "disableVpcPeering": True})
        state["operation"] = operation["name"]
        gateway.persist(path, state)
    if state.get("operation"):
        deadline = time.monotonic() + 3600
        while True:
            operation = client.request("GET", state["operation"])
            if operation.get("done"):
                if operation.get("error"):
                    raise RuntimeError("evaluation provisioning failed; no paid fallback")
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("evaluation still provisioning; rerun setup to resume")
            print("Waiting for Apigee evaluation provisioning...", flush=True)
            time.sleep(20)
    organization = client.request("GET", org)
    if organization.get("billingType") != "EVALUATION":
        raise RuntimeError("provisioning did not return an evaluation; inspect before continuing, no paid fallback")
    return {"organization": c["project"], "environments": client.request("GET", org + "/environments"),
            "tenant_project": organization["apigeeProjectId"],
            "instances": client.request("GET", org + "/instances").get("instances", [])}


def ensure(c):
    path = gateway.ROOT / c["apigee_config"]
    if path.exists():
        a = gateway.apigee_config(c)
        if c["apigee_mode"] == "evaluation" and not (gateway.ROOT / ".devspace/apigee-infra/evaluation.json").exists():
            raise ValueError("existing evaluation is supplied infrastructure; select --apigee existing")
        if not a.get("bootstrap_pending"):
            apigee.preflight(apigee.Client(a), a)
            if a.get("synthetic_demo"):
                import apigee_demo
                if not (gateway.ROOT / a["kubernetes"]["values"]).exists():
                    subject = a.get("proxy_subject") or gateway.output(["gcloud", "iam", "service-accounts", "describe", a["proxy_service_account"], "--project=" + a["project"], "--format=value(uniqueId)"])
                    apigee_demo.fixture_values(a, c["registry"], "dev", subject)
                    apigee_demo.keycloak_config(a)
            return
    if c["apigee_mode"] != "evaluation":
        raise ValueError("existing Apigee requires apigee_config referencing explicit configuration and owned values; see docs/gateway-setup.md")
    # Read generic GKE networking instead of depending on starter-pack Apigee outputs.
    cluster = c.get("cluster") or c["context"].split("_", 3)[-1]
    details = json.loads(gateway.output(["gcloud", "container", "clusters", "describe", cluster, "--project=" + c["project"], "--region=" + c["region"], "--format=json(network,subnetwork)"]))
    network = c.get("network", details["network"])
    subnet = c.get("subnetwork", details["subnetwork"])
    if not network.startswith("projects/"):
        network = "projects/" + c["project"] + "/global/networks/" + network
    if not subnet.startswith("projects/"):
        subnet = "projects/" + c["project"] + "/regions/" + c["region"] + "/subnetworks/" + subnet
    infra = terraform(c, "prerequisites", {"project_id": c["project"], "region": c["region"], "network": network,
                      "psc_cidrs": c.get("psc_cidrs", {"callout": "10.50.0.0/24", "backend": "10.51.0.0/24"})})
    trial = evaluation(c, apigee.Client(c))
    import apigee_demo
    if not path.exists():
        apigee_demo.prepare(argparse.Namespace(infrastructure={**infra, **c, "organization": trial["organization"], "callout_address": "127.0.0.1"},
                            trial_data=trial, environment=None, config=str(path), tag="dev", ca_cert=None, ca_key=None, pending=True))
    a = apigee.load_config(path)
    a.update(network=network, subnetwork=subnet, managed_ingress=True)
    a["demo"]["psc_nat_subnets"] = infra["psc_nat_subnets"]
    a["demo"]["consumer_project"] = trial["tenant_project"]
    a["ingress"]["service_attachment"] = trial["instances"][0]["serviceAttachment"]
    groups = apigee.Client(a).request("GET", "organizations/" + a["organization"] + "/envgroups").get("environmentGroups", [])
    if len(groups) != 1:
        raise ValueError("evaluation requires exactly one discovered environment group")
    group = groups[0]
    hostname = "apigee.gcp.kube"
    if hostname not in group.get("hostnames", []):
        apigee.Client(a).request("PATCH", "organizations/" + a["organization"] + "/envgroups/" + group["name"] + "?updateMask=hostnames", {"hostnames": group.get("hostnames", []) + [hostname]})
    plugin_path = gateway.ROOT / a["kubernetes"]["values"]
    plugin = json.loads(plugin_path.read_text())
    plugin["apigee"]["service"] = {"type": "ClusterIP"}
    plugin["apigee"]["psc"] = {"enabled": True, "natSubnet": infra["psc_nat_subnets"]["callout"], "consumerProjects": [trial["tenant_project"]]}
    gateway.persist(plugin_path, plugin)
    demo_path = gateway.ROOT / ".devspace/apigee-demo-values.json"
    demo = json.loads(demo_path.read_text())
    demo["teamApp"]["exposure"] = {"type": "ClusterIP", "pscNatSubnet": infra["psc_nat_subnets"]["backend"], "pscConsumerProjects": [trial["tenant_project"]]}
    gateway.persist(demo_path, demo)
    a.pop("bootstrap_pending", None)
    gateway.persist(path, a)
    apigee_demo.keycloak_config(a)


def connect(c, a):
    """Complete private connectivity after Helm publishes the producer attachments."""
    import apigee_demo
    if not a.get("psc"):
        a["psc"] = {}
        for role, ns, name in (("callout", a["kubernetes"]["namespace"], a["kubernetes"].get("release", "txe-apigee") + "-apigee"),
                               ("backend", a["demo"]["backend_namespace"], "httpbin")):
            deadline = time.monotonic() + 600
            while True:
                attachment = json.loads(apigee.kubectl(a, "-n", ns, "get", "serviceattachment", name, "-o", "json"))
                url = attachment.get("status", {}).get("serviceAttachmentURL")
                if url:
                    a["psc"][role] = url.removeprefix("https://www.googleapis.com/compute/v1/")
                    break
                if time.monotonic() >= deadline:
                    raise RuntimeError("GKE ServiceAttachment is not ready")
                time.sleep(10)
    if not a.get("private_active"):
        apigee.psc(apigee.Client(a), a)
        apigee_demo.rotate_certificates(a, argparse.Namespace(ca_cert=None, ca_key=None))
        gateway.persist(gateway.ROOT / c["apigee_config"], a)
        apigee_demo.secrets(a)


def ingress(c):
    a = gateway.apigee_config(c)
    if a.get("managed_ingress"):
        result = terraform(c, "ingress", {"project_id": a["project"], "region": a["region"], "network": a["network"], "subnetwork": a["subnetwork"],
                            "apigee_service_attachment": a["ingress"]["service_attachment"], "certificate_file": a["ingress"]["server_certificate"], "private_key_file": a["ingress"]["server_key"]})
        a["ingress"]["address"] = result["ingress_address"]
        gateway.persist(gateway.ROOT / c["apigee_config"], a)
