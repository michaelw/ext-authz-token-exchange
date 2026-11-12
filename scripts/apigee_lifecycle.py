"""Explicit, journaled teardown of an owned ephemeral Apigee environment."""

import argparse
import json
from pathlib import Path
import shutil
import time

import apigee
import apigee_infra
import gateway


def validate(c, confirmation):
    if c.get("gateway") != "apigee" or c.get("infrastructure") != "provision" or c.get("apigee_mode") != "evaluation":
        raise ValueError("full destruction requires owned Kubernetes and evaluation infrastructure")
    if confirmation != c.get("project"):
        raise ValueError("project confirmation does not match")
    if c.get("apigee_project", c["project"]) != c["project"]:
        raise ValueError("full destruction requires one owned ephemeral project")


def step(path, state, name, operation):
    if state["stages"].get(name) == "done":
        return
    print("Teardown stage: " + name, flush=True)
    state["stages"][name] = "running"
    gateway.persist(path, state)
    operation()
    state["stages"][name] = "done"
    gateway.persist(path, state)
    print("Completed: " + name, flush=True)


def wait_operation(client, operation, timeout=1800):
    deadline = time.monotonic() + timeout
    while operation and not operation.get("done"):
        if time.monotonic() >= deadline:
            raise RuntimeError("deletion still running; rerun the command to resume")
        time.sleep(10)
        operation = client.request("GET", operation["name"])
    if operation and operation.get("error"):
        raise RuntimeError("deletion operation failed; inspect cloud diagnostics")


def delete_evaluation(a, client):
    path = gateway.ROOT / ".devspace/apigee-infra/evaluation.json"
    state = json.loads(path.read_text()) if path.exists() else {}
    if state.get("project") != a["project"] or not state.get("attempted") or a["organization"] != a["project"]:
        raise ValueError("evaluation ownership is missing or mismatched")
    if state.get("delete_operation"):
        wait_operation(client, client.request("GET", state["delete_operation"]))
    elif state.get("delete_attempted"):
        deadline = time.monotonic() + 1800
        while any(item.get("organization") == a["organization"] for item in client.request("GET", "organizations").get("organizations", [])):
            if time.monotonic() >= deadline:
                raise RuntimeError("delete response was lost; inspect organization state before retrying")
            time.sleep(10)
    else:
        visible = client.request("GET", "organizations").get("organizations", [])
        if any(item.get("organization") == a["organization"] for item in visible):
            organization = client.request("GET", "organizations/" + a["organization"])
            if organization.get("billingType") != "EVALUATION":
                raise ValueError("refusing to delete a non-evaluation organization")
            state["delete_attempted"] = True
            gateway.persist(path, state)
            operation = client.request("DELETE", "organizations/" + a["organization"])
            if operation and operation.get("name"):
                state["delete_operation"] = operation["name"]
                gateway.persist(path, state)
            wait_operation(client, operation)
    visible = client.request("GET", "organizations").get("organizations", [])
    if any(item.get("organization") == a["organization"] for item in visible):
        raise RuntimeError("evaluation organization is still visible; keep infrastructure intact")
    state["deleted"] = True
    gateway.persist(path, state)


def cloud_list(c, kind):
    return json.loads(gateway.output(["gcloud", "compute", kind, "list", "--project=" + c["project"], "--format=json"]))


def inventory(c, a):
    addresses = []
    for namespace in (a["kubernetes"]["namespace"], a["demo"]["backend_namespace"]):
        services = json.loads(apigee.kubectl(a, "-n", namespace, "get", "services", "-o", "json"))
        for service in services["items"]:
            addresses += [item["ip"] for item in service.get("status", {}).get("loadBalancer", {}).get("ingress", []) if item.get("ip")]
    return {"addresses": addresses, "service_attachments": list(a.get("psc", {}).values()),
            "forwarding_rules": [r["selfLink"] for r in cloud_list(c, "forwarding-rules") if r.get("IPAddress") in addresses]}


def wait_network(c, recorded):
    deadline = time.monotonic() + 1200
    while True:
        attachments = {item["selfLink"].split("/compute/v1/")[-1] for item in cloud_list(c, "service-attachments")}
        rules = {item["selfLink"] for item in cloud_list(c, "forwarding-rules")}
        if not (attachments & set(recorded["service_attachments"])) and not (rules & set(recorded["forwarding_rules"])):
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("controller networking still exists; NAT subnets were not removed")
        time.sleep(15)


def verify_absence(c, recorded):
    wait_network(c, recorded)
    for kind in ("backend-services", "url-maps", "target-https-proxies", "network-endpoint-groups", "addresses", "forwarding-rules", "ssl-certificates"):
        resources = cloud_list(c, kind)
        if any(item.get("name", "").startswith("devspace-apigee") or item.get("name") == "apigee-callout" for item in resources):
            raise RuntimeError("Apigee resource still present: " + kind)
    subnets = json.loads(gateway.output([
        "gcloud", "compute", "networks", "subnets", "list", "--project=" + c["project"], "--format=json(name)"]))
    if any(item["name"].startswith("apigee-psc-") for item in subnets):
        raise RuntimeError("Apigee NAT subnets still present")


def destroy_module(c, module):
    directory = gateway.ROOT / ".devspace/apigee-infra" / module
    state = directory / "terraform.tfstate"
    if not state.exists():
        raise ValueError("missing owned Terraform state: " + module)
    values = json.loads((directory / "inputs.json").read_text())
    if values["project_id"] != c["project"]:
        raise ValueError("Terraform project mismatch")
    apigee_infra.terraform(c, module, values, destroy=True)
    resources = json.loads(state.read_text()).get("resources", [])
    if any(item.get("mode") == "managed" for item in resources):
        raise RuntimeError("Terraform still owns resources after destroy")


def archive(c):
    directory = gateway.ROOT / ".devspace"
    destination = directory / "environments" / c["project"]
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    names = {"gateway.json", "gateway-setup-state.json", "destroy-environment.json", "cache.yaml"}
    for path in list(directory.iterdir()):
        if path.name.startswith(("apigee-", "apigee.", "gateway-")) or path.name in names:
            if (destination / path.name).exists():
                raise ValueError("archive destination already exists: " + path.name)
            shutil.move(path, destination / path.name)
    for path in destination.rglob("*"):
        path.chmod(0o700 if path.is_dir() else 0o600)
    print("Old environment settings archived; the next setup starts with fresh inputs.")


def destroy(c, arguments):
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm-project", required=True)
    args = parser.parse_args(arguments)
    validate(c, args.confirm_project)
    a = gateway.apigee_config(c)
    if a["project"] != c["project"] or a["organization"] != c["project"]:
        raise ValueError("Apigee ownership does not match the confirmed project")
    path = gateway.ROOT / ".devspace/destroy-environment.json"
    state = json.loads(path.read_text()) if path.exists() else {"project": c["project"], "stages": {}}
    if state["project"] != c["project"]:
        raise ValueError("teardown journal belongs to another project")
    with gateway.lock():
        print("Destroying owned application, Apigee evaluation/networking, GKE, and project " + c["project"], flush=True)
        if not state["stages"]:
            gateway.check_context(c)
            for module in ("prerequisites", "ingress"):
                directory = gateway.ROOT / ".devspace/apigee-infra" / module
                if not (directory / "terraform.tfstate").exists() or not (directory / "inputs.json").exists():
                    raise ValueError("missing owned Terraform state: " + module)
            owner = Path(c["starter_pack"]) / "infra/gcp-ephemeral"
            if gateway.output(["terraform", "-chdir=" + str(owner), "output", "-raw", "project_id"]) != c["project"]:
                raise ValueError("starter-pack state project mismatch")
            state["network"] = inventory(c, a)
            gateway.persist(path, state)
        step(path, state, "stop", lambda: gateway.run(["devspace", "reset", "pods"], cwd=gateway.ROOT))
        step(path, state, "proxy", lambda: apigee.cleanup(apigee.Client(a), a))
        # Reconcile releases even after a cached purge reported success.
        if state["stages"].get("producer-network") != "done":
            gateway.run(["devspace", "run-pipeline", "remove-owned-applications"], cwd=gateway.ROOT)
            state["stages"]["applications"] = "done"
            gateway.persist(path, state)
        step(path, state, "producer-network", lambda: wait_network(c, state["network"]))
        step(path, state, "ingress", lambda: destroy_module(c, "ingress"))
        step(path, state, "evaluation", lambda: delete_evaluation(a, apigee.Client(a)))
        step(path, state, "prerequisites", lambda: destroy_module(c, "prerequisites"))
        step(path, state, "apigee-absence", lambda: verify_absence(c, state["network"]))
        step(path, state, "kubernetes", lambda: gateway.run(["devspace", "--var", "CLUSTER_PROVIDER=gke", "run", "destroy-cluster"], cwd=c["starter_pack"]))
        project = json.loads(gateway.output(["gcloud", "projects", "describe", c["project"], "--format=json(lifecycleState)"]))
        if project.get("lifecycleState") != "DELETE_REQUESTED":
            raise RuntimeError("old project shutdown is not confirmed")
        state["project_state"] = "DELETE_REQUESTED"
        gateway.persist(path, state)
        print("Component cleanup and project shutdown confirmed.")
        archive(c)
