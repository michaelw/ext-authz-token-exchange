"""Journaled certificate renewal for repository-owned synthetic development only."""

import argparse
import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.parse

import apigee
import apigee_demo
import apigee_infra
import gateway
from developer_runtime import port_forward


def validate(c):
    if not c.get("synthetic_demo") or not c.get("managed_ingress") or not c.get("private_active"):
        raise ValueError("renewal requires owned synthetic fixtures and owned private development ingress; use the production renewal runbook for supplied infrastructure")
    root = (gateway.ROOT / ".devspace/apigee-tls").resolve()
    for role in ("callout", "backend"):
        for suffix in ("cert", "key"):
            if not Path(c["demo"][role + "_" + suffix]).resolve().is_relative_to(root):
                raise ValueError("certificate is outside owned development storage")
    for name in ("server_certificate", "server_key"):
        if not Path(c["ingress"][name]).resolve().is_relative_to(root):
            raise ValueError("ingress certificate is outside owned development storage")


def inspect_endpoint(host, port, name, ca):
    command = ["openssl", "s_client", "-connect", host + ":" + str(port), "-servername", name,
               "-CAfile", str(ca), "-verify_return_error", "-showcerts"]
    result = subprocess.run(command, input=b"", capture_output=True, check=True, timeout=20)
    certificate = subprocess.run(["openssl", "x509", "-noout", "-dates", "-fingerprint", "-sha256"],
                                 input=result.stdout, capture_output=True, check=True).stdout.decode()
    return certificate.strip().splitlines()


def check_ownership(c):
    for namespace in (c["kubernetes"]["namespace"], c["demo"]["system_namespace"], c["demo"]["backend_namespace"]):
        resource = json.loads(apigee.kubectl(c, "get", "namespace", namespace, "-o", "json"))
        if resource["metadata"].get("labels", {}).get("txe-apigee-demo") != "owned":
            raise ValueError("fixture namespace ownership is missing")
    for namespace, name, release in (
        (c["kubernetes"]["namespace"], c["kubernetes"].get("release", "txe-apigee"), c["kubernetes"].get("release", "txe-apigee")),
        (c["demo"]["backend_namespace"], "httpbin", c["demo"].get("release", "txe-apigee-demo")),
    ):
        resource = json.loads(apigee.kubectl(c, "-n", namespace, "get", "deployment", name, "-o", "json"))
        if resource["metadata"].get("annotations", {}).get("meta.helm.sh/release-name") != release:
            raise ValueError("deployment Helm ownership is missing")


def inspect_live(c):
    hostname = urllib.parse.urlparse(c["ingress"]["url"]).hostname
    result = {"ingress": inspect_endpoint(c["ingress"]["address"], 443, hostname, c["ingress"]["certificate"])}
    for role, namespace, service in (
        ("callout", c["kubernetes"]["namespace"], c["kubernetes"].get("release", "txe-apigee") + "-apigee-private"),
        ("backend", c["demo"]["backend_namespace"], "httpbin-private"),
    ):
        with port_forward(c["context"], namespace, service, 443 if role == "callout" else c[role]["port"]) as port:
            result[role] = inspect_endpoint("127.0.0.1", port, c[role]["server_name"], c[role]["certificate"])
    return result


def wait_ingress(c, certificate):
    expected = subprocess.check_output(["openssl", "x509", "-in", str(certificate), "-noout", "-fingerprint", "-sha256"], text=True).strip()
    deadline = time.monotonic() + 1800
    hostname = urllib.parse.urlparse(c["ingress"]["url"]).hostname
    while True:
        try:
            actual = inspect_endpoint(c["ingress"]["address"], 443, hostname, c["ingress"]["certificate"])
            if expected in actual:
                return
        except (subprocess.SubprocessError, OSError):
            pass
        if time.monotonic() >= deadline:
            raise RuntimeError("ingress certificate has not propagated; protected renewal state is retained")
        time.sleep(5)


def prepare(c, directory):
    directory.mkdir(parents=True, mode=0o700)
    os.chmod(directory, 0o700)
    old, new = copy.deepcopy(c), copy.deepcopy(c)
    files = []
    for role in ("callout", "backend", "ingress"):
        target = c[role]
        cert = Path(c["demo"][role + "_cert"] if role != "ingress" else target["server_certificate"])
        key = Path(c["demo"][role + "_key"] if role != "ingress" else target["server_key"])
        for original in (cert, key):
            backup = directory / (role + "-old" + original.suffix)
            shutil.copyfile(original, backup)
            backup.chmod(0o600)
            files.append({"path": str(original), "backup": str(backup)})
    ca_dir = gateway.ROOT / ".devspace/apigee-tls"
    ca_cert, ca_key = ca_dir / "development-ca.crt", ca_dir / "development-ca.key"
    if not ca_cert.exists() or not ca_key.exists():
        if ca_cert.exists() or ca_key.exists():
            raise ValueError("incomplete development CA; inspect before renewing")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "90", "-subj", "/CN=Token Exchange Development CA",
                        "-addext", "basicConstraints=critical,CA:TRUE", "-keyout", str(ca_key), "-out", str(ca_cert)], check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-in", str(ca_cert), "-checkend", "1209600", "-noout"], check=True, capture_output=True)
    for role in ("callout", "backend", "ingress"):
        name = c[role].get("server_name") or urllib.parse.urlparse(c[role]["url"]).hostname
        addresses = [] if role == "ingress" else [c[role]["host"]]
        cert, key = apigee_demo.certificate(directory, name, str(ca_cert), str(ca_key), addresses, rotate=True)
        destination_cert = c["demo"][role + "_cert"] if role != "ingress" else c[role]["server_certificate"]
        destination_key = c["demo"][role + "_key"] if role != "ingress" else c[role]["server_key"]
        for original, replacement in ((destination_cert, cert), (destination_key, key)):
            next(item for item in files if item["path"] == original)["replacement"] = replacement
        if role != "ingress":
            bundle = directory / (role + "-overlap.pem")
            bundle.write_bytes(Path(c[role]["certificate"]).read_bytes() + b"\n" + ca_cert.read_bytes())
            bundle.chmod(0o600)
            new[role]["certificate"] = str(bundle)
    new["ingress"]["certificate"] = str(ca_cert)
    return {"project": c["project"], "original": old, "next": new, "files": files, "ca": str(ca_cert), "stage": "prepared"}


def publish_files(state, restore=False):
    for item in state["files"]:
        destination = Path(item["path"])
        temporary = destination.with_suffix(destination.suffix + ".renewing")
        temporary.write_bytes(Path(item["backup" if restore else "replacement"]).read_bytes())
        temporary.chmod(0o600)
        temporary.replace(destination)


def reconcile(c, journal, state):
    config_path = gateway.ROOT / gateway.load()["apigee_config"]
    client = apigee.Client(c)
    # Client trust must also overlap while global ingress configuration propagates.
    bundle = journal.parent / "ingress-overlap.pem"
    backup = next(item["backup"] for item in state["files"] if item["path"] == state["original"]["ingress"]["server_certificate"])
    bundle.write_bytes(Path(backup).read_bytes() + b"\n" + Path(state["ca"]).read_bytes())
    bundle.chmod(0o600)
    state["next"]["ingress"]["certificate"] = str(bundle)
    try:
        # Reconcile each stage on resume: earlier API responses can be lost.
        apigee.deploy(client, state["next"])
        state["stage"] = "trust-ready"
        gateway.persist(journal, state)
        publish_files(state)
        gateway.persist(config_path, state["next"])
        apigee_demo.secrets(state["next"])
        state["stage"] = "serving-updated"
        gateway.persist(journal, state)
        apigee_infra.ingress(gateway.load())
        wait_ingress(state["next"], state["next"]["ingress"]["server_certificate"])
        apigee.smoke(state["next"])
        final = copy.deepcopy(state["next"])
        final["ingress"]["certificate"] = state["ca"]
        for role in ("callout", "backend"):
            final[role]["certificate"] = state["ca"]
        apigee.deploy(client, final)
        apigee.smoke(final)
        gateway.persist(config_path, final)
        state["stage"] = "ready"
        gateway.persist(journal, state)
        return final
    except Exception:
        state["stage"] = "restoring"
        gateway.persist(journal, state)
        # Restore overlap trust before old serving material, then old-only trust.
        apigee.deploy(client, state["next"])
        publish_files(state, restore=True)
        restore = copy.deepcopy(state["original"])
        restore["ingress"]["certificate"] = str(bundle)
        gateway.persist(config_path, restore)
        apigee_demo.secrets(state["original"])
        apigee_infra.ingress(gateway.load())
        wait_ingress(restore, restore["ingress"]["server_certificate"])
        apigee.deploy(client, state["original"])
        gateway.persist(config_path, state["original"])
        state["stage"] = "rolled-back"
        gateway.persist(journal, state)
        raise


def run(c, arguments):
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(arguments)
    validate(c)
    gateway.check_context(c)
    with gateway.lock(), apigee.operation_lock(c):
        check_ownership(c)
        if args.check:
            print(json.dumps(inspect_live(c), indent=2))
            return
        directory = gateway.ROOT / ".devspace/apigee-renewals"
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        journal = directory / "current.json"
        state = json.loads(journal.read_text()) if journal.exists() else {}
        if state and state["project"] != c["project"]:
            raise ValueError("renewal journal belongs to another project")
        previous_umask = os.umask(0o077)
        try:
            if not state or state["stage"] == "ready":
                before = inspect_live(c)
                state = prepare(c, directory / str(time.time_ns()))
                state["live_before"] = before
                gateway.persist(journal, state)
            final = reconcile(c, journal, state)
            state["live_after"] = inspect_live(final)
            gateway.persist(journal, state)
        finally:
            os.umask(previous_umask)
        print("Owned development certificates renewed; probes passed and protected rollback material retained.")
