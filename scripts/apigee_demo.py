#!/usr/bin/env python3
"""Prepare or deploy isolated synthetic fixtures in an existing GKE cluster."""

import argparse
import base64
import json
import ipaddress
import os
from pathlib import Path
import subprocess
import sys

import apigee


def certificate(directory, name, ca_cert=None, ca_key=None, addresses=(), rotate=False):
    cert = directory / (name + ".crt")
    key = directory / (name + ".key")
    if cert.exists() and key.exists() and not rotate:
        subprocess.run(["openssl", "x509", "-in", str(cert), "-checkend", "3600", "-noout"], check=True)
        return str(cert), str(key)
    san = "DNS:" + name + "".join(",IP:" + str(ipaddress.ip_address(address)) for address in addresses)
    command = ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=" + name, "-keyout", str(key)]
    if ca_cert:
        csr = directory / (name + ".csr")
        subprocess.run(command + ["-out", str(csr)], check=True, capture_output=True)
        extension = directory / (name + ".ext")
        extension.write_text("subjectAltName=" + san + "\n")
        subprocess.run(["openssl", "x509", "-req", "-in", str(csr), "-CA", ca_cert, "-CAkey", ca_key, "-set_serial", str(int.from_bytes(os.urandom(16), "big")), "-days", "7", "-extfile", str(extension), "-out", str(cert)], check=True, capture_output=True)
    else:
        subprocess.run(command + ["-x509", "-days", "7", "-addext", "subjectAltName=" + san, "-out", str(cert)], check=True, capture_output=True)
    os.chmod(key, 0o600)
    return str(cert), str(key)


def prepare(args):
    infra = args.infrastructure
    trial = args.trial_data
    environments = trial["environments"]
    if isinstance(environments, dict):
        environments = environments.get("environments", [])
    environment = args.environment or (environments[0] if len(environments) == 1 else None)
    if not environment:
        raise ValueError("select --environment explicitly")
    directory = apigee.ROOT / ".devspace/apigee-tls"
    directory.mkdir(parents=True, exist_ok=True)
    os.chmod(directory, 0o700)
    ca = (args.ca_cert, args.ca_key)
    if bool(ca[0]) != bool(ca[1]):
        raise ValueError("provide both --ca-cert and --ca-key to reuse the starter-pack CA")
    callout_cert, callout_key = certificate(directory, "callout.apigee.test", *ca)
    backend_cert, backend_key = certificate(directory, "backend.apigee.test", *ca)
    ingress_cert, ingress_key = certificate(directory, "apigee.gcp.kube", *ca)
    c = {"project": infra["project"], "context": infra["context"], "region": infra["region"], "organization": infra["organization"], "environment": environment, "proxy": "txe-development", "proxy_service_account": infra["proxy_service_account"], "synthetic_demo": True,
         "callout": {"host": infra["callout_address"], "port": 443, "certificate": args.ca_cert or callout_cert, "server_name": "callout.apigee.test", "audience": "https://callout.apigee.test"},
         "backend": {"host": "PENDING_BACKEND_SERVICE", "port": 8080, "certificate": args.ca_cert or backend_cert, "server_name": "backend.apigee.test"},
         "ingress": {"url": "https://apigee.gcp.kube", "certificate": args.ca_cert or ingress_cert, "server_certificate": ingress_cert, "server_key": ingress_key},
         "kubernetes": {"namespace": "txe-apigee", "release": "txe-apigee", "values": ".devspace/apigee-plugin-values.json"},
         "demo": {"system_namespace": "txe-apigee-system", "backend_namespace": "txe-apigee-demo-yellow", "callout_cert": callout_cert, "callout_key": callout_key, "backend_cert": backend_cert, "backend_key": backend_key}}
    path = Path(args.config)
    if path.exists():
        raise ValueError("configuration exists; reuse it rather than overwriting endpoint/ownership settings")
    path.parent.mkdir(parents=True, exist_ok=True)
    if getattr(args, "pending", False):
        c["bootstrap_pending"] = True
    path.write_text(json.dumps(c, indent=2) + "\n")
    fixture_values(c, infra["registry"], args.tag, infra["proxy_subject"])
    print("Prepared ignored demo configuration:", path)


def fixture_values(c, registry, tag, subject):
    k, d = c["kubernetes"], c["demo"]
    ns = d["system_namespace"]
    prefix = d["backend_namespace"].removesuffix("-yellow")
    plugin = {"gatewayProvider": "apigee", "fullnameOverride": k.get("release", "txe-apigee"), "image": {"repository": registry + "/ext-authz-token-exchange", "tag": tag, "pullPolicy": "Always"}, "apigee": {"enabled": True, "tlsSecret": "txe-callout-tls", "audience": c["callout"]["audience"], "allowedSubjects": subject, "inspectMessages": False, "service": {"type": "ClusterIP"}},
              "env": {"TOKEN_EXCHANGE_ALLOW_HTTP_TOKEN_ENDPOINT": "true", "GRPC_LOG_HEALTH_CHECKS": "false"},
              "issuerProfiles": {"profiles": [{"name": "fake-issuer", "tokenEndpoint": "http://fake-token-endpoint." + ns + ".svc.cluster.local:8080/token/success", "clientIDSecretRef": {"name": "txe-fake-issuer", "key": "client_id"}, "clientSecretSecretRef": {"name": "txe-fake-issuer", "key": "client_secret"}}]}}
    scenarios = [{"name": "denied", "action": "deny", "pathPrefix": "/anything/denied", "methods": ["*"]}, {"name": "error-invalid-grant", "scope": "invalid-grant", "pathPrefix": "/anything/error-invalid-grant"}]
    demo = {"gatewayProvider": "apigee", "host": c["ingress"]["url"].removeprefix("https://"), "namespacePrefix": prefix, "systemNamespace": ns, "policy": {"httpbinResourceBase": c["ingress"]["url"]}, "teamApp": {"enabled": True, "tlsSecret": "txe-backend-tls", "exposure": {"type": "ClusterIP"}}, "teams": [{"color": "yellow", "scenarios": scenarios}], "fakeTokenEndpoint": {"image": registry + "/ext-authz-token-exchange-fake-token-endpoint:" + tag}}
    if d.get("psc_nat_subnets"):
        plugin["apigee"]["psc"] = {"enabled": True, "natSubnet": d["psc_nat_subnets"]["callout"], "consumerProjects": [d["consumer_project"]]}
        demo["teamApp"]["exposure"].update(pscNatSubnet=d["psc_nat_subnets"]["backend"], pscConsumerProjects=[d["consumer_project"]])
    for filename, values in ((k["values"], plugin), (d.get("values", ".devspace/apigee-demo-values.json"), demo)):
        destination = apigee.ROOT / filename
        if not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(json.dumps(values, indent=2) + "\n")


def namespace(c, name):
    existing = subprocess.run(["kubectl", "--context=" + c["context"], "get", "namespace", name, "-o", "json", "--ignore-not-found"], text=True, capture_output=True, check=True)
    if existing.stdout:
        value = json.loads(existing.stdout)
        if value["metadata"].get("labels", {}).get("txe-apigee-demo") != "owned":
            raise ValueError("refusing to adopt existing namespace " + name)
        return
    labels = {"txe-apigee-demo": "owned", "ext-authz-token-exchange.magneticflux.net/policy": "enabled"}
    apigee.kubectl(c, "create", "-f", "-", data=json.dumps({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": labels}}))


def secrets(c):
    if not c.get("synthetic_demo"):
        raise ValueError("this command is only for owned synthetic fixtures")
    d = c["demo"]
    for name in (c["kubernetes"]["namespace"], d["system_namespace"], d["backend_namespace"]):
        namespace(c, name)
    changed = []
    for ns, name, cert, key in [(c["kubernetes"]["namespace"], "txe-callout-tls", d["callout_cert"], d["callout_key"]), (d["backend_namespace"], "txe-backend-tls", d["backend_cert"], d["backend_key"])]:
        secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": name, "namespace": ns}, "type": "kubernetes.io/tls", "data": {"tls.crt": base64.b64encode(Path(cert).read_bytes()).decode(), "tls.key": base64.b64encode(Path(key).read_bytes()).decode()}}
        existing = apigee.kubectl(c, "-n", ns, "get", "secret", name, "-o", "json", "--ignore-not-found")
        if existing and json.loads(existing).get("data") != secret["data"]:
            changed.append((ns, c["kubernetes"].get("release", "txe-apigee") if name == "txe-callout-tls" else "httpbin"))
        apigee.kubectl(c, "apply", "-f", "-", data=json.dumps(secret))
    secret = {"apiVersion": "v1", "kind": "Secret", "metadata": {"name": "txe-fake-issuer", "namespace": c["kubernetes"]["namespace"]}, "stringData": {"client_id": "e2e-client", "client_secret": "e2e-secret"}}
    apigee.kubectl(c, "apply", "-f", "-", data=json.dumps(secret))
    for ns, name in changed:
        apigee.kubectl(c, "-n", ns, "rollout", "restart", "deployment/" + name)
        apigee.kubectl(c, "-n", ns, "rollout", "status", "deployment/" + name, "--timeout=300s")


def deploy(c):
    import gateway
    gateway.check_context(c)
    subprocess.run(["devspace", "deploy"], cwd=apigee.ROOT, check=True)


def rotate_certificates(c, args):
    if not c.get("synthetic_demo"):
        raise ValueError("certificate rotation requires owned synthetic fixtures")
    if bool(args.ca_cert) != bool(args.ca_key):
        raise ValueError("provide both CA certificate and key")
    for role in ("callout", "backend"):
        target = c[role]
        cert = Path(c["demo"][role + "_cert"])
        addresses = [target["host"]]
        if c.get("public_targets"):
            addresses.append(c["public_targets"][role])
        certificate(cert.parent, target["server_name"], args.ca_cert, args.ca_key, sorted(set(addresses)), rotate=True)
        target["certificate"] = args.ca_cert or str(cert)


def keycloak_config(c):
    if not c.get("synthetic_demo"):
        raise ValueError("Keycloak setup requires owned synthetic fixtures")
    ns = c["demo"]["system_namespace"]
    base = "http://keycloak." + ns + ".svc.cluster.local:8080"
    values = {"namespace": ns, "fullnameOverride": "keycloak", "pluginNamespace": c["kubernetes"]["namespace"], "gateway": {"enabled": False}, "keycloak": {"externalURL": base, "resources": {"requests": {"cpu": "1", "memory": "1536Mi"}, "limits": {"cpu": "2", "memory": "2Gi"}}}}
    path = apigee.ROOT / c["demo"].get("keycloak_values", ".devspace/apigee-keycloak-values.json")
    path.write_text(json.dumps(values, indent=2) + "\n")
    plugin_path = apigee.ROOT / c["kubernetes"]["values"]
    plugin = json.loads(plugin_path.read_text())
    profiles = plugin["issuerProfiles"]["profiles"]
    added = not any(profile["name"] == "local-keycloak" for profile in profiles)
    if added:
        profiles.append({"name": "local-keycloak", "tokenEndpoint": base + "/realms/token-exchange-e2e/protocol/openid-connect/token", "clientIDSecretRef": {"name": "ext-authz-token-exchange-keycloak-oauth", "key": "client_id"}, "clientSecretSecretRef": {"name": "ext-authz-token-exchange-keycloak-oauth", "key": "client_secret"}})
        plugin_path.write_text(json.dumps(plugin, indent=2) + "\n")
    demo_path = apigee.ROOT / c["demo"].get("values", ".devspace/apigee-demo-values.json")
    demo = json.loads(demo_path.read_text())
    scenarios = json.loads(subprocess.check_output(["yq", "-o=json", ".", str(apigee.ROOT / "charts/ext-authz-token-exchange-e2e/values-keycloak.yaml")], text=True))
    demo["additionalScenarios"] = scenarios["additionalScenarios"]
    demo_path.write_text(json.dumps(demo, indent=2) + "\n")


def keycloak(c):
    keycloak_config(c)
    deploy(c)
    k = c["kubernetes"]
    apigee.kubectl(c, "-n", k["namespace"], "rollout", "status", "deployment/" + k.get("release", "txe-apigee"), "--timeout=300s")
    print("Keycloak is internal only. Run the existing focused e2e suite with a local port forward.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["deploy", "keycloak", "rotate-certificates", "cleanup"])
    parser.add_argument("--config", default=".devspace/apigee.json")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--environment")
    parser.add_argument("--tag", default="apigee-dev")
    parser.add_argument("--ca-cert")
    parser.add_argument("--ca-key")
    args = parser.parse_args()
    c = apigee.load_config(args.config)
    apigee.confirmed(c, args)
    if args.command == "rotate-certificates":
        rotate_certificates(c, args)
        Path(args.config).write_text(json.dumps(c, indent=2) + "\n")
    elif args.command == "deploy":
        deploy(c)
        Path(args.config).write_text(json.dumps(c, indent=2) + "\n")
    elif args.command == "keycloak":
        keycloak(c)
    else:
        subprocess.run(["devspace", "run-pipeline", "cleanup-fixtures"], cwd=apigee.ROOT, check=True)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print("E:", error, file=sys.stderr)
        sys.exit(1)
