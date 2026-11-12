#!/usr/bin/env python3
"""Shared developer entry points. Cloud provisioning is reachable only from setup."""

import argparse
import base64
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import apigee

ROOT = Path(__file__).resolve().parents[1]
STARTER_REVISION = "b98d99ba1a489da36216bbabd0c75b5f93f3db21"


def run(args, **kwargs):
    return subprocess.run([str(arg) for arg in args], check=True, **kwargs)


def output(args, **kwargs):
    return subprocess.check_output([str(arg) for arg in args], text=True, **kwargs).strip()


def persist(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.chmod(0o600)
    temporary.replace(path)


def load():
    path = ROOT / ".devspace/gateway.json"
    return json.loads(path.read_text()) if path.exists() else {}


def value(key, default):
    c = load()
    if key in c:
        return c[key]
    if c.get("gateway") == "apigee" and (ROOT / c.get("apigee_config", ".devspace/apigee.json")).exists():
        a = apigee_config(c)
        d = a.get("demo", {})
        fields = {"plugin_namespace": a["kubernetes"]["namespace"], "plugin_release": a["kubernetes"].get("release", "txe-apigee"),
                  "plugin_values": a["kubernetes"]["values"], "system_namespace": d.get("system_namespace", "txe-apigee-system"),
                  "demo_values": d.get("values", ".devspace/apigee-demo-values.json"), "demo_release": d.get("release", "txe-apigee-demo"),
                  "keycloak_values": d.get("keycloak_values", ".devspace/apigee-keycloak-values.json"), "keycloak_release": d.get("keycloak_release", "txe-apigee-keycloak"),
                  "fixtures_disabled": not a.get("synthetic_demo", False),
                  "keycloak_disabled": not a.get("synthetic_demo", False) or not (ROOT / d.get("keycloak_values", ".devspace/apigee-keycloak-values.json")).exists()}
        return fields.get(key, default)
    return default


def image_tag():
    digest = hashlib.sha256()
    names = subprocess.check_output(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"], cwd=ROOT).decode().split("\0")
    for name in sorted(set(names) - {""}):
        if not name.startswith(("cmd/", "internal/", "api/")) and name not in {"go.mod", "go.sum", "Dockerfile", ".dockerignore", "LICENSE", "scripts/docker-entrypoint.sh"}:
            continue
        path = ROOT / name
        if path.is_file():
            digest.update(name.encode() + b"\0" + path.read_bytes() + b"\0")
    return "dev-" + digest.hexdigest()[:20]


def read_inputs(path):
    if not path:
        return {}
    text = Path(path).read_text()
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        value = json.loads(output(["yq", "-o=json", ".", path]))
    validate_nonsecret(value)
    return value


def validate_nonsecret(value):
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in {"access_token", "refresh_token", "client_secret", "private_key", "password", "credentials"}:
                raise ValueError("inputs must reference credentials, not contain them")
            validate_nonsecret(item)
    elif isinstance(value, list):
        for item in value:
            validate_nonsecret(item)
    elif isinstance(value, str) and ("PRIVATE KEY-----" in value or value.startswith("Bearer ")):
        raise ValueError("inputs must reference credentials, not contain them")


def resolve(args, supplied):
    c = dict(supplied)
    c.update(gateway=args.gateway, infrastructure=args.infrastructure)
    c.setdefault("keycloak_enabled", True)
    if args.gateway == "apigee":
        mode = args.apigee or c.get("apigee_mode", "evaluation")
        if mode not in ("evaluation", "existing"):
            raise ValueError("Apigee requires --apigee existing|evaluation")
        c["apigee_mode"] = mode
        c.setdefault("apigee_config", ".devspace/apigee.json")
        if mode == "evaluation" and not ((args.daily_budget or c.get("daily_budget", 0)) > 0):
            raise ValueError("evaluation requires an explicit positive --daily-budget")
    elif args.apigee:
        raise ValueError("--apigee is only valid with --gateway apigee")
    else:
        c.setdefault("manage_gateway", args.infrastructure == "provision")
        c.setdefault("namespace", "gke-gateway")
        c.setdefault("gateway_name", "gateway")
    if args.daily_budget:
        c["daily_budget"] = args.daily_budget
    if args.starter_pack:
        c["starter_pack"] = str(Path(args.starter_pack).resolve())
    if isinstance(c.get("apigee_config"), dict):
        c["apigee_settings"] = c["apigee_config"]
        c["apigee_config"] = ".devspace/apigee.json"
    return c


def check_context(c, invocation=True):
    selected = os.environ.get("DEVSPACE_CONTEXT") if invocation else None
    if selected and selected != c.get("context"):
        raise ValueError("DevSpace context differs from the configured Kubernetes context")
    if not c.get("context") or output(["kubectl", "config", "current-context"]) != c["context"]:
        raise ValueError("select the configured Kubernetes context before continuing")


def stage(c, name, operation):
    path = ROOT / ".devspace/gateway-setup-state.json"
    state = json.loads(path.read_text()) if path.exists() else {"stages": {}}
    identity = {key: c.get(key) for key in ("gateway", "project", "context", "apigee_config")}
    if state.get("target") and state["target"] != identity:
        raise ValueError("setup journal belongs to another target; use a separate workspace")
    state["target"] = identity
    print("Setup stage: " + name, flush=True)
    state["stages"][name] = {"status": "running", "started": time.time()}
    persist(path, state)
    try:
        operation()
    except BaseException:
        state["stages"][name]["status"] = "failed"
        persist(path, state)
        raise
    state["target"] = {key: c.get(key) for key in identity}
    state["stages"][name]["status"] = "ready"
    persist(path, state)
    print("Completed: " + name, flush=True)


@contextlib.contextmanager
def lock():
    path = ROOT / ".devspace/gateway.lock"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another gateway operation is running") from None
        yield


def starter_pack(c):
    path = Path(c.get("starter_pack", ROOT / ".devspace/starter-pack"))
    if not path.exists():
        run(["git", "clone", "--no-checkout", "https://github.com/michaelw/devspace-starter-pack", path])
        run(["git", "-C", path, "checkout", "--detach", STARTER_REVISION])
    revision = output(["git", "-C", path, "rev-parse", "HEAD"])
    if "starter_pack" not in c and revision != STARTER_REVISION:
        raise ValueError("cached starter-pack checkout does not match its pin")
    c.update(starter_pack=str(path), starter_pack_revision=revision)
    return path


def kubernetes(c):
    if c["infrastructure"] == "provision":
        path = starter_pack(c)
        active = output(["kubectl", "config", "view", "-o", "jsonpath={.current-context}"])
        state_path = path / "infra/gcp-ephemeral/terraform.tfstate"
        state = json.loads(state_path.read_text()) if state_path.exists() else {}
        clusters = [item["attributes"] for resource in state.get("resources", []) if resource["type"] == "google_container_cluster" for item in resource.get("instances", [])]
        owned_contexts = {"gke_" + item["project"] + "_" + item["location"] + "_" + item["name"] for item in clusters}
        if active.startswith("gke_") and active not in owned_contexts:
            raise ValueError("provisioning must not select an unrelated GKE cluster; select a non-GKE context or use existing infrastructure inputs")
        command = ["devspace", "--var", "CLUSTER_PROVIDER=gke", "--var", "GKE_PROJECT_ID=" + c.get("project", "")]
        for key, variable in (("region", "GKE_REGION"), ("cluster", "GKE_CLUSTER_NAME")):
            if c.get(key):
                command += ["--var", variable + "=" + c[key]]
        for key, item in c.get("starter_vars", {}).items():
            if key not in {"GCP_BILLING_ACCOUNT_ID", "GCP_ORG_ID", "GCP_FOLDER_ID", "DOCKER_CIDR_PREFIX", "GKE_DNS_DOMAIN"}:
                raise ValueError("unsupported generic starter-pack input: " + key)
            command += ["--var", key + "=" + str(item)]
        run(command + ["run", "ensure-cluster"], cwd=path)
        data = json.loads(output(["terraform", "-chdir=" + str(path / "infra/gcp-ephemeral"), "output", "-json"]))
        values = {key: item["value"] for key, item in data.items()}
        c.update(project=values["project_id"], region=values["region"], registry=values["dev_registry"],
                 cluster=values["cluster_name"], context="gke_" + values["project_id"] + "_" + values["region"] + "_" + values["cluster_name"])
        c.setdefault("domain", values["dns_domain"].rstrip("."))
    for name in ("project", "region", "registry", "context"):
        if not c.get(name):
            raise ValueError("missing infrastructure input: " + name)
    check_context(c, invocation=False)
    if c["gateway"] == "gke-gateway":
        if not c.get("domain"):
            raise ValueError("GKE Gateway requires domain in existing infrastructure inputs")
        if not c.get("manage_gateway"):
            output(["kubectl", "--context=" + c["context"], "-n", c["namespace"], "get", "gateway", c["gateway_name"], "-o", "json"])


def apigee_config(c):
    result = apigee.load_config(ROOT / c["apigee_config"])
    for key in ("region", "context"):
        if c.get(key) and result.get(key) != c[key]:
            raise ValueError("Apigee configuration disagrees with selected " + key)
    if c.get("apigee_project") and result["project"] != c["apigee_project"]:
        raise ValueError("Apigee configuration disagrees with selected Apigee project")
    return result


def provision_apigee(c):
    import apigee_infra
    apigee_infra.ensure(c)


def application_deploy(c):
    # A setup command can start on another gateway before it resolves this target.
    names = set(json.loads(output(["yq", "-o=json", ".vars | keys", ROOT / "devspace.yaml"])))
    env = {key: item for key, item in os.environ.items() if key not in names and not key.startswith("DEVSPACE_")}
    env["DEVSPACE_CONTEXT"] = c["context"]
    run(["devspace", "--kube-context", c["context"], "--no-warn", "deploy", "--build-sequential"], cwd=ROOT, env=env)


def setup(args):
    supplied = load()
    supplied.update(read_inputs(args.inputs))
    c = resolve(args, supplied)
    inline = c.pop("apigee_settings", None)
    if inline:
        for key in ("project", "region", "context"):
            if inline.get(key):
                c.setdefault(key, inline[key])
    if c["gateway"] == "apigee" and c["apigee_mode"] == "existing" and not inline:
        existing = apigee_config(c)
        c.setdefault("apigee_project", existing["project"])
        for key in (("project", "region", "context") if c["infrastructure"] == "existing" else ("region",)):
            c.setdefault(key, existing[key])
        if not c.get("registry"):
            values = json.loads((ROOT / existing["kubernetes"]["values"]).read_text())
            c["registry"] = values["image"]["repository"].rsplit("/", 1)[0]
    with lock():
        if c["infrastructure"] == "existing":
            check_context(c)
        stage(c, "kubernetes", lambda: kubernetes(c))
        os.environ["DEVSPACE_CONTEXT"] = c["context"]
        if inline:
            for key in ("project", "region", "context"):
                inline.setdefault(key, c.get("apigee_project", c[key]) if key == "project" else c[key])
            path = ROOT / c["apigee_config"]
            if path.exists():
                if not supplied_matches(json.loads(path.read_text()), inline):
                    raise ValueError("supplied Apigee settings differ from saved configuration; reconcile explicitly")
            else:
                persist(path, inline)
        persist(ROOT / ".devspace/gateway.json", c)
        if c["gateway"] == "apigee":
            stage(c, "apigee-infrastructure", lambda: provision_apigee(c))
        persist(ROOT / ".devspace/gateway.json", c)
        select_devspace_cache(c)
        stage(c, "application", lambda: application_deploy(c))
        if c["gateway"] == "apigee":
            import apigee_infra
            stage(c, "ingress", lambda: apigee_infra.ingress(c))
        else:
            stage(c, "ingress", lambda: gke_access(c))
            persist(ROOT / ".devspace/gateway.json", c)
        stage(c, "acceptance", lambda: dispatch("smoke", []))
        persist(ROOT / ".devspace/gateway.json", c)
    print("Setup acceptance probes passed. Dashboard: devspace run demo-dashboard -- -open")


def supplied_matches(actual, supplied):
    if isinstance(supplied, dict):
        return isinstance(actual, dict) and all(key in actual and supplied_matches(actual[key], value) for key, value in supplied.items())
    return actual == supplied


def gke_access(c):
    deadline = time.monotonic() + 600
    while True:
        resource = json.loads(output(["kubectl", "--context=" + c["context"], "-n", c["namespace"], "get", "gateway", c["gateway_name"], "-o", "json"]))
        addresses = resource.get("status", {}).get("addresses", [])
        conditions = resource.get("status", {}).get("conditions", [])
        if addresses and any(item["type"] == "Programmed" and item["status"] == "True" for item in conditions):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("GKE Gateway has not become programmed")
        time.sleep(5)
    ingress = c.setdefault("ingress", {})
    ingress.setdefault("url", "https://httpbin." + c["domain"])
    ingress["address"] = addresses[0]["value"]
    if not ingress.get("certificate"):
        tls = next((listener.get("tls") for listener in resource["spec"]["listeners"] if listener["protocol"] == "HTTPS"), None)
        if not tls or not tls.get("certificateRefs"):
            raise ValueError("supply ingress.certificate for the existing gateway TLS configuration")
        reference = tls["certificateRefs"][0]
        secret = json.loads(output(["kubectl", "--context=" + c["context"], "-n", reference.get("namespace", c["namespace"]), "get", "secret", reference["name"], "-o", "json"]))
        path = ROOT / ".devspace/gateway-tls.crt"
        path.write_bytes(base64.b64decode(secret["data"]["tls.crt"]))
        ingress["certificate"] = str(path.relative_to(ROOT))


def select_devspace_cache(c):
    """Preserve stale local context metadata before selecting an explicit setup target."""
    path = ROOT / ".devspace/cache.yaml"
    if not path.exists():
        return
    cached = read_inputs(path)
    if cached.get("lastContext", {}).get("context") == c["context"]:
        return
    backup = ROOT / ".devspace/gateway-previous-devspace-cache.json"
    if not backup.exists():
        persist(backup, cached)
    namespace = apigee_config(c)["kubernetes"]["namespace"] if c["gateway"] == "apigee" else c.get("namespace", "default")
    # Do not reuse image/deployment metadata belonging to a different target.
    persist(path, {"lastContext": {"context": c["context"], "namespace": namespace}})


def snapshot(c, pods=False):
    a = apigee_config(c)
    check_context(a)
    resources = []
    for ns in (a["kubernetes"]["namespace"], a["demo"]["system_namespace"], a["demo"]["backend_namespace"]):
        kinds = "service,serviceattachment,deployment" + (",pod" if pods else "")
        data = json.loads(apigee.kubectl(a, "-n", ns, "get", kinds, "-o", "json"))
        for item in data["items"]:
            entry = {"namespace": ns, "kind": item["kind"], "name": item["metadata"]["name"], "uid": item["metadata"]["uid"]}
            if item["kind"] == "Deployment":
                entry["images"] = [container["image"] for container in item["spec"]["template"]["spec"]["containers"]]
            if item["kind"] == "Pod":
                entry["image_ids"] = [container.get("imageID") for container in item.get("status", {}).get("containerStatuses", [])]
            resources.append(entry)
    state = apigee.read_state(a)
    return {"resources": sorted(resources, key=lambda item: (item["namespace"], item["kind"], item["name"])), "proxy": a["proxy"], "revision": state.get("current"), "bundle_sha256": state.get("digest"), "attachments": state.get("attachments", [])}


def baseline(c):
    result = snapshot(c)
    path = ROOT / ".devspace/gateway-baseline.json"
    if path.exists():
        path = ROOT / ".devspace/gateway-latest.json"
    persist(path, result)
    print("Recorded resource identities and deployed image references")


def repeatability(c):
    with lock():
        before = snapshot(c, pods=True)
        cycles = []
        for cycle in range(2):
            run(["devspace", "--no-warn", "deploy", "--build-sequential"], cwd=ROOT)
            dispatch("smoke", [])
            after = snapshot(c, pods=True)
            if after != before:
                persist(ROOT / ".devspace/gateway-repeatability-drift.json", {"before": before, "after": after})
                raise RuntimeError("unchanged deployment changed resource/pod identities or the ready revision")
            cycles.append({"cycle": cycle + 1, "stable_identities_and_images": True, "revision": after["revision"]})
        persist(ROOT / ".devspace/gateway-repeatability.json", {"cycles": cycles, "snapshot": before})
    print("Both deployment cycles preserved Services, attachments, Deployments, Pods, image IDs and the proxy revision")


def cleanup_check(a):
    if not a.get("synthetic_demo"):
        raise ValueError("cleanup is restricted to owned synthetic fixtures")
    if apigee.read_state(a).get("attachments"):
        raise ValueError("remove owned endpoint attachments explicitly before fixture cleanup")
    expected = {"APIGEE_RELEASE": a["kubernetes"].get("release", "txe-apigee"),
                "APIGEE_NAMESPACE": a["kubernetes"]["namespace"],
                "APIGEE_SYSTEM_NAMESPACE": a["demo"]["system_namespace"],
                "APIGEE_DEMO_RELEASE": a["demo"].get("release", "txe-apigee-demo"),
                "APIGEE_KEYCLOAK_RELEASE": a["demo"].get("keycloak_release", "txe-apigee-keycloak")}
    if any(os.environ.get(key, item) != item for key, item in expected.items()):
        raise ValueError("cleanup release or namespace overrides disagree with recorded ownership")
    for attachment in a.get("psc", {}).values():
        parts = attachment.split("/")
        connections = json.loads(output(["gcloud", "compute", "service-attachments", "list", "--project=" + parts[1], "--filter=name=" + parts[-1], "--format=json(selfLink,connectedEndpoints)"]))
        if any(item.get("selfLink", "").endswith("/" + attachment) and item.get("connectedEndpoints") for item in connections):
            raise ValueError("PSC still has connected consumers; refusing fixture cleanup")
    for namespace in (a["kubernetes"]["namespace"], a["demo"]["system_namespace"], a["demo"]["backend_namespace"]):
        metadata = json.loads(apigee.kubectl(a, "get", "namespace", namespace, "-o", "json"))["metadata"]
        if metadata.get("labels", {}).get("txe-apigee-demo") != "owned":
            raise ValueError("fixture namespace ownership is missing")


def destructive(a, action, args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--confirm-resource", required=True)
    parser.add_argument("--revision")
    options = parser.parse_args(args)
    state = apigee.read_state(a)
    if options.confirm_resource != a["proxy"] or not state.get("revisions"):
        raise ValueError("destructive operations require the exact owned proxy name and ownership state")
    client = apigee.Client(a)
    if action == "undeploy-proxy":
        if options.revision not in state["revisions"]:
            raise ValueError("--revision must name an explicitly owned revision")
        _, env, _ = apigee.paths(a)
        client.request("DELETE", f"{env}/apis/{a['proxy']}/revisions/{options.revision}/deployments", missing=True)
    else:
        if not state.get("owns_proxy"):
            raise ValueError("proxy deletion requires explicit proxy ownership")
        apigee.cleanup(client, a)


def destroy_infrastructure(c, args):
    parser = argparse.ArgumentParser()
    parser.add_argument("--scope", choices=["apigee", "kubernetes"], required=True)
    parser.add_argument("--confirm-project", required=True)
    options = parser.parse_args(args)
    if options.confirm_project != c["project"]:
        raise ValueError("destruction requires the exact configured project")
    if options.scope == "apigee" and c["gateway"] != "apigee":
        raise ValueError("Apigee destruction requires an Apigee setup")
    check_context(c)
    if c["gateway"] == "apigee":
        a = apigee_config(c)
        if apigee.read_state(a).get("attachments"):
            raise ValueError("remove endpoint attachments before infrastructure destruction")
        for namespace in (a["kubernetes"]["namespace"], a["demo"]["backend_namespace"]):
            attachments = json.loads(apigee.kubectl(a, "-n", namespace, "get", "serviceattachments", "-o", "json"))
            if attachments["items"]:
                raise ValueError("remove producer ServiceAttachments before infrastructure destruction")
    if options.scope == "kubernetes":
        if c["infrastructure"] != "provision" or not c.get("starter_pack"):
            raise ValueError("supplied Kubernetes infrastructure is never destroyed")
        path = Path(c["starter_pack"])
        actual = output(["terraform", "-chdir=" + str(path / "infra/gcp-ephemeral"), "output", "-raw", "project_id"])
        if actual != c["project"]:
            raise ValueError("starter-pack Terraform state does not match selected project")
        run(["devspace", "--var", "CLUSTER_PROVIDER=gke", "run", "destroy-cluster"], cwd=path)
    else:
        import apigee_infra
        for module in ("ingress", "prerequisites"):
            data = ROOT / ".devspace/apigee-infra" / module
            if not (data / "terraform.tfstate").exists():
                raise ValueError("no repository-owned " + module + " state; supplied infrastructure is not destroyed")
        for module in ("ingress", "prerequisites"):
            values = json.loads((ROOT / ".devspace/apigee-infra" / module / "inputs.json").read_text())
            apigee_infra.terraform(c, module, values, destroy=True)


def dispatch(action, args):
    c = load()
    if not c:
        raise ValueError("run devspace run setup first")
    if action == "destroy-environment":
        import apigee_lifecycle
        apigee_lifecycle.destroy(c, args)
        return
    if action == "destroy-infrastructure":
        with lock():
            destroy_infrastructure(c, args)
        return
    if action == "repeatability":
        repeatability(c)
        return
    if c["gateway"] == "apigee":
        a = apigee_config(c)
        check_context(a)
        if action == "renew-certificates":
            import apigee_certificates
            apigee_certificates.run(a, args)
        elif action == "test-e2e":
            run([sys.executable, ROOT / "scripts/apigee_keycloak_test.py", "--config", c["apigee_config"], "--confirm", a["project"], *args])
            run([sys.executable, ROOT / "scripts/apigee_e2e.py", "--config", c["apigee_config"], "--confirm", a["project"]])
        elif action == "dashboard":
            run([sys.executable, ROOT / "scripts/apigee_dashboard.py", "--config", c["apigee_config"], "--confirm", a["project"], *args])
        elif action == "fixtures":
            import apigee_demo
            if a.get("synthetic_demo"):
                apigee_demo.secrets(a)
        elif action == "baseline":
            baseline(c)
        elif action == "cleanup-check":
            cleanup_check(a)
        elif action in ("undeploy-proxy", "delete-proxy-resources"):
            destructive(a, action, args)
        elif action == "test-logging":
            run([sys.executable, ROOT / "scripts/apigee_logging_test.py", "--config", c["apigee_config"], "--confirm", a["project"], *args])
        else:
            if action == "proxy" and a.get("demo") and (a.get("psc") or a["demo"].get("consumer_project")):
                import apigee_infra
                apigee_infra.connect(c, a)
            command = {"proxy": "deploy"}.get(action, action)
            run([sys.executable, ROOT / "scripts/apigee.py", command, "--config", c["apigee_config"], "--confirm", a["project"], *args])
    elif action == "smoke":
        ingress = c.get("ingress", {})
        from developer_runtime import wait_gateway
        wait_gateway(ingress, c.get("readiness_path", "/anything/yellow"))
        env = dict(os.environ, E2E_BASE_URL=ingress.get("url", ""), E2E_DIRECT_ADDRESS=ingress.get("address", ""),
                   E2E_CA_CERT_FILE=str(ROOT / ingress.get("certificate", "")), E2E_INSECURE_SKIP_VERIFY="false")
        run(["devspace", "run", "test-e2e", *args], cwd=ROOT, env=env)
    elif action == "preflight":
        check_context(c)
    elif action == "diagnostics":
        check_context(c)
        print(output(["kubectl", "--context=" + c["context"], "-n", c["namespace"], "get", "pods,services,gateways", "-o", "wide"]))
    elif action == "cleanup-check":
        check_context(c)
        resource = output(["kubectl", "--context=" + c["context"], "-n", "ext-authz-token-exchange-e2e", "get", "deployment", "fake-token-endpoint", "--ignore-not-found", "-o", "json"])
        if resource and json.loads(resource)["metadata"].get("annotations", {}).get("meta.helm.sh/release-name") != "ext-authz-token-exchange-e2e":
            raise ValueError("fixture Helm ownership is missing")
    else:
        raise ValueError("command is not supported for selected gateway: " + action)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["setup", "value", "dependency", "image-tag", "preflight", "fixtures", "proxy", "rollback", "smoke", "test-e2e", "dashboard", "diagnostics", "baseline", "repeatability", "cleanup-check", "undeploy-proxy", "delete-proxy-resources", "destroy-infrastructure", "destroy-environment", "test-logging", "log-format", "inspect-on", "inspect-off", "debug", "renew-certificates"])
    parser.add_argument("--gateway", choices=["gke-gateway", "apigee"])
    parser.add_argument("--infrastructure", choices=["provision", "existing"])
    parser.add_argument("--apigee", choices=["evaluation", "existing"])
    parser.add_argument("--inputs")
    parser.add_argument("--daily-budget", type=float)
    parser.add_argument("--starter-pack")
    parser.add_argument("--key")
    parser.add_argument("--default", default="")
    parser.add_argument("--selected", choices=["none", "apigee", "gke-gateway"], default="none")
    parser.add_argument("--local-path")
    args, extra = parser.parse_known_args()
    if extra and extra[0] == "--":
        extra.pop(0)
    if args.command == "value":
        selected = value(args.key, args.default)
        print(json.dumps(selected) if isinstance(selected, bool) else selected)
    elif args.command == "image-tag":
        print(image_tag())
    elif args.command == "dependency":
        source = {"path": args.local_path} if args.local_path else {"git": "https://github.com/michaelw/devspace-starter-pack"}
        print(json.dumps({} if args.selected != "none" else {"infra": {**source, "profiles": ["with-test"]}}))
    elif args.command == "setup":
        if not args.gateway or not args.infrastructure or extra:
            parser.error("setup requires --gateway and --infrastructure; unknown arguments are not accepted")
        setup(args)
    else:
        dispatch(args.command, extra)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print("E:", error, file=sys.stderr)
        sys.exit(1)
