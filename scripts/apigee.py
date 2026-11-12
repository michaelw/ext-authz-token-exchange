#!/usr/bin/env python3
"""Explicit developer workflows. Importing this module never contacts GCP."""

import argparse
import datetime
import contextlib
import fcntl
import hashlib
import io
import ipaddress
import json
import os
import platform
from pathlib import Path
import re
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zipfile

ROOT = Path(__file__).resolve().parents[1]
API = "https://apigee.googleapis.com/v1/"


def build_go_binary(package, output, test=False):
    """Compile host executables in the shared toolchain, without host Go tools."""
    system = {"Darwin": "darwin", "Linux": "linux"}.get(platform.system())
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "AMD64": "amd64"}.get(platform.machine())
    if not system or not arch:
        raise ValueError("developer binaries support macOS/Linux on amd64/arm64")
    output = Path(output).resolve()
    relative = output.relative_to(ROOT.resolve())
    output.parent.mkdir(parents=True, exist_ok=True)
    cache = ROOT / ".devspace/toolchain-cache"
    cache.mkdir(parents=True, exist_ok=True)
    args = ["go", "test", "-c"] if test else ["go", "build"]
    args += ["-o", "/workspace/" + relative.as_posix(), package]
    subprocess.run(["docker", "run", "--rm", "--pull=never", "--user", str(os.getuid()) + ":" + str(os.getgid()), "-e", "HOME=/tmp", "-e", "GOOS=" + system, "-e", "GOARCH=" + arch,
                    "-v", str(ROOT) + ":/workspace", "-v", str(cache) + ":/go-cache", "-w", "/workspace", os.environ.get("TXE_TOOLCHAIN_IMAGE", "txe-toolchain:local"),
                    "sh", "-c", 'go generate ./... && exec "$@"', "sh", *args], check=True)
    return output


def load_config(path):
    c = json.loads(Path(path).read_text())
    for name in ("project", "context", "organization", "environment", "proxy", "proxy_service_account"):
        if not c.get(name):
            raise ValueError(f"{name} is required")
    for name in ("project", "organization", "environment", "proxy"):
        if not re.fullmatch(r"[a-zA-Z0-9_-]+", c[name]):
            raise ValueError(f"invalid {name}")
    if not c["proxy"].startswith("txe-"):
        raise ValueError("use a dedicated proxy name beginning txe-")
    for role in ("callout", "backend"):
        target = c[role]
        if not target.get("host") or not 0 < int(target.get("port", 443)) < 65536:
            raise ValueError(f"invalid {role} target")
        if not target.get("certificate"):
            raise ValueError(f"{role}.certificate PEM file is required")
    if not c["callout"].get("audience"):
        raise ValueError("callout.audience is required")
    return c


def bundle(c):
    result = io.BytesIO()
    with zipfile.ZipFile(result, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted((ROOT / "deploy/apigee/apiproxy").rglob("*.xml")):
            doc = ET.parse(path)
            relative = path.relative_to(ROOT / "deploy/apigee")
            if path.name == "token-exchange.xml":
                doc.getroot().set("name", c["proxy"])
                relative = Path("apiproxy") / (c["proxy"] + ".xml")
            if path.name == "EC-TokenExchange.xml":
                doc.find("./GrpcConnection/Server").set("name", target_name(c, "callout"))
                doc.find("./GrpcConnection/Authentication/GoogleIDToken/Audience").text = c["callout"]["audience"]
                doc.find("./TimeoutMs").text = str(c.get("timeout_ms", 1000))
            if path.parent.name == "targets":
                doc.find("./HTTPTargetConnection/LoadBalancer/Server").set("name", target_name(c, "backend"))
            if path.parent.name == "proxies":
                base_path = c.get("base_path", "/")
                if not re.fullmatch(r"/[A-Za-z0-9/_-]*", base_path):
                    raise ValueError("invalid proxy base_path")
                doc.find("HTTPProxyConnection/BasePath").text = base_path
            entry = zipfile.ZipInfo(str(relative), (1980, 1, 1, 0, 0, 0))
            archive.writestr(entry, ET.tostring(doc.getroot(), encoding="utf-8", xml_declaration=True))
    return result.getvalue()


def target_name(c, role):
    if not c.get("manage_targets", True):
        name = c[role].get("name")
        if not name or not re.fullmatch(r"[A-Za-z0-9_-]+", name):
            raise ValueError("externally managed targets require an explicit target name")
        return name
    target = dict(c[role])
    target["certificate"] = hashlib.sha256(Path(target["certificate"]).read_bytes()).hexdigest()
    digest = hashlib.sha256(json.dumps(target, sort_keys=True).encode()).hexdigest()[:12]
    return c["proxy"] + "-" + role + "-" + digest


def multipart(field, filename, data):
    boundary = "txe-" + hashlib.sha256(data).hexdigest()
    prefix = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n").encode()
    return prefix + data + f"\r\n--{boundary}--\r\n".encode(), "multipart/form-data; boundary=" + boundary


class Client:
    def __init__(self, c):
        self.c = c
        command = ["gcloud", "--project=" + c["project"]]
        if c.get("account"):
            command.append("--account=" + c["account"])
        self.command = command

    def request(self, method, path, data=None, content_type="application/json", missing=False, _attempt=0, raw=False):
        if data is not None and not isinstance(data, bytes):
            data = json.dumps(data).encode()
        token = subprocess.check_output(self.command + ["auth", "print-access-token"], text=True).strip()
        req = urllib.request.Request(API + path, data=data, method=method, headers={"Authorization": "Bearer " + token, "Content-Type": content_type})
        try:
            with urllib.request.urlopen(req, timeout=60) as response:
                body = response.read()
                return body if raw else (json.loads(body) if body else {})
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                error.close()
                return None
            if method == "GET" and error.code in (429, 500, 502, 503, 504) and _attempt < 2:
                error.close()
                time.sleep(2 ** _attempt)
                return self.request(method, path, data, content_type, missing, _attempt + 1, raw=raw)
            # Keep detailed errors local; never print arbitrary provider values.
            directory = ROOT / ".devspace/apigee-debug"
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, 0o700)
            error_path = directory / "api-error.json"
            fd = os.open(error_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as output, error:
                output.write(error.read(65536))
            raise RuntimeError(f"Apigee {method} {path.split('?')[0]} returned HTTP {error.code}") from None
        except (urllib.error.URLError, ssl.SSLError, TimeoutError):
            if method == "GET" and _attempt < 2:
                time.sleep(2 ** _attempt)
                return self.request(method, path, data, content_type, missing, _attempt + 1, raw=raw)
            raise RuntimeError(f"Apigee {method} transport failed; inspect state before retrying mutations") from None


def paths(c):
    org = "organizations/" + c["organization"]
    env = org + "/environments/" + c["environment"]
    return org, env, org + "/apis/" + c["proxy"]


def state_path(c):
    if c.get("ownership_state"):
        return ROOT / c["ownership_state"]
    return ROOT / ".devspace" / f"apigee-{c['organization']}-{c['environment']}-{c['proxy']}.json"


def save_state(c, state):
    state["target"] = {key: c[key] for key in ("organization", "environment", "proxy")}
    path = state_path(c)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    temp.write_text(json.dumps(state, indent=2) + "\n")
    temp.chmod(0o600)
    temp.replace(path)


def read_state(c):
    path = state_path(c)
    state = json.loads(path.read_text()) if path.exists() else {"revisions": [], "targets": [], "truststores": [], "attachments": []}
    if c.get("ownership_state") and path.exists() and state.get("target") != {key: c[key] for key in ("organization", "environment", "proxy")}:
        raise ValueError("supplied ownership state does not identify this organization/environment/proxy")
    return state


@contextlib.contextmanager
def operation_lock(c):
    path = state_path(c).with_suffix(".lock")
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("another operation is using this Apigee proxy") from None
        yield


def confirmed(c, args):
    if args.confirm != c["project"]:
        raise ValueError("cloud operations require --confirm " + c["project"])


def wait_ready(client, env, proxy, revision):
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        deployment = client.request("GET", f"{env}/apis/{proxy}/revisions/{revision}/deployments", missing=True)
        if deployment and deployment.get("state") == "READY":
            return
        if deployment and deployment.get("state") == "ERROR":
            raise RuntimeError("Apigee deployment failed; inspect gateway diagnostics")
        time.sleep(5)
    raise RuntimeError("Apigee deployment readiness timed out")


def configure_targets(client, c, state):
    _, env, _ = paths(c)
    if not c.get("manage_targets", True):
        return
    for role in ("callout", "backend"):
        target = c[role]
        cert = Path(target["certificate"]).read_bytes()
        # Content-addressed stores avoid replacing a truststore used by an old revision.
        store = c["proxy"] + "-" + role + "-" + hashlib.sha256(cert).hexdigest()[:12]
        resource = env + "/keystores/" + store
        if client.request("GET", resource, missing=True) is None:
            client.request("POST", env + "/keystores?name=" + store, {})
            state["truststores"].append(store)
            save_state(c, state)
        elif store not in state["truststores"]:
            raise RuntimeError("refusing to adopt an existing truststore: " + store)
        if client.request("GET", resource + "/aliases/ca", missing=True) is None:
            data, kind = multipart("certFile", "ca.pem", cert)
            client.request("POST", resource + "/aliases?alias=ca&format=keycertfile", data, kind)
        name = target_name(c, role)
        resource = env + "/targetservers/" + name
        existing = client.request("GET", resource, missing=True)
        if existing and name not in state["targets"]:
            raise RuntimeError("refusing to overwrite existing TargetServer: " + name)
        reference = c["proxy"] + "-" + role + "-trust"
        reference_path = env + "/references/" + reference
        current = client.request("GET", reference_path, missing=True)
        if current and reference not in state.get("references", []):
            raise RuntimeError("refusing to overwrite existing trust reference: " + reference)
        reference_body = {"name": reference, "resourceType": "TrustStore", "refers": store}
        if not current:
            state.setdefault("references", []).append(reference)
            save_state(c, state)
            client.request("POST", env + "/references", reference_body)
        elif current.get("refers") != store:
            client.request("PUT", reference_path, reference_body)
        body = {"name": name, "host": target["host"], "port": int(target.get("port", 443)), "isEnabled": True, "protocol": "GRPC" if role == "callout" else "HTTP", "sSLInfo": {"enabled": True, "ignoreValidationErrors": False, "trustStore": "ref://" + reference}}
        if target.get("server_name"):
            body["sSLInfo"]["commonName"] = {"value": target["server_name"]}
        if not existing:
            client.request("POST", env + "/targetservers", body)
        elif any(existing.get(key) != value for key, value in body.items()):
            client.request("PUT", resource, body)
        if name not in state["targets"]:
            state["targets"].append(name)
        save_state(c, state)


def deploy(client, c):
    org, env, api = paths(c)
    deadline = time.monotonic() + 900
    while True:
        instances = client.request("GET", org + "/instances").get("instances", [])
        if instances and all(instance.get("state") == "ACTIVE" for instance in instances):
            break
        if time.monotonic() >= deadline:
            raise RuntimeError("Apigee runtime is not active; retry after managed provisioning completes")
        print("Waiting for active Apigee runtime before importing a proxy...", flush=True)
        time.sleep(20)
    state = read_state(c)
    existing_proxy = client.request("GET", api, missing=True)
    if existing_proxy and not state.get("revisions") and not state.get("owns_proxy"):
        raise RuntimeError("existing proxy has no local ownership record; choose a new txe- proxy name")
    if not existing_proxy:
        state["owns_proxy"] = True
    if state.get("current") and state.get("digest"):
        state.setdefault("revision_digests", {})[state["current"]] = state["digest"]
    configure_targets(client, c, state)
    data = bundle(c)
    digest = hashlib.sha256(data).hexdigest()
    if state.get("digest") == digest:
        wait_ready(client, env, c["proxy"], state["current"])
        print("Proxy bundle unchanged; existing deployment is ready")
        return
    pending = state.get("pending", {})
    if pending.get("digest") == digest:
        if not pending.get("revision"):
            candidates = set(str(item) for item in (existing_proxy or {}).get("revision", [])) - set(str(item) for item in pending.get("before", []))
            if len(candidates) != 1:
                raise RuntimeError("import response was interrupted; revision inventory is ambiguous, refusing another import")
            candidate = candidates.pop()
            exported = client.request("GET", api + "/revisions/" + candidate + "?format=bundle", raw=True)
            if bundle_contents(exported) != bundle_contents(data):
                raise RuntimeError("interrupted import does not match the requested bundle; refusing adoption")
            pending["revision"] = candidate
            if candidate not in state["revisions"]:
                state["revisions"].append(candidate)
            save_state(c, state)
        revision = pending["revision"]
    else:
        if pending:
            raise RuntimeError("another bundle has a pending import/deployment; recover it before changing configuration")
        state["pending"] = {"digest": digest, "before": (existing_proxy or {}).get("revision", []), "status": "importing"}
        save_state(c, state)
        upload, kind = multipart("file", "proxy.zip", data)
        result = client.request("POST", org + "/apis?action=import&name=" + c["proxy"], upload, kind)
        revision = str(result["revision"])
        state["revisions"].append(revision)
        state["pending"] = {"revision": revision, "digest": digest}
    save_state(c, state)
    query = urllib.parse.urlencode({"override": "true", "serviceAccount": c["proxy_service_account"]})
    previous = state.get("current")
    try:
        client.request("POST", f"{env}/apis/{c['proxy']}/revisions/{revision}/deployments?{query}", {})
        wait_ready(client, env, c["proxy"], revision)
    except Exception:
        if previous:
            client.request("POST", f"{env}/apis/{c['proxy']}/revisions/{previous}/deployments?{query}", {})
            wait_ready(client, env, c["proxy"], previous)
        raise
    state.update(previous=previous, current=revision, digest=digest)
    state.setdefault("revision_digests", {})[revision] = digest
    state.pop("pending", None)
    save_state(c, state)
    print(json.dumps({"proxy": c["proxy"], "revision": revision, "bundle_sha256": digest}))


def bundle_contents(data):
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        result = {}
        for name in archive.namelist():
            if not name.endswith(".xml"):
                continue
            doc = ET.fromstring(archive.read(name))
            if name.count("/") == 1:
                doc.attrib.pop("revision", None)
                # Apigee adds timestamps and summaries derived from the XML files.
                for child in list(doc):
                    if child.tag in ("CreatedAt", "LastModifiedAt", "BasePaths", "Policies"):
                        doc.remove(child)
            result[name] = ET.canonicalize(ET.tostring(doc, encoding="unicode"), strip_text=True)
        return result


def rollback(client, c, revision):
    state = read_state(c)
    if revision not in state.get("revisions", []) or revision not in state.get("revision_digests", {}):
        raise ValueError("rollback requires an owned revision with a recorded bundle hash")
    _, env, _ = paths(c)
    query = urllib.parse.urlencode({"override": "true", "serviceAccount": c["proxy_service_account"]})
    client.request("POST", f"{env}/apis/{c['proxy']}/revisions/{revision}/deployments?{query}", {})
    wait_ready(client, env, c["proxy"], revision)
    state.update(previous=state.get("current"), current=revision, digest=state["revision_digests"][revision])
    state.pop("pending", None)
    save_state(c, state)


def preflight(client, c):
    org, env, _ = paths(c)
    organization = client.request("GET", org)
    client.request("GET", env)
    service_account = c["proxy_service_account"]
    if not service_account.endswith("@" + c["project"] + ".iam.gserviceaccount.com"):
        raise ValueError("proxy service account must belong to the Apigee project")
    if not c.get("synthetic_demo"):
        if organization.get("state") != "ACTIVE":
            raise ValueError("supplied Apigee organization must be ACTIVE")
        if not c.get("private_active"):
            raise ValueError("supply validated private callout/backend connectivity with private_active=true")
        permissions = ["apigee.deployments.create", "apigee.deployments.get", "apigee.deployments.delete"]
        granted = client.request("POST", env + ":testIamPermissions", {"permissions": permissions}).get("permissions", [])
        if set(permissions) - set(granted):
            raise ValueError("deployment identity lacks required Apigee environment permissions")
        identity = json.loads(subprocess.check_output(["gcloud", "iam", "service-accounts", "describe", service_account, "--project=" + c["project"], "--format=json(uniqueId)"], text=True))
        if not c.get("proxy_subject") or identity.get("uniqueId") != c["proxy_subject"]:
            raise ValueError("proxy_subject must match the dedicated service account unique ID")
        for role in ("callout", "backend", "ingress"):
            subprocess.run(["openssl", "x509", "-in", c[role]["certificate"], "-checkend", "86400", "-noout"], check=True, capture_output=True)
        if not c.get("acceptance_probe"):
            raise ValueError("existing non-demo setup requires an operator-supplied acceptance_probe")
    print(json.dumps({"organization_state": organization.get("state"), "billing_type": organization.get("billingType"), "expires": organization.get("expiresAt"), "context": c["context"], "environment": c["environment"], "cloud_provisioning": False}, indent=2))


def kubectl(c, *args, data=None):
    return subprocess.check_output(["kubectl", "--context=" + c["context"], *args], input=data, text=True)


def deploy_service(c):
    k = c["kubernetes"]
    release = k.get("release", "txe-apigee")
    if not release.startswith("txe-"):
        raise ValueError("use a dedicated txe- Helm release")
    current = subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip()
    if current != c["context"]:
        raise ValueError("select the configured Kubernetes context explicitly before deployment")
    subprocess.run(["devspace", "run-pipeline", "plugin-only"], cwd=ROOT, check=True)
    print("Plugin deployment ready; no cloud infrastructure was provisioned")


def logging_settings(c, settings):
    k = c["kubernetes"]
    release = k.get("release", "txe-apigee")
    if not release.startswith("txe-"):
        raise ValueError("logging changes require a dedicated txe- plugin deployment")
    current = subprocess.check_output(["kubectl", "config", "current-context"], text=True).strip()
    if current != c["context"]:
        raise ValueError("select the configured Kubernetes context explicitly")
    deployment = "deployment/" + release
    value = json.loads(kubectl(c, "-n", k["namespace"], "get", deployment, "-o", "json"))
    if value["metadata"].get("labels", {}).get("app.kubernetes.io/instance") != release:
        raise ValueError("plugin deployment ownership does not match")
    kubectl(c, "-n", k["namespace"], "set", "env", deployment, *settings)
    kubectl(c, "-n", k["namespace"], "rollout", "status", deployment, "--timeout=300s")
    wait_gateway(c)


def wait_gateway(c):
    if c.get("synthetic_demo"):
        from developer_runtime import wait_gateway as wait
        wait(c["ingress"], c.get("readiness_path", "/anything/yellow"))
        wait(c["ingress"], c.get("readiness_path", "/anything/yellow"), synthetic_exchange=True)


def inspection(c, enabled):
    settings = ["APIGEE_INSPECT_MESSAGES=" + str(enabled).lower()]
    if not enabled:
        settings.append("TOKEN_EXCHANGE_INSECURE_LOG_TOKENS=false")
    logging_settings(c, settings)
    print("Temporary inspection " + ("enabled; token logging unchanged" if enabled else "disabled; token logging disabled"))


def log_format(c, value):
    if value not in ("json", "text"):
        raise ValueError("log format must be json or text")
    logging_settings(c, ["TOKEN_EXCHANGE_LOG_FORMAT=" + value])
    print("Plugin restarted with log format=" + value)


def diagnostics(c):
    k = c["kubernetes"]
    print(kubectl(c, "-n", k["namespace"], "get", "pods,services", "-o", "wide"))
    print(kubectl(c, "-n", k["namespace"], "logs", "-l", "app.kubernetes.io/instance=" + k.get("release", "txe-apigee"), "--all-containers=true", "--tail=100"))


def production_probe(c):
    probe = c.get("acceptance_probe", {})
    path = probe.get("path", "")
    expected = probe.get("status")
    base = c["ingress"]["url"].rstrip("/")
    if not base.startswith("https://") or not path.startswith("/") or path.startswith("//") or not isinstance(expected, int) or not 200 <= expected < 500:
        raise ValueError("acceptance_probe requires an absolute local path and expected status 200..499 on HTTPS ingress")
    command = ["curl", "--silent", "--show-error", "--max-time", "15", "--cacert", c["ingress"]["certificate"], "-o", "/dev/null", "-w", "%{http_code}"]
    if c["ingress"].get("address"):
        command += ["--resolve", urllib.parse.urlparse(base).hostname + ":443:" + c["ingress"]["address"]]
    status = subprocess.check_output(command + [base + path], text=True).strip()
    if status != str(expected):
        raise RuntimeError("operator acceptance probe returned an unexpected status")
    print("Operator-supplied HTTPS acceptance probe passed; full authorization QA remains operator-run.")


def smoke(c):
    if not c.get("synthetic_demo"):
        return production_probe(c)
    wait_gateway(c)
    base = c["ingress"]["url"].rstrip("/")
    if not base.startswith("https://"):
        raise ValueError("ingress URL must use HTTPS")
    # curl --resolve supports split DNS while retaining certificate validation.
    command = ["curl", "--silent", "--show-error", "--fail-with-body", "--max-time", "15", "--cacert", c["ingress"]["certificate"]]
    address = c["ingress"].get("address")
    if address:
        host = urllib.parse.urlparse(base).hostname
        command += ["--resolve", host + ":443:" + address]
    checks = [("missing-bearer", "/anything/yellow", None, 401), ("exchange", "/anything/yellow?synthetic=preserved", "Bearer synthetic-subject", 200), ("explicit-deny", "/anything/denied", "Bearer synthetic-subject", 403), ("unmatched", "/status/204", None, 204), ("malformed-bearer", "/anything/yellow", "Bearer a b", 401), ("duplicate-bearer", "/anything/yellow", "Bearer synthetic-subject", 401), ("oauth-invalid-grant", "/anything/error-invalid-grant", "Bearer synthetic-subject", 400), ("preflight", "/anything/yellow", None, 200), ("options-not-preflight", "/anything/yellow", None, 401)]
    results = []
    for name, path, auth, expected in checks:
        args = command + ["-H", "X-Txe-Debug: synthetic", "-H", "X-Txe-Preserved: synthetic"]
        if auth:
            args += ["-H", "Authorization: " + auth]
        if name == "duplicate-bearer":
            args += ["-H", "Authorization: Bearer another-synthetic-subject"]
        if name in ("preflight", "options-not-preflight"):
            args += ["-X", "OPTIONS"]
        if name == "preflight":
            args += ["-H", "Origin: https://synthetic.example", "-H", "Access-Control-Request-Method: POST"]
        if name == "exchange":
            args += ["-H", "Content-Type: application/json", "--data", '{"synthetic":"preserved"}']
        result = subprocess.run(args + ["-w", "\n%{http_code}", base + path], text=True, capture_output=True)
        body, _, status = result.stdout.rpartition("\n")
        if status != str(expected):
            detail = result.stderr[:500] if status == "000" else "inspect Debug/service logs"
            raise RuntimeError(f"smoke {name}: expected {expected}, received {status}; {detail}")
        if name == "exchange":
            echo = json.loads(body)
            authorization = next((value for key, value in echo["headers"].items() if key.lower() == "authorization"), [])
            if isinstance(authorization, str):
                authorization = [authorization]
            if not authorization or authorization == ["Bearer synthetic-subject"]:
                raise RuntimeError("backend did not receive a replacement token")
            if echo.get("json") != {"synthetic": "preserved"}:
                raise RuntimeError("POST body changed in transit")
            if echo.get("args") != {"synthetic": ["preserved"]}:
                raise RuntimeError("query parameters changed in transit")
            preserved = next((value for key, value in echo["headers"].items() if key.lower() == "x-txe-preserved"), [])
            if preserved not in ("synthetic", ["synthetic"]) or echo.get("method") != "POST":
                raise RuntimeError("unrelated request header or method changed in transit")
        results.append({"scenario": name, "status": int(status)})
    output = ROOT / ".devspace/apigee-smoke.json"
    output.parent.mkdir(exist_ok=True)
    evidence = json.dumps({"time": datetime.datetime.now(datetime.timezone.utc).isoformat(), "proxy": c["proxy"], "targets": {role: c[role]["host"] for role in ("callout", "backend")}, "deployment": read_state(c), "results": results}, indent=2)
    output.write_text(evidence)
    (output.parent / ("apigee-" + c["proxy"] + "-smoke.json")).write_text(evidence)
    print(json.dumps(results, indent=2))


def cleanup(client, c):
    _, env, api = paths(c)
    state = read_state(c)
    existing_proxy = client.request("GET", api, missing=True) or {}
    owned_proxy = state.get("owns_proxy") or (bool(state["revisions"]) and set(existing_proxy.get("revision", [])) == set(state["revisions"]))
    deployments = client.request("GET", f"{env}/apis/{c['proxy']}/deployments", missing=True) or {}
    active = {str(item["revision"]) for item in deployments.get("deployments", [])}
    for revision in reversed(state["revisions"]):
        if revision in active:
            client.request("DELETE", f"{env}/apis/{c['proxy']}/revisions/{revision}/deployments", missing=True)
        client.request("DELETE", api + "/revisions/" + revision, missing=True)
    for name in state["targets"]:
        client.request("DELETE", env + "/targetservers/" + name, missing=True)
    for name in state.get("references", []):
        client.request("DELETE", env + "/references/" + name, missing=True)
    for name in state["truststores"]:
        client.request("DELETE", env + "/keystores/" + name, missing=True)
    for name in state.get("attachments", []):
        operation = client.request("DELETE", "organizations/" + c["organization"] + "/endpointAttachments/" + name, missing=True)
        deadline = time.monotonic() + 600
        while operation and operation.get("name") and not operation.get("done"):
            if time.monotonic() >= deadline:
                raise RuntimeError("PSC deletion is still running; keep ownership state and retry cleanup")
            time.sleep(5)
            operation = client.request("GET", operation["name"])
        if operation and operation.get("error"):
            raise RuntimeError("PSC deletion failed; preserve producer resources and inspect diagnostics")
    if owned_proxy:
        remaining = client.request("GET", api, missing=True)
        if remaining and not remaining.get("revision"):
            client.request("DELETE", api, missing=True)
    state_path(c).unlink(missing_ok=True)
    print("Removed only locally recorded proxy revisions, targets and truststores")


def repeatability(c):
    if not c.get("synthetic_demo"):
        raise ValueError("repeatability uses owned synthetic demo namespaces")
    def snapshot():
        resources = {}
        for namespace in (c["kubernetes"]["namespace"], c["demo"]["backend_namespace"]):
            for kind in ("services", "serviceattachments"):
                data = json.loads(kubectl(c, "-n", namespace, "get", kind, "-o", "json"))
                resources[namespace + "/" + kind] = {item["metadata"]["name"]: item["metadata"]["uid"] for item in data["items"]}
        return resources
    resources = snapshot()
    results = []
    for cycle in range(2):
        deploy_service(c)
        deploy(Client(c), c)
        smoke(c)
        if snapshot() != resources:
            raise RuntimeError("Service or PSC attachment identities changed during repeated deployment")
        results.append({"cycle": cycle + 1, "stable_service_and_attachment_uids": True, "revision": read_state(c)["current"]})
    if results[0]["revision"] != results[1]["revision"]:
        raise RuntimeError("unchanged proxy deployment created another revision")
    output = ROOT / ".devspace/apigee-repeatability.json"
    output.write_text(json.dumps({"results": results, "resources": resources}, indent=2))
    print("Two repeatable deployment cycles passed with stable gateway and service resources")


def psc(client, c):
    org, _, _ = paths(c)
    state = read_state(c)
    hosts = {}
    for role in ("callout", "backend"):
        attachment = c["psc"][role]
        if not re.fullmatch(r"projects/[^/]+/regions/[^/]+/serviceAttachments/[^/]+", attachment):
            raise ValueError("invalid PSC service attachment")
        digest = hashlib.sha256(attachment.encode()).hexdigest()[:10]
        name = c["proxy"][:10] + "-" + role + "-" + digest
        resource = org + "/endpointAttachments/" + name
        existing = client.request("GET", resource, missing=True)
        if existing and name not in state.get("attachments", []):
            raise RuntimeError("refusing to adopt an existing endpoint attachment")
        recorded = state.get("attachment_operations", {}).get(name)
        if recorded:
            operation = client.request("GET", recorded)
            deadline = time.monotonic() + 600
            while not operation.get("done") and time.monotonic() < deadline:
                time.sleep(5)
                operation = client.request("GET", recorded)
            if not operation.get("done") or operation.get("error"):
                raise RuntimeError("recorded PSC operation failed or is still running; keep ownership state")
        if not existing:
            operation = client.request("POST", org + "/endpointAttachments?endpointAttachmentId=" + name,
                                       {"location": c["region"], "serviceAttachment": attachment})
            state.setdefault("attachments", []).append(name)
            state.setdefault("attachment_operations", {})[name] = operation.get("name")
            save_state(c, state)
            deadline = time.monotonic() + 600
            while not operation.get("done") and time.monotonic() < deadline:
                time.sleep(5)
                operation = client.request("GET", operation["name"])
            if not operation.get("done") or operation.get("error"):
                raise RuntimeError("PSC operation failed or timed out; inspect the recorded attachment")
        deadline = time.monotonic() + 600
        while True:
            existing = client.request("GET", resource)
            if existing.get("state") == "ACTIVE" and existing.get("connectionState") == "ACCEPTED":
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("PSC attachment not accepted/active; check producer consumer allowlist")
            time.sleep(10)
        hosts[role] = existing["host"]
        if name in state.get("attachment_operations", {}):
            state["attachment_operations"].pop(name)
            save_state(c, state)
    try:
        public_targets = {role: str(ipaddress.ip_address(c[role]["host"])) for role in hosts}
    except ValueError:
        public_targets = {}
    if public_targets:
        c.setdefault("public_targets", public_targets)
    for role, host in hosts.items():
        c[role]["host"] = host
    c["private_active"] = True
    print(json.dumps({"private_target_hosts": hosts, "connection": "ACTIVE/ACCEPTED"}, indent=2))


def debug(client, c, args):
    _, env, _ = paths(c)
    state = read_state(c)
    revision = args.revision or state["current"]
    if not str(revision).isdigit() or (args.session and not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", args.session)):
        raise ValueError("invalid Debug revision or session ID")
    if args.session:
        metadata = ROOT / ".devspace/apigee-debug" / urllib.parse.quote(args.session, safe="") / "session.json"
        if metadata.exists():
            revision = json.loads(metadata.read_text())["revision"]
    base = f"{env}/apis/{c['proxy']}/revisions/{revision}/debugsessions"
    if not args.session:
        if not c.get("synthetic_demo"):
            raise ValueError("gateway Debug capture requires synthetic_demo=true")
        session = client.request("POST", base, {"timeout": "120", "count": 15, "filter": 'request.header.x-txe-debug = "synthetic"'})
        directory = ROOT / ".devspace/apigee-debug" / urllib.parse.quote(session["name"], safe="")
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o700)
        (directory / "session.json").write_text(json.dumps({"revision": revision}))
        print(json.dumps(session))
        print("Wait at least 20 seconds, then send synthetic requests with X-Txe-Debug: synthetic")
    else:
        session = urllib.parse.quote(args.session, safe="")
        transactions = client.request("GET", base + "/" + session + "/data")
        output = ROOT / ".devspace/apigee-debug" / session
        output.mkdir(parents=True, exist_ok=True)
        os.chmod(output, 0o700)
        for transaction in transactions:
            name = urllib.parse.quote(str(transaction), safe="")
            data = client.request("GET", base + "/" + session + "/data/" + name)
            path = output / (hashlib.sha256(name.encode()).hexdigest()[:16] + ".json")
            path.write_text(json.dumps(data, indent=2))
            os.chmod(path, 0o600)
        print("Saved sensitive gateway Debug data to ignored directory:", output)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["bundle", "preflight", "deploy", "rollback", "deploy-service", "diagnostics", "inspect-on", "inspect-off", "log-format", "smoke", "repeatability", "cleanup", "debug", "psc"])
    parser.add_argument("--format", choices=["json", "text"])
    parser.add_argument("--config", default=".devspace/apigee.json")
    parser.add_argument("--confirm", default="")
    parser.add_argument("--output", default=".devspace/apigee-proxy.zip")
    parser.add_argument("--session")
    parser.add_argument("--revision")
    args = parser.parse_args()
    c = load_config(args.config)
    if args.command == "bundle":
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(bundle(c))
        print(path)
        return
    confirmed(c, args)
    if args.command in ("deploy-service", "repeatability"):
        execute(c, args)
    else:
        with operation_lock(c):
            execute(c, args)


def execute(c, args):
    local_commands = {"deploy-service": deploy_service, "diagnostics": diagnostics, "inspect-on": lambda c: inspection(c, True), "inspect-off": lambda c: inspection(c, False), "log-format": lambda c: log_format(c, args.format), "smoke": smoke, "repeatability": repeatability}
    if args.command in local_commands:
        local_commands[args.command](c)
        return
    client = Client(c)
    {"preflight": lambda: preflight(client, c), "deploy": lambda: deploy(client, c), "rollback": lambda: rollback(client, c, args.revision), "cleanup": lambda: cleanup(client, c), "debug": lambda: debug(client, c, args), "psc": lambda: psc(client, c)}[args.command]()
    if args.command == "psc":
        Path(args.config).write_text(json.dumps(c, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, RuntimeError, KeyError, OSError, subprocess.CalledProcessError) as error:
        print("E:", error, file=sys.stderr)
        sys.exit(1)
