"""Shared private issuer access and developer process cleanup."""

from contextlib import contextmanager
import socket
import subprocess
import tempfile
import time
import urllib.request
import urllib.parse


@contextmanager
def port_forward(context, namespace, service, remote_port):
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(["kubectl", "--context=" + context, "-n", namespace, "port-forward", "service/" + service, str(port) + ":" + str(remote_port), "--address=127.0.0.1"], stdout=log, stderr=log)
        try:
            deadline = time.monotonic() + 60
            while True:
                try:
                    connection = socket.create_connection(("127.0.0.1", port), timeout=2)
                    connection.close()
                    break
                except OSError:
                    if process.poll() is not None or time.monotonic() >= deadline:
                        raise RuntimeError("private service port forward did not become ready") from None
                    time.sleep(1)
            yield port
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


@contextmanager
def private_keycloak(context, namespace):
    with port_forward(context, namespace, "keycloak", 8080) as port:
        base = "http://127.0.0.1:" + str(port)
        deadline = time.monotonic() + 60
        while True:
            try:
                with urllib.request.urlopen(base + "/realms/token-exchange-e2e", timeout=2):
                    break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("private Keycloak realm did not become ready") from None
                time.sleep(1)
        yield base


def wait_gateway(ingress, path="/anything/yellow", timeout=180, synthetic_exchange=False):
    """Wait for the owned missing-bearer fixture through the actual gateway."""
    url = ingress["url"].rstrip("/")
    if not url.startswith("https://"):
        raise ValueError("gateway readiness requires HTTPS")
    command = ["curl", "--silent", "--show-error", "--max-time", "5", "-o", "/dev/null", "-w", "%{http_code}"]
    expected = "200" if synthetic_exchange else "401"
    if synthetic_exchange:
        command += ["-H", "Authorization: Bearer synthetic-subject"]
    if ingress.get("certificate"):
        command += ["--cacert", ingress["certificate"]]
    if ingress.get("address"):
        command += ["--resolve", urllib.parse.urlparse(url).hostname + ":443:" + ingress["address"]]
    deadline = time.monotonic() + timeout
    while True:
        response = subprocess.run(command + [url + path], text=True, capture_output=True)
        if response.returncode == 0 and response.stdout == expected:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError("gateway request path did not become ready; inspect gateway/service diagnostics")
        time.sleep(3)
