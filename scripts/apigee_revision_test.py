#!/usr/bin/env python3
"""Developer-only reversible import recovery and rollback probe on an owned proxy."""

import argparse
import copy

import apigee
import gateway


def run(c):
    if not c.get("synthetic_demo"):
        raise ValueError("revision probe requires owned synthetic fixtures")
    gateway.check_context(c)
    state = apigee.read_state(c)
    original = state.get("current")
    if not original:
        raise ValueError("revision probe requires a ready owned deployment")
    changed = copy.deepcopy(c)
    changed["timeout_ms"] = int(c.get("timeout_ms", 1000)) + 1
    if state.get("pending") and state["pending"]["digest"] != apigee.hashlib.sha256(apigee.bundle(changed)).hexdigest():
        raise ValueError("another bundle is pending; recover it before running the probe")

    class Interrupted(apigee.Client):
        def request(self, method, path, *args, **kwargs):
            result = super().request(method, path, *args, **kwargs)
            if method == "POST" and "action=import" in path:
                raise InterruptedError("controlled interruption after successful import")
            return result

    with apigee.operation_lock(c):
        if not state.get("pending"):
            try:
                apigee.deploy(Interrupted(c), changed)
            except InterruptedError:
                pass
        try:
            apigee.deploy(apigee.Client(c), changed)
            apigee.smoke(changed)
        finally:
            current = apigee.read_state(c)
            if current.get("current") != original:
                apigee.rollback(apigee.Client(c), c, original)
        apigee.smoke(c)
    gateway.persist(apigee.ROOT / ".devspace/apigee-revision-report.json", {
        "original_revision": original, "current_revision": apigee.read_state(c)["current"],
        "unique_import_recovered": True, "rollback_ready": True})
    print("Recovered interrupted import and verified rollback readiness")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default=".devspace/apigee.json")
    parser.add_argument("--confirm", required=True)
    args = parser.parse_args()
    config = apigee.load_config(args.config)
    apigee.confirmed(config, args)
    run(config)
