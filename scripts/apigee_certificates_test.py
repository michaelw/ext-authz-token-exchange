import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch, Mock

import apigee_certificates as renewal


class RenewalTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.root_patch = patch.object(renewal.gateway, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.tls = self.root / ".devspace/apigee-tls"
        self.tls.mkdir(parents=True)
        self.c = {"project":"example", "synthetic_demo":True, "private_active":True, "managed_ingress":True,
                  "demo":{}, "ingress":{}, "callout":{}, "backend":{}}
        self.files = []
        for role in ("callout", "backend", "ingress"):
            for suffix in ("cert", "key"):
                filename = self.tls / (role + "." + suffix)
                filename.write_text("old-" + role)
                backup = self.root / (role + "-old." + suffix)
                backup.write_text(filename.read_text())
                replacement = self.root / (role + "-new." + suffix)
                replacement.write_text("new-" + role)
                self.files.append({"path":str(filename), "backup":str(backup), "replacement":str(replacement)})
                if role == "ingress":
                    self.c[role]["server_certificate" if suffix == "cert" else "server_key"] = str(filename)
                else:
                    self.c["demo"][role + "_" + suffix] = str(filename)
            self.c[role]["certificate"] = "old-trust"
        self.next = copy.deepcopy(self.c)
        for role in ("callout", "backend"):
            self.next[role]["certificate"] = "old-and-new-trust"
        self.state = {"project":"example", "original":self.c, "next":self.next, "ca":"new-trust", "files":self.files, "stage":"prepared"}
        self.config = self.root / ".devspace/apigee.json"
        renewal.gateway.persist(self.config, self.c)

    def test_supplied_or_external_certificates_are_never_renewed(self):
        renewal.validate(self.c)
        for change in ({"synthetic_demo":False}, {"managed_ingress":False}, {"private_active":False}):
            with self.assertRaises(ValueError):
                renewal.validate(dict(self.c, **change))
        self.c["demo"]["callout_key"] = str(self.root / "operator.key")
        with self.assertRaises(ValueError):
            renewal.validate(self.c)

    def exercise(self, fail=False):
        active = {"trust":None}
        def targets(client, c):
            active["trust"] = c["callout"]["certificate"]
        def secrets(c):
            if Path(self.c["demo"]["callout_cert"]).read_text().startswith("new"):
                self.assertEqual(active["trust"], "old-and-new-trust")
            elif active["trust"] != "old-and-new-trust":
                self.fail("old serving files restored without overlap trust")
        with patch.object(renewal.gateway, "load", return_value={"apigee_config":".devspace/apigee.json"}), \
             patch.object(renewal.apigee, "Client"), patch.object(renewal.apigee, "read_state", return_value={}), \
             patch.object(renewal.apigee, "deploy", side_effect=targets), \
             patch.object(renewal.apigee_demo, "secrets", side_effect=secrets), \
             patch.object(renewal.apigee_infra, "ingress"), \
             patch.object(renewal.apigee, "smoke", side_effect=RuntimeError("probe failure") if fail else None):
            if fail:
                with self.assertRaisesRegex(RuntimeError, "probe failure"):
                    renewal.reconcile(self.c, self.root / "journal.json", self.state)
            else:
                renewal.reconcile(self.c, self.root / "journal.json", self.state)
        return active["trust"]

    def test_new_serving_material_follows_overlap_trust(self):
        self.assertEqual(self.exercise(), "new-trust")
        self.assertEqual(self.state["stage"], "ready")
        self.assertEqual(json.loads(self.config.read_text())["callout"]["certificate"], "new-trust")
        self.assertTrue(all(Path(item["backup"]).exists() for item in self.files))
        self.assertEqual((self.root / "journal.json").stat().st_mode & 0o777, 0o600)

    def test_failure_restores_serving_files_and_configuration(self):
        self.assertEqual(self.exercise(fail=True), "old-trust")
        self.assertEqual(self.state["stage"], "rolled-back")
        self.assertEqual(json.loads(self.config.read_text()), self.c)
        self.assertTrue(all(Path(item["path"]).read_text().startswith("old") for item in self.files))

    def test_interrupted_serving_stage_reconciles_safely(self):
        self.state["stage"] = "serving-updated"
        renewal.publish_files(self.state)
        self.assertEqual(self.exercise(), "new-trust")
        self.assertEqual(self.state["stage"], "ready")

    def test_missing_namespace_ownership_stops_before_deployment_mutation(self):
        c = {"kubernetes":{"namespace":"plugin"}, "demo":{"system_namespace":"system", "backend_namespace":"backend"}}
        with patch.object(renewal.apigee, "kubectl", return_value=json.dumps({"metadata":{}})):
            with self.assertRaisesRegex(ValueError, "ownership"):
                renewal.check_ownership(c)
