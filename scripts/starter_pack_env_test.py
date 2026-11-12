import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


class StarterPackDiscoveryTests(unittest.TestCase):
    def test_namespace_fallback_and_published_value(self):
        script = Path(__file__).with_name("starter-pack-env.sh").resolve()
        for context, published, expected in (
            ("kind-example", None, "istio-ingress"),
            ("gke_example_region_cluster", None, "gke-gateway"),
            ("kind-example", "supplied-gateway", "supplied-gateway"),
        ):
            with self.subTest(context=context, published=published), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                kubectl = root / "kubectl"
                data = {"data": {"STARTER_PACK_ENV_VERSION": "v1", "GATEWAY_NAMESPACE": published}}
                kubectl.write_text("#!/bin/sh\n" + ("exit 1\n" if published is None else "printf '%s\\n' '" + json.dumps(data) + "'\n"))
                kubectl.chmod(0o700)
                env = dict(os.environ, PATH=str(root) + os.pathsep + os.environ["PATH"], DEVSPACE_TMPDIR=directory)
                result = subprocess.check_output([str(script), "get", "GATEWAY_NAMESPACE", "gke-gateway", context], cwd=root, env=env, text=True)
                self.assertEqual(result.strip(), expected)
