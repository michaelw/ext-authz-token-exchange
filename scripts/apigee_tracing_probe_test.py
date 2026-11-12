import unittest
from unittest.mock import patch

import apigee_tracing_probe as probe


class TracingProbeTests(unittest.TestCase):
    def test_supplied_infrastructure_cannot_receive_synthetic_traffic(self):
        with patch.object(probe.gateway, "check_context") as context:
            with self.assertRaisesRegex(ValueError, "synthetic"):
                probe.run({"synthetic_demo": False})
        context.assert_not_called()

    def test_wrong_context_stops_before_network_access(self):
        with patch.object(probe.gateway, "check_context", side_effect=ValueError("context mismatch")), \
             patch.object(probe.subprocess, "check_output") as request:
            with self.assertRaisesRegex(ValueError, "context"):
                probe.run({"synthetic_demo": True})
        request.assert_not_called()
