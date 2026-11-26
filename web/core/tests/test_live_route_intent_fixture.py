from django.test import SimpleTestCase

from core.tests.live_route_intent_fixture import _ping_ok


class GatewayPingLossParserTests(SimpleTestCase):
    def test_requires_actual_zero_loss(self):
        self.assertTrue(_ping_ok("3 packets transmitted, 3 received, 0% packet loss"))
        self.assertTrue(_ping_ok("Success rate is 100 percent (3/3), 0.0% packet loss"))
        self.assertFalse(_ping_ok("3 packets transmitted, 0 received, 100% packet loss"))
        self.assertFalse(_ping_ok("packet loss unavailable"))

