"""Unit tests for ULPF Phase 4 Semantic Taxonomy, Actions, Results, and Dimensions."""

import unittest

from ulpf_semantic.taxonomy.actions import ActionTaxonomy, map_action
from ulpf_semantic.taxonomy.categories import EventCategory, EventClass, EventType
from ulpf_semantic.taxonomy.dimensions import extract_aggregation_keys
from ulpf_semantic.taxonomy.results import ResultStatus, derive_result


class TestSemanticTaxonomy(unittest.TestCase):
    def test_categories_enum(self) -> None:
        self.assertEqual(EventCategory.NETWORK.value, "NETWORK")
        self.assertEqual(EventCategory.SECURITY.value, "SECURITY")
        self.assertEqual(EventCategory.FIREWALL.value, "FIREWALL")
        self.assertIn("CLOUD", [c.value for c in EventCategory])

    def test_classes_enum(self) -> None:
        self.assertEqual(EventClass.NETWORK_ACTIVITY.value, "Network Activity")
        self.assertEqual(EventClass.SECURITY_FINDING.value, "Security Finding")
        self.assertEqual(EventClass.AUTHENTICATION.value, "Authentication")

    def test_types_enum(self) -> None:
        self.assertEqual(EventType.FIREWALL_DENY.value, "firewall.deny")
        self.assertEqual(EventType.FIREWALL_ALLOW.value, "firewall.allow")
        self.assertEqual(EventType.IDS_ALERT.value, "ids.alert")
        self.assertEqual(EventType.USER_AUTHENTICATION.value, "user.authentication")


class TestActionTaxonomy(unittest.TestCase):
    def test_map_permissive_actions(self) -> None:
        for token in ("allow", "permit", "accept", "pass", "forward"):
            act = map_action(original=token, normalized=token)
            self.assertEqual(act.semantic, ActionTaxonomy.ALLOW.value)
            self.assertEqual(act.original, token)

    def test_map_restrictive_actions(self) -> None:
        act_drop = map_action(original="drop", normalized="drop")
        self.assertEqual(act_drop.semantic, ActionTaxonomy.DROP.value)

        act_deny = map_action(original="deny", normalized="deny")
        self.assertEqual(act_deny.semantic, ActionTaxonomy.DENY.value)

        act_block = map_action(original="block", normalized="block")
        self.assertEqual(act_block.semantic, ActionTaxonomy.BLOCK.value)

    def test_map_unknown_action(self) -> None:
        act = map_action(original=None, normalized=None)
        self.assertEqual(act.semantic, ActionTaxonomy.UNKNOWN.value)


class TestResultTaxonomy(unittest.TestCase):
    def test_derive_from_action(self) -> None:
        act_allow = map_action("allow", "allow")
        res = derive_result(act_allow)
        self.assertEqual(res.status, ResultStatus.ALLOWED.value)

        act_drop = map_action("drop", "drop")
        res_drop = derive_result(act_drop)
        self.assertEqual(res_drop.status, ResultStatus.BLOCKED.value)

    def test_derive_from_http_status(self) -> None:
        act = map_action("access", "access")
        res_200 = derive_result(act, status_code=200)
        self.assertEqual(res_200.status, ResultStatus.SUCCESS.value)

        res_401 = derive_result(act, status_code=401)
        self.assertEqual(res_401.status, ResultStatus.DENIED.value)

        res_500 = derive_result(act, status_code=500)
        self.assertEqual(res_500.status, ResultStatus.FAILURE.value)

    def test_derive_from_raw_status(self) -> None:
        act = map_action("auth", "auth")
        res_fail = derive_result(act, raw_status="FAILURE")
        self.assertEqual(res_fail.status, ResultStatus.FAILURE.value)


class TestAnalyticsDimensions(unittest.TestCase):
    def test_extract_keys(self) -> None:
        event = {
            "source": {"ip": "192.168.1.100"},
            "destination": {"ip": "10.0.0.1"},
            "network": {"protocol": "TCP"},
            "identity": {"user": {"name": "alice"}},
            "device": {"hostname": "fw-edge-01"},
        }
        keys = extract_aggregation_keys(event, vendor="Cisco", product="ASA")
        self.assertEqual(keys["source_ip"], "192.168.1.100")
        self.assertEqual(keys["destination_ip"], "10.0.0.1")
        self.assertEqual(keys["protocol"], "TCP")
        self.assertEqual(keys["user"], "alice")
        self.assertEqual(keys["host"], "fw-edge-01")
        self.assertEqual(keys["vendor"], "Cisco")
        self.assertEqual(keys["product"], "ASA")


if __name__ == "__main__":
    unittest.main()
