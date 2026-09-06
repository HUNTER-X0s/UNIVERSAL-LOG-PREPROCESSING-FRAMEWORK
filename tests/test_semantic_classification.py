"""Unit tests for ULPF Phase 4 Semantic Classification and Explainability."""

import unittest

from ulpf_semantic.classification.classifier import SemanticClassifier


class TestSemanticClassification(unittest.TestCase):
    def setUp(self) -> None:
        self.classifier = SemanticClassifier()

    def test_classify_paloalto_drop(self) -> None:
        uce = {
            "event": {
                "category": "security",
                "type": "firewall",
                "action": "drop",
                "metadata": {
                    "vendor": "Palo Alto Networks",
                    "product": "PAN-OS",
                    "parser_id": "parser.paloalto.panos",
                },
            }
        }
        triple, conf, trace = self.classifier.classify(uce)
        self.assertEqual(triple.category, "SECURITY")
        self.assertEqual(triple.class_name, "Firewall")
        self.assertEqual(triple.type_name, "firewall.deny")
        self.assertEqual(conf.level.value, "EXACT")
        self.assertEqual(trace.rule_id, "rule.firewall.deny")
        self.assertTrue(len(trace.evidence) > 0)
        self.assertIsNotNone(trace.explanation)

    def test_classify_fortigate_deny(self) -> None:
        uce = {
            "event": {
                "category": "security",
                "type": "traffic",
                "action": "deny",
                "metadata": {
                    "vendor": "Fortinet",
                    "product": "FortiGate",
                    "parser_id": "parser.fortinet.fortigate",
                },
            }
        }
        triple, conf, trace = self.classifier.classify(uce)
        self.assertEqual(triple.category, "SECURITY")
        self.assertEqual(triple.class_name, "Firewall")
        self.assertEqual(triple.type_name, "firewall.deny")
        self.assertEqual(trace.rule_id, "rule.firewall.deny")

    def test_classify_suricata_alert(self) -> None:
        uce = {
            "event": {
                "category": "security",
                "type": "alert",
                "action": "alert",
                "metadata": {
                    "vendor": "Suricata",
                    "product": "EVE",
                    "parser_id": "parser.suricata.eve",
                },
            }
        }
        triple, conf, trace = self.classifier.classify(uce)
        self.assertEqual(triple.category, "SECURITY")
        self.assertEqual(triple.class_name, "Detection Finding")
        self.assertEqual(triple.type_name, "ids.alert")
        self.assertEqual(trace.rule_id, "rule.ids.alert")

    def test_classify_http_web_access(self) -> None:
        uce = {
            "event": {
                "category": "web",
                "type": "access",
                "action": "allow",
                "metadata": {
                    "vendor": "NGINX",
                    "parser_id": "parser.web.access",
                },
            }
        }
        triple, conf, trace = self.classifier.classify(uce)
        self.assertEqual(triple.category, "WEB")
        self.assertEqual(triple.class_name, "HTTP Activity")
        self.assertEqual(triple.type_name, "http.request")

    def test_classify_generic_fallback(self) -> None:
        uce = {
            "event": {
                "category": "telemetry",
                "type": "custom",
                "metadata": {
                    "parser_id": "parser.generic.json",
                },
            }
        }
        triple, conf, trace = self.classifier.classify(uce)
        self.assertEqual(triple.category, "OTHER")
        self.assertEqual(triple.type_name, "generic.telemetry")
        self.assertEqual(conf.level.value, "LOW")
        self.assertEqual(trace.rule_id, "rule.generic.fallback")


if __name__ == "__main__":
    unittest.main()
