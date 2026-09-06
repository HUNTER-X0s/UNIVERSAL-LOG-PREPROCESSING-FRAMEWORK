"""Unit tests for Phase 3 Tier A generic parsers.

Tests:
- GenericJsonParser (depth/key limits, field extraction, failures)
- NdJsonParser (delegates to GenericJsonParser per line)
- GenericCsvParser (delimiter sniffing, header, multi-row)
- KeyValueParser (quoted/bare values, prefix, duplicates)
- SyslogRFC3164Parser (with and without PRI, partial parse)
- SyslogRFC5424Parser (structured data, NIL fields, partial parse)
"""

import unittest

from ulpf_parser_runtime.framing import FramedRecord
from ulpf_parser_runtime.models import ParseStatus
from ulpf_parser_runtime.parsers.csv_parser import GenericCsvParser
from ulpf_parser_runtime.parsers.json_parser import GenericJsonParser, NdJsonParser
from ulpf_parser_runtime.parsers.kv_parser import KeyValueParser
from ulpf_parser_runtime.parsers.syslog_rfc3164 import SyslogRFC3164Parser
from ulpf_parser_runtime.parsers.syslog_rfc5424 import SyslogRFC5424Parser


def _record(text: str) -> FramedRecord:
    raw = text.encode()
    return FramedRecord(
        record_index=0,
        text=text,
        raw_bytes=raw,
        start_byte_offset=0,
        end_byte_offset=len(raw),
        line_count=text.count("\n") + 1,
    )


# ---------------------------------------------------------------------------
# JSON Parser
# ---------------------------------------------------------------------------


class TestGenericJsonParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = GenericJsonParser()

    def test_parse_flat_json(self) -> None:
        rec = _record('{"src_ip": "10.0.0.1", "dst_port": 443, "action": "allow"}')
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("src_ip", result.extracted_fields)
        self.assertEqual(result.extracted_fields["src_ip"].value, "10.0.0.1")
        self.assertIn("dst_port", result.extracted_fields)
        self.assertEqual(result.extracted_fields["dst_port"].value, 443)

    def test_parse_nested_json(self) -> None:
        rec = _record('{"outer": {"inner": "value"}}')
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("outer.inner", result.extracted_fields)
        self.assertEqual(result.extracted_fields["outer.inner"].value, "value")

    def test_parse_json_array_top_level(self) -> None:
        rec = _record('[{"a": 1}, {"b": 2}]')
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARTIAL)
        self.assertIn("raw_value", result.unmapped_fields)

    def test_malformed_json(self) -> None:
        rec = _record("{not: valid json}")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.FAILED)
        self.assertTrue(len(result.errors) > 0)

    def test_raw_locator_format(self) -> None:
        rec = _record('{"event_type": "login"}')
        result = self.parser.parse(rec)
        field = result.extracted_fields["event_type"]
        self.assertEqual(field.raw_locator, "json:event_type")

    def test_depth_bounded_nesting(self) -> None:
        # Build deeply nested JSON exceeding max_depth=5
        nested = '{"a":' * 10 + '"deep"' + "}" * 10
        parser = GenericJsonParser(max_depth=5)
        rec = _record(nested)
        result = parser.parse(rec)
        # Should succeed with warnings (nesting limit)
        self.assertIn(result.status, [ParseStatus.PARSED, ParseStatus.PARTIAL])
        self.assertTrue(any(w.code.value == "NESTING_LIMIT_EXCEEDED" for w in result.warnings))

    def test_empty_object(self) -> None:
        rec = _record("{}")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(len(result.extracted_fields), 0)

    def test_parser_id(self) -> None:
        self.assertEqual(self.parser.metadata.parser_id, "parser.generic.json")

    def test_format_label(self) -> None:
        rec = _record('{"x": 1}')
        result = self.parser.parse(rec)
        self.assertEqual(result.format, "json")


class TestNdJsonParser(unittest.TestCase):
    def test_single_ndjson_line(self) -> None:
        parser = NdJsonParser()
        rec = _record('{"event": "flow", "bytes": 512}')
        result = parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.format, "ndjson")
        self.assertIn("event", result.extracted_fields)

    def test_parser_id(self) -> None:
        parser = NdJsonParser()
        self.assertEqual(parser.metadata.parser_id, "parser.generic.ndjson")


# ---------------------------------------------------------------------------
# CSV Parser
# ---------------------------------------------------------------------------


class TestGenericCsvParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = GenericCsvParser()

    def test_single_row_with_header(self) -> None:
        text = "src_ip,dst_port,action\n10.0.0.1,443,allow"
        rec = _record(text)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("src_ip", result.extracted_fields)
        self.assertEqual(result.extracted_fields["src_ip"].value, "10.0.0.1")
        self.assertEqual(result.extracted_fields["dst_port"].value, "443")

    def test_tab_delimited(self) -> None:
        text = "user\taction\tresult\nadmin\tlogin\tsuccess"
        rec = _record(text)
        result = GenericCsvParser().parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("user", result.extracted_fields)

    def test_pipe_delimited(self) -> None:
        text = "host|service|status\nweb01|nginx|running"
        rec = _record(text)
        result = GenericCsvParser(delimiter="|").parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("host", result.extracted_fields)

    def test_multi_row_returns_rows_list(self) -> None:
        text = "a,b\n1,2\n3,4\n5,6"
        rec = _record(text)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("rows", result.unmapped_fields)
        self.assertEqual(len(result.unmapped_fields["rows"]), 3)

    def test_header_sanitization(self) -> None:
        text = "Src IP,Dst Port\n10.0.0.1,443"
        rec = _record(text)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        # Special chars → underscores, lowercased
        self.assertIn("src_ip", result.extracted_fields)
        self.assertIn("dst_port", result.extracted_fields)

    def test_no_header_mode(self) -> None:
        text = "10.0.0.1,443"
        rec = _record(text)
        result = GenericCsvParser(has_header=False).parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("col_0", result.extracted_fields)
        self.assertIn("col_1", result.extracted_fields)

    def test_parser_id(self) -> None:
        self.assertEqual(self.parser.metadata.parser_id, "parser.generic.csv")


# ---------------------------------------------------------------------------
# Key-Value Parser
# ---------------------------------------------------------------------------


class TestKeyValueParser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = KeyValueParser()

    def test_bare_kv_pairs(self) -> None:
        rec = _record("action=allow src=192.168.1.1 dst=8.8.8.8 dport=443")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["action"].value, "allow")
        self.assertEqual(result.extracted_fields["src"].value, "192.168.1.1")
        self.assertEqual(result.extracted_fields["dport"].value, "443")

    def test_double_quoted_value(self) -> None:
        rec = _record('type="traffic" bytes=1024 msg="Login failed"')
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["type"].value, "traffic")
        self.assertEqual(result.extracted_fields["msg"].value, "Login failed")

    def test_message_prefix_extraction(self) -> None:
        rec = _record("ALERT: action=block src=10.0.0.1")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("msg_prefix", result.extracted_fields)
        self.assertIn("ALERT:", result.extracted_fields["msg_prefix"].value)

    def test_duplicate_key_handling(self) -> None:
        rec = _record("tag=a tag=b tag=c")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        # First tag is 'tag', duplicates are 'tag__1', 'tag__2'
        self.assertIn("tag", result.extracted_fields)
        self.assertIn("tag__1", result.extracted_fields)

    def test_no_kv_returns_partial(self) -> None:
        rec = _record("this is plain text with no key=value pairs... wait=actually")
        result = self.parser.parse(rec)
        # "wait=actually" is a valid kv pair
        self.assertEqual(result.status, ParseStatus.PARSED)

    def test_empty_record_returns_partial(self) -> None:
        rec = _record("no pairs here at all")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARTIAL)

    def test_raw_locator_format(self) -> None:
        rec = _record("action=deny")
        result = self.parser.parse(rec)
        field = result.extracted_fields["action"]
        self.assertEqual(field.raw_locator, "kv:action")

    def test_parser_id(self) -> None:
        self.assertEqual(self.parser.metadata.parser_id, "parser.generic.keyvalue")


# ---------------------------------------------------------------------------
# Syslog RFC 3164 Parser
# ---------------------------------------------------------------------------


class TestSyslogRFC3164Parser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = SyslogRFC3164Parser()

    def test_standard_message_with_pri(self) -> None:
        rec = _record(
            "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8"
        )
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("pri", result.extracted_fields)
        self.assertEqual(result.extracted_fields["pri"].value, 34)
        self.assertIn("hostname", result.extracted_fields)
        self.assertEqual(result.extracted_fields["hostname"].value, "mymachine")
        self.assertIn("app_name", result.extracted_fields)
        self.assertEqual(result.extracted_fields["app_name"].value, "su")
        self.assertIn("timestamp", result.extracted_fields)
        self.assertIn("facility", result.extracted_fields)
        self.assertIn("severity", result.extracted_fields)

    def test_pri_facility_severity_decomposition(self) -> None:
        # PRI=165 → facility=20, severity=5
        rec = _record("<165>Oct 11 22:14:15 host kern: test msg")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["facility"].value, 20)
        self.assertEqual(result.extracted_fields["severity"].value, 5)

    def test_message_with_pid(self) -> None:
        rec = _record("<13>Jan  1 00:00:00 localhost sshd[1234]: Connection from 10.0.0.1")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("process_id", result.extracted_fields)
        self.assertEqual(result.extracted_fields["process_id"].value, "1234")

    def test_malformed_returns_partial(self) -> None:
        rec = _record("this is not a syslog message at all")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARTIAL)
        self.assertTrue(len(result.errors) > 0)

    def test_parser_id(self) -> None:
        self.assertEqual(self.parser.metadata.parser_id, "parser.syslog.rfc3164")

    def test_format_label(self) -> None:
        rec = _record("<34>Oct 11 22:14:15 host app: msg")
        result = self.parser.parse(rec)
        self.assertEqual(result.format, "syslog_rfc3164")


# ---------------------------------------------------------------------------
# Syslog RFC 5424 Parser
# ---------------------------------------------------------------------------


class TestSyslogRFC5424Parser(unittest.TestCase):
    def setUp(self) -> None:
        self.parser = SyslogRFC5424Parser()

    def test_standard_5424_message(self) -> None:
        raw = (
            "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com "
            "su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8"
        )
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("pri", result.extracted_fields)
        self.assertEqual(result.extracted_fields["pri"].value, 34)
        self.assertIn("hostname", result.extracted_fields)
        self.assertIn("app_name", result.extracted_fields)
        self.assertEqual(result.extracted_fields["app_name"].value, "su")
        self.assertIn("message_id", result.extracted_fields)
        self.assertEqual(result.extracted_fields["message_id"].value, "ID47")

    def test_structured_data_extraction(self) -> None:
        raw = (
            "<165>1 2003-08-24T05:14:15.000003-07:00 192.0.2.1 myproc 8710 - "
            '[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] '
            "An application event log entry"
        )
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("structured_data", result.extracted_fields)
        sd = result.extracted_fields["structured_data"].value
        # Verify SD element and params
        self.assertIn("exampleSDID@32473", sd)
        self.assertEqual(sd["exampleSDID@32473"]["iut"], "3")
        self.assertEqual(sd["exampleSDID@32473"]["eventSource"], "Application")

    def test_nil_fields_excluded(self) -> None:
        raw = "<34>1 - - - - - -"
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        # NIL fields ("-") should NOT be in extracted_fields
        self.assertNotIn("hostname", result.extracted_fields)
        self.assertNotIn("app_name", result.extracted_fields)
        self.assertNotIn("timestamp", result.extracted_fields)

    def test_pri_facility_severity_decomposition(self) -> None:
        # PRI=165 → facility=20, severity=5
        raw = "<165>1 2003-08-24T05:14:15Z host app 123 - -"
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.extracted_fields["facility"].value, 20)
        self.assertEqual(result.extracted_fields["severity"].value, 5)

    def test_malformed_returns_partial(self) -> None:
        rec = _record("not a 5424 message at all")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARTIAL)

    def test_parser_id(self) -> None:
        self.assertEqual(self.parser.metadata.parser_id, "parser.syslog.rfc5424")

    def test_format_label(self) -> None:
        raw = "<34>1 2003-10-11T22:14:15Z host su - ID47 - msg"
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.format, "syslog_rfc5424")


# ---------------------------------------------------------------------------
# CEF Parser
# ---------------------------------------------------------------------------


class TestCefParser(unittest.TestCase):
    def setUp(self) -> None:
        from ulpf_parser_runtime.parsers.cef_parser import CefParser

        self.parser = CefParser()

    def test_standard_cef(self) -> None:
        raw = "CEF:0|Security|threatmanager|1.0|100|worm successfully stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232"
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["cef_version"].value, "0")
        self.assertEqual(result.extracted_fields["device_vendor"].value, "Security")
        self.assertEqual(result.extracted_fields["device_product"].value, "threatmanager")
        self.assertEqual(result.extracted_fields["name"].value, "worm successfully stopped")
        self.assertEqual(result.extracted_fields["severity"].value, "10")
        self.assertEqual(result.extracted_fields["src"].value, "10.0.0.1")
        self.assertEqual(result.extracted_fields["dst"].value, "2.1.2.2")
        self.assertEqual(result.extracted_fields["spt"].value, "1232")

    def test_cef_with_syslog_prefix(self) -> None:
        raw = "Oct 12 04:16:11 myhost CEF:0|Check Point|VPN-1 & FireWall-1|Check Point|drop|Drop|Low|act=drop"
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("syslog_prefix", result.extracted_fields)
        self.assertEqual(result.extracted_fields["device_vendor"].value, "Check Point")
        self.assertEqual(result.extracted_fields["act"].value, "drop")

    def test_malformed_cef(self) -> None:
        rec = _record("not a cef message")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.FAILED)


# ---------------------------------------------------------------------------
# LEEF Parser
# ---------------------------------------------------------------------------


class TestLeefParser(unittest.TestCase):
    def setUp(self) -> None:
        from ulpf_parser_runtime.parsers.leef_parser import LeefParser

        self.parser = LeefParser()

    def test_leef_1_0(self) -> None:
        raw = "LEEF:1.0|Microsoft|MSExchange|2013|AuthSuccess|src=192.168.1.1\tdst=10.0.0.2\tusr=admin"
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["leef_version"].value, "1.0")
        self.assertEqual(result.extracted_fields["vendor"].value, "Microsoft")
        self.assertEqual(result.extracted_fields["product"].value, "MSExchange")
        self.assertEqual(result.extracted_fields["event_id"].value, "AuthSuccess")
        self.assertEqual(result.extracted_fields["src"].value, "192.168.1.1")
        self.assertEqual(result.extracted_fields["usr"].value, "admin")

    def test_leef_2_0_custom_delim(self) -> None:
        raw = "LEEF:2.0|Vendor|Product|1.0|1234|^|src=1.1.1.1^dst=2.2.2.2"
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertEqual(result.extracted_fields["src"].value, "1.1.1.1")
        self.assertEqual(result.extracted_fields["dst"].value, "2.2.2.2")


# ---------------------------------------------------------------------------
# XML Parser
# ---------------------------------------------------------------------------


class TestXmlParser(unittest.TestCase):
    def setUp(self) -> None:
        from ulpf_parser_runtime.parsers.xml_parser import XmlParser

        self.parser = XmlParser()

    def test_valid_xml(self) -> None:
        raw = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><EventID>4624</EventID><Channel>Security</Channel></System></Event>"
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.PARSED)
        self.assertIn("Event.System.EventID", result.extracted_fields)
        self.assertEqual(result.extracted_fields["Event.System.EventID"].value, "4624")

    def test_xxe_rejection(self) -> None:
        raw = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
        rec = _record(raw)
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.FAILED)
        self.assertTrue(any(e.code.value == "SECURITY_POLICY_VIOLATION" for e in result.errors))

    def test_malformed_xml(self) -> None:
        rec = _record("<broken><tag>")
        result = self.parser.parse(rec)
        self.assertEqual(result.status, ParseStatus.FAILED)


# ---------------------------------------------------------------------------
# W3C Parser
# ---------------------------------------------------------------------------


class TestW3CParser(unittest.TestCase):
    def setUp(self) -> None:
        from ulpf_parser_runtime.parsers.w3c_parser import W3CParser

        self.parser = W3CParser()

    def test_directive_and_data_row(self) -> None:
        fields_dir = _record("#Fields: date time c-ip cs-method cs-uri-stem sc-status")
        dir_res = self.parser.parse(fields_dir)
        self.assertEqual(dir_res.status, ParseStatus.PARSED)
        self.assertEqual(dir_res.extracted_fields["directive"].value, "Fields")

        data_row = _record("2023-01-01 12:00:00 192.168.1.5 GET /index.html 200")
        row_res = self.parser.parse(data_row)
        self.assertEqual(row_res.status, ParseStatus.PARSED)
        self.assertEqual(row_res.extracted_fields["c_ip"].value, "192.168.1.5")
        self.assertEqual(row_res.extracted_fields["cs_method"].value, "GET")
        self.assertEqual(row_res.extracted_fields["sc_status"].value, "200")


# ---------------------------------------------------------------------------
# Default Registry Factory
# ---------------------------------------------------------------------------


class TestDefaultRegistry(unittest.TestCase):
    def test_create_default_registry(self) -> None:
        from ulpf_parser_runtime.registry import create_default_registry

        reg = create_default_registry()
        parsers = reg.list_parsers()
        self.assertGreaterEqual(len(parsers), 10)
        desc = reg.self_description()
        self.assertIn("cef", desc["supported_formats"])
        self.assertIn("xml", desc["supported_formats"])
        self.assertIn("w3c", desc["supported_formats"])
        self.assertIn("leef", desc["supported_formats"])


if __name__ == "__main__":
    unittest.main()
