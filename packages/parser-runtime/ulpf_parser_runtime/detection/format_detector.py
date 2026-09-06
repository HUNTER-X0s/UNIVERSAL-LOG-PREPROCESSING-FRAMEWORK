"""Deterministic scored format detection engine for ULPF Phase 3.

Adheres to:
- Spec §8: Format Detection Engine (scored detection, not first regex wins)
- Spec §9: Format Detector Safety (bounded samples, ReDoS safety, no arbitrary execution)
- Spec §46: Parser Priority / Ambiguity (explainable scoring, ambiguity detection)
"""

import csv
import io
import json
import re
from typing import Any

from ulpf_parser_runtime.models import DetectedFormat

# Precompiled bounded regexes for format detection
RE_CEF = re.compile(r"^CEF:\s*(\d+)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$")
RE_LEEF = re.compile(r"^LEEF:\s*(\d+(?:\.\d+)?)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|(.*)$")
RE_SYSLOG_5424 = re.compile(
    r"^<(\d{1,3})>1\s+(\d{4}-\d{2}-\d{2}T[^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s+([^\s]+)\s*(.*)$"
)
RE_SYSLOG_3164 = re.compile(
    r"^<(\d{1,3})>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+(.*)$"
)
RE_SYSLOG_BSD_NOTAG = re.compile(r"^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+([^\s]+)\s+(.*)$")
RE_CRI = re.compile(r"^\d{4}-\d{2}-\d{2}T[^\s]+\s+(stdout|stderr)\s+([FP])\s+(.*)$")
RE_CLF = re.compile(
    r'^[^\s]+\s+[^\s]+\s+[^\s]+\s+\[\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+\-]\d{4}\]\s+"[A-Z]+\s+[^"]+"\s+\d{3}\s+'
)
RE_SNORT_FAST = re.compile(r"^\[\*\*\]\s+\[\d+:\d+:\d+\]\s+.*?\s+\[\*\*\]")
RE_KV_PAIR = re.compile(r'\b([a-zA-Z0-9_\.\-]+)=(?:"([^"]*)"|([^\s,;]+))')
RE_XML_PROLOG = re.compile(r"^\s*<\?xml\b", re.IGNORECASE)
RE_XML_TAG = re.compile(r"^\s*<([a-zA-Z0-9_:\.\-]+)[\s>].*</\1>\s*$", re.DOTALL)


class FormatDetector:
    """Scored format detector evaluating multiple format hypotheses concurrently."""

    def __init__(self, sample_byte_limit: int = 65_536) -> None:
        self.sample_byte_limit = sample_byte_limit

    def detect(self, text: str) -> tuple[DetectedFormat, tuple[DetectedFormat, ...], bool]:
        """Detect format with ranked candidates.

        Returns (best_format, all_candidates, is_ambiguous).
        """
        sample = text[: self.sample_byte_limit].strip()
        if not sample:
            unknown = DetectedFormat(
                format_name="unknown",
                score=0.0,
                confidence=0.0,
                evidence=("empty_sample",),
            )
            return unknown, (unknown,), False

        candidates: list[DetectedFormat] = []

        # 1. ArcSight CEF
        cef_score, cef_ev, cef_det = self._detect_cef(sample)
        if cef_score > 0.0:
            candidates.append(DetectedFormat("cef", cef_score, cef_score, tuple(cef_ev), cef_det))

        # 2. IBM LEEF
        leef_score, leef_ev, leef_det = self._detect_leef(sample)
        if leef_score > 0.0:
            candidates.append(
                DetectedFormat("leef", leef_score, leef_score, tuple(leef_ev), leef_det)
            )

        # 3. JSON / NDJSON
        json_score, json_ev, json_det, is_ndjson = self._detect_json(sample)
        if json_score > 0.0:
            fmt_name = "ndjson" if is_ndjson else "json"
            candidates.append(
                DetectedFormat(fmt_name, json_score, json_score, tuple(json_ev), json_det)
            )

        # 4. XML
        xml_score, xml_ev, xml_det = self._detect_xml(sample)
        if xml_score > 0.0:
            candidates.append(DetectedFormat("xml", xml_score, xml_score, tuple(xml_ev), xml_det))

        # 5. Syslog RFC 5424
        s5424_score, s5424_ev, s5424_det = self._detect_syslog_5424(sample)
        if s5424_score > 0.0:
            candidates.append(
                DetectedFormat(
                    "syslog_rfc5424",
                    s5424_score,
                    s5424_score,
                    tuple(s5424_ev),
                    s5424_det,
                )
            )

        # 6. Syslog RFC 3164 / BSD
        s3164_score, s3164_ev, s3164_det = self._detect_syslog_3164(sample)
        if s3164_score > 0.0:
            candidates.append(
                DetectedFormat(
                    "syslog_rfc3164",
                    s3164_score,
                    s3164_score,
                    tuple(s3164_ev),
                    s3164_det,
                )
            )

        # 7. W3C Extended Log
        w3c_score, w3c_ev, w3c_det = self._detect_w3c(sample)
        if w3c_score > 0.0:
            candidates.append(DetectedFormat("w3c", w3c_score, w3c_score, tuple(w3c_ev), w3c_det))

        # 8. CRI Container Log
        cri_score, cri_ev, cri_det = self._detect_cri(sample)
        if cri_score > 0.0:
            candidates.append(DetectedFormat("cri", cri_score, cri_score, tuple(cri_ev), cri_det))

        # 9. Common / Combined Web Log
        clf_score, clf_ev, clf_det = self._detect_clf(sample)
        if clf_score > 0.0:
            candidates.append(DetectedFormat("clf", clf_score, clf_score, tuple(clf_ev), clf_det))

        # 10. Key=Value (KV)
        kv_score, kv_ev, kv_det = self._detect_kv(sample)
        if kv_score > 0.0:
            candidates.append(DetectedFormat("kv", kv_score, kv_score, tuple(kv_ev), kv_det))

        # 11. CSV / TSV
        delim_fmt, delim_score, delim_ev, delim_det = self._detect_delimited(sample)
        if delim_score > 0.0:
            candidates.append(
                DetectedFormat(
                    delim_fmt,
                    delim_score,
                    delim_score,
                    tuple(delim_ev),
                    delim_det,
                )
            )

        # Sort candidates strictly by score descending, then by format name for determinism
        candidates.sort(key=lambda c: (-c.score, c.format_name))

        if not candidates:
            unknown = DetectedFormat(
                format_name="unknown",
                score=0.0,
                confidence=0.0,
                evidence=("no_matching_grammar",),
            )
            return unknown, (unknown,), False

        best = candidates[0]
        is_ambiguous = False
        if len(candidates) > 1:
            diff = best.score - candidates[1].score
            # If the two top candidates are within 0.05, mark ambiguous
            if diff <= 0.05 and candidates[1].score >= 0.5:
                is_ambiguous = True

        return best, tuple(candidates), is_ambiguous

    def _detect_cef(self, sample: str) -> tuple[float, list[str], dict[str, Any]]:
        first_line = sample.splitlines()[0].strip()
        match = RE_CEF.match(first_line)
        if match:
            version, vendor, product, dev_ver, event_id, name, severity, ext = match.groups()
            return (
                0.98,
                ["valid_cef_header", f"version:{version}", f"vendor:{vendor}"],
                {
                    "version": version,
                    "vendor": vendor,
                    "product": product,
                    "severity": severity,
                },
            )
        return 0.0, [], {}

    def _detect_leef(self, sample: str) -> tuple[float, list[str], dict[str, Any]]:
        first_line = sample.splitlines()[0].strip()
        match = RE_LEEF.match(first_line)
        if match:
            version, vendor, product, dev_ver, event_id, ext = match.groups()
            return (
                0.98,
                ["valid_leef_header", f"version:{version}", f"vendor:{vendor}"],
                {
                    "version": version,
                    "vendor": vendor,
                    "product": product,
                    "event_id": event_id,
                },
            )
        return 0.0, [], {}

    def _detect_json(self, sample: str) -> tuple[float, list[str], dict[str, Any], bool]:
        # Single JSON object
        if sample.startswith("{") and sample.endswith("}"):
            try:
                parsed = json.loads(sample)
                if isinstance(parsed, dict):
                    return (
                        0.97,
                        ["valid_json_object", f"keys:{len(parsed)}"],
                        {"keys": list(parsed.keys())[:10]},
                        False,
                    )
            except (json.JSONDecodeError, ValueError):
                pass

        # NDJSON check (first line and multiple lines)
        lines = [line.strip() for line in sample.splitlines() if line.strip()]
        if len(lines) >= 1 and lines[0].startswith("{") and lines[0].endswith("}"):
            valid_count = 0
            for line in lines[:5]:
                if line.startswith("{") and line.endswith("}"):
                    try:
                        if isinstance(json.loads(line), dict):
                            valid_count += 1
                    except (json.JSONDecodeError, ValueError):
                        break
            if valid_count == len(lines[:5]) and valid_count > 0:
                is_nd = len(lines) > 1
                return (
                    0.96,
                    [f"valid_ndjson_lines:{valid_count}"],
                    {"sample_lines": valid_count},
                    is_nd,
                )

        return 0.0, [], {}, False

    def _detect_xml(self, sample: str) -> tuple[float, list[str], dict[str, Any]]:
        if RE_XML_PROLOG.match(sample):
            return 0.97, ["xml_prolog_matched"], {"has_prolog": True}
        if sample.startswith("<") and sample.endswith(">"):
            match = RE_XML_TAG.match(sample)
            if match:
                root_tag = match.group(1)
                return 0.92, ["xml_balanced_root_tag", f"root:{root_tag}"], {"root_tag": root_tag}
        return 0.0, [], {}

    def _detect_syslog_5424(self, sample: str) -> tuple[float, list[str], dict[str, Any]]:
        first_line = sample.splitlines()[0].strip()
        match = RE_SYSLOG_5424.match(first_line)
        if match:
            pri, ts, host, app, procid, msgid, rest = match.groups()
            return (
                0.95,
                [
                    "rfc5424_header_matched",
                    f"pri:{pri}",
                    f"app:{app}",
                ],
                {
                    "pri": pri,
                    "timestamp": ts,
                    "hostname": host,
                    "app_name": app,
                    "procid": procid,
                    "msgid": msgid,
                },
            )
        return 0.0, [], {}

    def _detect_syslog_3164(self, sample: str) -> tuple[float, list[str], dict[str, Any]]:
        first_line = sample.splitlines()[0].strip()
        match_pri = RE_SYSLOG_3164.match(first_line)
        if match_pri:
            pri, ts, host, rest = match_pri.groups()
            return (
                0.91,
                [
                    "rfc3164_pri_header_matched",
                    f"pri:{pri}",
                    f"host:{host}",
                ],
                {
                    "pri": pri,
                    "timestamp": ts,
                    "hostname": host,
                },
            )
        match_bsd = RE_SYSLOG_BSD_NOTAG.match(first_line)
        if match_bsd:
            ts, host, rest = match_bsd.groups()
            return (
                0.75,
                ["bsd_timestamp_matched", f"host:{host}"],
                {
                    "timestamp": ts,
                    "hostname": host,
                },
            )
        return 0.0, [], {}

    def _detect_w3c(self, sample: str) -> tuple[float, list[str], dict[str, Any]]:
        lines = sample.splitlines()
        has_fields = any(line.startswith("#Fields:") for line in lines[:10])
        if has_fields:
            return 0.96, ["w3c_fields_directive_found"], {"has_fields_directive": True}
        has_w3c_header = any(
            line.startswith(("#Software:", "#Version:", "#Date:")) for line in lines[:5]
        )
        if has_w3c_header:
            return 0.85, ["w3c_metadata_directive_found"], {"has_metadata": True}
        return 0.0, [], {}

    def _detect_cri(self, sample: str) -> tuple[float, list[str], dict[str, Any]]:
        first_line = sample.splitlines()[0].strip()
        match = RE_CRI.match(first_line)
        if match:
            stream, tag, msg = match.groups()
            return (
                0.94,
                ["cri_format_matched", f"stream:{stream}", f"tag:{tag}"],
                {
                    "stream": stream,
                    "tag": tag,
                },
            )
        return 0.0, [], {}

    def _detect_clf(self, sample: str) -> tuple[float, list[str], dict[str, Any]]:
        first_line = sample.splitlines()[0].strip()
        if RE_CLF.match(first_line):
            return 0.93, ["common_log_format_matched"], {}
        return 0.0, [], {}

    def _detect_kv(self, sample: str) -> tuple[float, list[str], dict[str, Any]]:
        # Count key=value patterns in the first line
        first_line = sample.splitlines()[0].strip()
        matches = RE_KV_PAIR.findall(first_line)
        if len(matches) >= 3:
            # High count of key=value pairs
            score = min(0.85, 0.50 + len(matches) * 0.05)
            keys = [m[0] for m in matches[:10]]
            return score, [f"kv_pairs_found:{len(matches)}"], {"keys": keys}
        return 0.0, [], {}

    def _detect_delimited(self, sample: str) -> tuple[str, float, list[str], dict[str, Any]]:
        lines = [row_line for row_line in sample.splitlines() if row_line.strip()][:5]
        if not lines:
            return "csv", 0.0, [], {}

        # Check TSV
        tsv_counts = [row_line.count("\t") for row_line in lines]
        if tsv_counts[0] >= 2 and all(c == tsv_counts[0] for c in tsv_counts):
            return (
                "tsv",
                0.88,
                [f"consistent_tsv_columns:{tsv_counts[0] + 1}"],
                {
                    "delimiter": "\t",
                    "columns": tsv_counts[0] + 1,
                },
            )

        # Check CSV with sniffer
        if "," in lines[0]:
            try:
                dialect = csv.Sniffer().sniff("\n".join(lines), delimiters=",")
                if dialect.delimiter == ",":
                    reader = csv.reader(io.StringIO("\n".join(lines)), dialect)
                    col_counts = [len(row) for row in reader]
                    if col_counts and col_counts[0] >= 3 and len(set(col_counts)) == 1:
                        return (
                            "csv",
                            0.82,
                            [f"consistent_csv_columns:{col_counts[0]}"],
                            {
                                "delimiter": ",",
                                "columns": col_counts[0],
                            },
                        )
            except (csv.Error, ValueError):
                pass

        return "csv", 0.0, [], {}
