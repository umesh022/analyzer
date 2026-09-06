"""
Log Parser Module
Parses raw 3GPP protocol logs and extracts structured events and failure points.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from datetime import datetime


# ──────────────────────────────────────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class LogEvent:
    """Represents a single parsed log event."""
    line_number: int
    timestamp: Optional[str]
    layer: str          # e.g. RRC, NAS, MAC, RLC, PDCP, NGAP, S1AP
    message: str
    raw_line: str
    severity: str = "INFO"   # INFO | WARNING | ERROR | CRITICAL


@dataclass
class FailurePoint:
    """A detected failure point with specification reference."""
    line_number: int
    timestamp: Optional[str]
    layer: str
    failure_type: str
    cause: Optional[str]
    spec_reference: str
    description: str
    raw_line: str
    severity: str = "ERROR"


@dataclass
class ParseResult:
    """Full result of parsing a log file/text."""
    total_lines: int
    events: List[LogEvent] = field(default_factory=list)
    failures: List[FailurePoint] = field(default_factory=list)
    layers_found: List[str] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# Failure Signatures
# Each entry: (regex_pattern, layer, failure_type, spec_ref, description_template)
# ──────────────────────────────────────────────────────────────────────────────

FAILURE_SIGNATURES = [
    # ── RRC ──────────────────────────────────────────────────────────────────
    (r"RRC.*Setup.*Fail|RRCSetupFailure|rrcSetupFailure",
     "RRC", "RRC Setup Failure",
     "TS 38.331 Sec 5.3.3",
     "UE failed to complete RRC connection setup. Possible causes: gNB overload, T300 expiry."),

    (r"RRC.*Reject|RRCReject|rrcReject",
     "RRC", "RRC Rejection",
     "TS 38.331 Sec 5.3.3",
     "gNB rejected RRC setup. Check congestion and waitTime in RRCReject message."),

    (r"RRC.*Reestablish.*Fail|RRCReestablishmentReject|reestablishmentReject",
     "RRC", "RRC Re-establishment Failure",
     "TS 38.331 Sec 5.3.7",
     "RRC re-establishment rejected. Causes: context not found at target cell, shortMAC-I mismatch, T311 expiry."),

    (r"radioLinkFailure|radio.link.fail|RLF|rlf_detected",
     "RRC", "Radio Link Failure",
     "TS 38.331 Sec 5.3.10",
     "Radio link failure declared. Physical layer quality dropped below threshold. Check T310/N310/N311 configuration."),

    (r"[Tt]304.*expir|t304.Expiry|T304_EXPIRY",
     "RRC", "T304 Expiry",
     "TS 38.331 Sec 5.3.5",
     "Handover execution timer T304 expired. UE could not sync to target cell. Check target cell availability."),

    (r"[Tt]310.*expir|t310.Expiry|T310_EXPIRY",
     "RRC", "T310 Expiry",
     "TS 38.331 Sec 5.3.10",
     "RLF timer T310 expired after N310 out-of-sync indications. Radio quality severely degraded."),

    (r"[Tt]300.*expir|t300.Expiry|T300_EXPIRY",
     "RRC", "T300 Expiry",
     "TS 38.331 Sec 5.3.3",
     "T300 expired - no RRCSetup response from gNB within timeout."),

    (r"[Tt]301.*expir|t301.Expiry|T301_EXPIRY",
     "RRC", "T301 Expiry",
     "TS 38.331 Sec 5.3.7",
     "T301 expired - no RRCReestablishment response received."),

    (r"handover.*fail|HO.FAIL|HOFailure|handoverFailure",
     "RRC", "Handover Failure",
     "TS 38.331 / TS 38.413",
     "Handover procedure failed. Check preparation failure cause, T304 timer, target cell config."),

    (r"MeasurementReport.*missing|measurement.*timeout|no.*MeasReport",
     "RRC", "Measurement Report Issue",
     "TS 38.331 Sec 5.5.5",
     "MeasurementReport not received or delayed. Check A3/A5 event thresholds and TTT configuration."),

    (r"reconfiguration.*fail|RRCReconfigurationFailure",
     "RRC", "RRC Reconfiguration Failure",
     "TS 38.331 Sec 5.3.5",
     "UE rejected or failed RRC Reconfiguration. Check UE capabilities and configuration parameters."),

    # ── NAS ──────────────────────────────────────────────────────────────────
    (r"Registration.Reject|RegistrationReject|Attach.Reject|AttachReject",
     "NAS", "Registration/Attach Reject",
     "TS 24.501 Sec 5.5.1 / TS 24.301",
     "NAS registration rejected by network. Check cause code for specific reason."),

    (r"[Aa]uth.*[Ff]ail|Authentication.Fail|MAC.failure|synch.failure",
     "NAS", "Authentication Failure",
     "TS 24.501 Sec 5.4.1",
     "NAS authentication failed. Check USIM credentials, AMF/AUSF key synchronization, SQN counter."),

    (r"Security.Mode.*Reject|SecurityModeReject",
     "NAS", "Security Mode Command Failure",
     "TS 24.501 Sec 5.4.2",
     "Security mode command rejected by UE. Check NAS integrity algorithm and key derivation at AMF."),

    (r"PDU.Session.*Fail|PDUSessionFail|PDU.Establishment.*Fail",
     "NAS", "PDU Session Failure",
     "TS 24.501 Sec 6.4.1",
     "PDU session establishment failed. Check DNN configuration, SMF availability, and cause code."),

    (r"Deregistration|DeregRequest|cause.*#22|cause.*congestion",
     "NAS", "NAS Deregistration / Congestion",
     "TS 24.501 Sec 5.5.2",
     "UE deregistered or congestion cause received. T3346 timer may be active."),

    (r"cause.*#11|cause.*PLMN.not.allow|plmn.not.allowed",
     "NAS", "PLMN Not Allowed",
     "TS 24.501 Sec 5.5.1",
     "PLMN not allowed for this UE. Check SIM provisioning and PLMN configuration."),

    (r"cause.*#27|unknown.*DNN|DNN.*not.found|APN.*unknown",
     "NAS", "Unknown DNN/APN",
     "TS 24.501 Sec 6.4.1",
     "DNN (Data Network Name) not found or misconfigured. Check SMF/PGW DNN profiles."),

    # ── NGAP ─────────────────────────────────────────────────────────────────
    (r"NGAP.*HandoverPrep.*Fail|HandoverPreparationFailure",
     "NGAP", "Handover Preparation Failure",
     "TS 38.413 Sec 8.4",
     "NGAP handover preparation failed at target AMF/gNB. Check target cell admission and resources."),

    (r"NGAP.*InitialContext.*Fail|InitialContextSetupFailure",
     "NGAP", "Initial Context Setup Failure",
     "TS 38.413 Sec 8.3",
     "Initial UE context setup failed over NG interface. Check AMF-gNB connectivity and NAS message."),

    (r"NGAP.*PDUSession.*Fail|PDUSessionResourceSetupFail",
     "NGAP", "PDU Session Resource Setup Failure",
     "TS 38.413 Sec 8.2",
     "PDU session resource could not be set up at gNB. Check QoS parameters and radio resource availability."),

    (r"UEContextRelease.*radio.*connection.*lost|ue.context.release.*rlf",
     "NGAP", "UE Context Release - RLF",
     "TS 38.413 Sec 8.3",
     "AMF triggered UE context release due to radio link failure. Correlated with RRC RLF event."),

    # ── S1AP ─────────────────────────────────────────────────────────────────
    (r"S1AP.*Setup.*Fail|S1SetupFailure",
     "S1AP", "S1 Setup Failure",
     "TS 36.413 Sec 8.7.3",
     "S1 interface setup between eNB and MME failed. Check transport connectivity and configuration."),

    (r"S1AP.*Handover.*Fail|S1AP.*HO.*Fail",
     "S1AP", "S1AP Handover Failure",
     "TS 36.413 Sec 8.4",
     "S1-based handover failed. Check tS1relocOverall timer and MME availability."),

    (r"E-RAB.*Setup.*Fail|ERABSetupFail|erab.*fail",
     "S1AP", "E-RAB Setup Failure",
     "TS 36.413 Sec 8.2",
     "E-RAB (LTE bearer) setup failed. Check radio resources and QoS configuration."),

    # ── MAC ──────────────────────────────────────────────────────────────────
    (r"RACH.*fail|rach.failure|preamble.*max|preambleTransMax",
     "MAC", "RACH Failure",
     "TS 38.321 Sec 5.1",
     "Random access procedure failed. Preamble transmission limit reached. Check PRACH coverage and configuration."),

    (r"HARQ.*max.*retx|harq.*fail|max.*retransmission.*reached",
     "MAC", "HARQ Max Retransmissions",
     "TS 38.321 Sec 5.4",
     "HARQ maximum retransmissions exhausted. Transport block discarded. Poor radio conditions."),

    (r"no.*DL.*grant|scheduling.*fail|DL.grant.*missing",
     "MAC", "Scheduling Failure",
     "TS 38.321 Sec 5.4",
     "No downlink grant received for extended period. Check gNB scheduler and PDCCH coverage."),

    # ── RLC ──────────────────────────────────────────────────────────────────
    (r"maxRetxThreshold|rlc.*max.*retx|RLC.*fail",
     "RLC", "RLC Max Retransmission",
     "TS 38.322 Sec 5.3",
     "RLC AM mode maxRetxThreshold reached. Radio link failure will be declared. Check physical layer quality."),

    (r"t-Reordering.*expir|tReordering.*expir|RLC.*reorder.*timeout",
     "RLC", "RLC Reordering Timeout",
     "TS 38.322 Sec 5.2",
     "RLC t-Reordering timer expired. PDUs received out of order beyond window. Check radio conditions."),

    (r"RLC.*SDU.*discard|rlc.*sdu.*drop",
     "RLC", "RLC SDU Discarded",
     "TS 38.322 Sec 5.3",
     "RLC SDU discarded due to timer expiry or buffer overflow."),

    # ── PDCP ─────────────────────────────────────────────────────────────────
    (r"PDCP.*integrity.*fail|integrity.*verif.*fail|MAC.I.*mismatch",
     "PDCP", "PDCP Integrity Failure",
     "TS 38.323 Sec 5.9",
     "PDCP integrity verification failed. Security key mismatch, possibly after handover. Check key derivation."),

    (r"PDCP.*cipher.*fail|PDCP.*decipher.*error|ciphering.*fail",
     "PDCP", "PDCP Ciphering Error",
     "TS 38.323 Sec 5.8",
     "PDCP ciphering/deciphering error. Algorithm or key mismatch between UE and gNB."),

    (r"discardTimer.*expir|PDCP.*discard.*timer",
     "PDCP", "PDCP Discard Timer Expiry",
     "TS 38.323 Sec 5.2",
     "PDCP discard timer expired before packet transmission. Application-level delay likely."),

    # ── GTP / Core ────────────────────────────────────────────────────────────
    (r"GTP.*Context.*Not.*Found|gtp.*cause.*73|tunnel.*not.*found",
     "GTP", "GTP Context Not Found",
     "TS 29.281",
     "GTP tunnel context not found. F-TEID mismatch between UPF and gNB. Possible handover issue."),

    (r"UPF.*fail|upf.*down|N3.*interface.*down|N9.*interface.*down",
     "GTP", "UPF Interface Failure",
     "TS 23.501 / TS 29.244",
     "UPF interface failure detected. Check N3 (gNB-UPF) or N9 (UPF-UPF) connectivity."),
]


# ──────────────────────────────────────────────────────────────────────────────
# Timestamp & Layer Patterns
# ──────────────────────────────────────────────────────────────────────────────

TIMESTAMP_PATTERNS = [
    r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?",
    r"\d{2}/\d{2}/\d{4}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?",
    r"\d{2}:\d{2}:\d{2}(?:\.\d{3,6})?",
    r"\[\d+\.\d+\]",
]

LAYER_KEYWORDS = {
    "RRC": ["RRC", "rrc", "RRCSetup", "RRCReject", "RRCReestablish", "rrcConnection"],
    "NAS": ["NAS", "nas", "EMM", "ESM", "5GMM", "5GSM", "Registration", "Attach", "Detach", "PDU Session"],
    "MAC": ["MAC", "mac", "RACH", "HARQ", "BSR", "SR ", "PDCCH", "preamble"],
    "RLC": ["RLC", "rlc", "AM mode", "UM mode", "t-Reordering", "maxRetx"],
    "PDCP": ["PDCP", "pdcp", "integrity", "cipher", "ROHC", "discardTimer"],
    "NGAP": ["NGAP", "ngap", "NG-AP", "AMF", "HandoverRequired", "HandoverCommand"],
    "S1AP": ["S1AP", "s1ap", "S1-AP", "MME", "E-RAB", "erab"],
    "GTP": ["GTP", "gtp", "TEID", "F-TEID", "UPF", "SGW", "PGW", "N3", "N9"],
    "DIAMETER": ["Diameter", "diameter", "AVP", "HSS", "AAA"],
    "X2AP": ["X2AP", "x2ap", "X2-AP"],
    "XNAP": ["XnAP", "xnap", "Xn-AP"],
}


# ──────────────────────────────────────────────────────────────────────────────
# Parser
# ──────────────────────────────────────────────────────────────────────────────

class LogParser:
    """Parses 3GPP protocol logs and detects failure points."""

    def __init__(self):
        self._ts_patterns = [re.compile(p) for p in TIMESTAMP_PATTERNS]
        self._layer_patterns = {layer: [kw for kw in kws]
                                for layer, kws in LAYER_KEYWORDS.items()}
        self._failure_sigs = [(re.compile(pat, re.IGNORECASE), layer, ftype, spec, desc)
                              for pat, layer, ftype, spec, desc in FAILURE_SIGNATURES]

    def _extract_timestamp(self, line: str) -> Optional[str]:
        for pattern in self._ts_patterns:
            m = pattern.search(line)
            if m:
                return m.group(0)
        return None

    def _detect_layer(self, line: str) -> str:
        for layer, keywords in self._layer_patterns.items():
            for kw in keywords:
                if kw in line:
                    return layer
        return "UNKNOWN"

    def _detect_severity(self, line: str) -> str:
        upper = line.upper()
        if any(w in upper for w in ["CRITICAL", "FATAL", "EMERGENCY"]):
            return "CRITICAL"
        if any(w in upper for w in ["ERROR", "FAIL", "FAILURE", "REJECT", "ABORT"]):
            return "ERROR"
        if any(w in upper for w in ["WARN", "WARNING", "TIMEOUT", "EXPIRED", "RETRY"]):
            return "WARNING"
        return "INFO"

    def _extract_cause(self, line: str) -> Optional[str]:
        """Try to extract a cause value from the log line."""
        patterns = [
            r"cause\s*[=:]\s*([^\s,\]]+)",
            r"cause\s*=\s*#(\d+)",
            r"\bcause\b.*?([a-zA-Z0-9_\-]+(?:Expiry|Failure|Reject|Error))",
        ]
        for pat in patterns:
            m = re.search(pat, line, re.IGNORECASE)
            if m:
                return m.group(1)
        return None

    def parse(self, log_text: str) -> ParseResult:
        """Parse raw log text and return structured ParseResult."""
        lines = log_text.splitlines()
        result = ParseResult(total_lines=len(lines))
        layers_seen: set = set()

        for i, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()
            if not line:
                continue

            ts = self._extract_timestamp(line)
            layer = self._detect_layer(line)
            severity = self._detect_severity(line)

            if layer != "UNKNOWN":
                layers_seen.add(layer)

            event = LogEvent(
                line_number=i,
                timestamp=ts,
                layer=layer,
                message=line[:200],
                raw_line=raw_line,
                severity=severity,
            )
            result.events.append(event)

            # Check against failure signatures
            for compiled_re, sig_layer, ftype, spec, desc in self._failure_sigs:
                if compiled_re.search(line):
                    cause = self._extract_cause(line)
                    fp = FailurePoint(
                        line_number=i,
                        timestamp=ts,
                        layer=sig_layer,
                        failure_type=ftype,
                        cause=cause,
                        spec_reference=spec,
                        description=desc,
                        raw_line=raw_line,
                        severity="CRITICAL" if severity == "ERROR" else severity,
                    )
                    result.failures.append(fp)
                    layers_seen.add(sig_layer)
                    break  # one failure per line max

        result.layers_found = sorted(layers_seen)

        # Build summary
        result.summary = self._build_summary(result)
        return result

    def _build_summary(self, result: ParseResult) -> Dict:
        failure_counts: Dict[str, int] = {}
        layer_counts: Dict[str, int] = {}
        for fp in result.failures:
            failure_counts[fp.failure_type] = failure_counts.get(fp.failure_type, 0) + 1
            layer_counts[fp.layer] = layer_counts.get(fp.layer, 0) + 1

        return {
            "total_lines": result.total_lines,
            "total_events": len(result.events),
            "total_failures": len(result.failures),
            "failure_types": failure_counts,
            "failures_by_layer": layer_counts,
            "layers_found": result.layers_found,
            "most_critical_layer": max(layer_counts, key=layer_counts.get) if layer_counts else None,
        }


# Module-level singleton
_parser = LogParser()


def parse_logs(log_text: str) -> ParseResult:
    """Parse logs using the shared parser instance."""
    return _parser.parse(log_text)


def failures_to_dict(result: ParseResult) -> List[Dict]:
    """Convert FailurePoint objects to plain dicts for JSON serialization."""
    return [
        {
            "line_number": fp.line_number,
            "timestamp": fp.timestamp,
            "layer": fp.layer,
            "failure_type": fp.failure_type,
            "cause": fp.cause,
            "spec_reference": fp.spec_reference,
            "description": fp.description,
            "raw_line": fp.raw_line,
            "severity": fp.severity,
        }
        for fp in result.failures
    ]
