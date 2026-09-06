"""
PCAP / PCAPNG Parser for 3GPP Protocol Analysis
Uses dpkt to read binary packet captures and extract 3GPP-relevant
protocol fields (GTP-U, GTP-C, SCTP/S1AP, NGAP patterns, SIP, DNS, etc.)
converting them into the same line-based log format the log_parser understands.
"""

import io
import struct
import logging
import socket
from typing import List, Tuple, Optional

logger = logging.getLogger(__name__)

# ── PCAP magic numbers ────────────────────────────────────────────────────────
PCAP_MAGIC_LE   = 0xD4C3B2A1   # little-endian pcap
PCAP_MAGIC_BE   = 0xA1B2C3D4   # big-endian pcap
PCAPNG_MAGIC    = 0x0A0D0D0A   # pcapng section header block

# GTP port
GTP_C_PORT = 2123
GTP_U_PORT = 2152

# Known protocol ports for labelling
PORT_MAP = {
    2123: "GTP-C",
    2152: "GTP-U",
    36412: "S1AP/SCTP",
    38412: "NGAP/SCTP",
    5060:  "SIP",
    53:    "DNS",
    443:   "HTTPS",
    80:    "HTTP",
    22:    "SSH",
}

# GTP message type codes → human label
GTP_MSG_TYPES = {
    1:   "Echo Request",
    2:   "Echo Response",
    16:  "Create PDP Context Req",
    17:  "Create PDP Context Resp",
    18:  "Update PDP Context Req",
    19:  "Update PDP Context Resp",
    20:  "Delete PDP Context Req",
    21:  "Delete PDP Context Resp",
    26:  "Error Indication",
    31:  "Supported Extensions Header Notification",
    32:  "Create Session Request",
    33:  "Create Session Response",
    34:  "Modify Bearer Request",
    35:  "Modify Bearer Response",
    36:  "Delete Session Request",
    37:  "Delete Session Response",
    64:  "Create Bearer Request",
    65:  "Create Bearer Response",
    66:  "Update Bearer Request",
    67:  "Update Bearer Response",
    68:  "Delete Bearer Request",
    69:  "Delete Bearer Response",
    95:  "Release Access Bearer Request",
    96:  "Release Access Bearer Response",
    255: "G-PDU (User Data)",
}

# GTP cause values that indicate failures
GTP_FAIL_CAUSES = {
    64: "Request accepted",              # success — keep for context
    65: "New PDN type due to network",
    66: "New PDN type due to single",
    67: "New PDN type due to SGSN",
    68: "New PDN type due to P-CSCF",
    72: "Context not found",
    73: "Invalid message format",
    74: "Version not supported",
    75: "No resources available",
    76: "Service not supported",
    77: "Mandatory IE incorrect",
    78: "Mandatory IE missing",
    80: "System failure",
    81: "No resources available",
    82: "Semantic error in TFT",
    83: "Syntactic error in TFT",
    84: "Semantic errors in PF",
    85: "Syntactic errors in PF",
    86: "Missing or unknown APN",
    87: "GRE key not found",
    88: "Relocation failure",
    92: "APN not supported",
    93: "APN restriction",
    94: "UE not responding",
    95: "UE refuses",
    96: "Service denied",
    97: "Unable to page UE",
    98: "No memory",
    99: "User authentication failed",
    100: "APN access denied",
    101: "Request rejected",
    102: "P-TMSI signature mismatch",
    103: "IMSI/IMEI not known",
    112: "PDN connection not exist",
    113: "PDN type IPv4 only",
    114: "PDN type IPv6 only",
    115: "Single address bearers",
    116: "ESM information required",
    119: "Multiple PDN not allowed",
    120: "Collision with network initiated",
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ip_str(raw: bytes) -> str:
    try:
        if len(raw) == 4:
            return socket.inet_ntop(socket.AF_INET, raw)
        if len(raw) == 16:
            return socket.inet_ntop(socket.AF_INET6, raw)
    except Exception:
        pass
    return raw.hex()


def _parse_gtp(payload: bytes, src_ip: str, dst_ip: str,
               src_port: int, dst_port: int,
               ts: float, pkt_num: int) -> List[str]:
    """Parse GTP header and generate log lines."""
    lines = []
    if len(payload) < 8:
        return lines

    try:
        flags     = payload[0]
        msg_type  = payload[1]
        length    = struct.unpack_from(">H", payload, 2)[0]
        teid      = struct.unpack_from(">I", payload, 4)[0]

        msg_label = GTP_MSG_TYPES.get(msg_type, f"Unknown(type={msg_type})")
        layer     = "GTP-C" if dst_port == GTP_C_PORT or src_port == GTP_C_PORT else "GTP-U"

        base = (f"{_ts_str(ts)} [{layer}] pkt={pkt_num} "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                f"TEID=0x{teid:08X} msg={msg_label} len={length}")
        lines.append(base)

        # Look for cause IE in response messages (GTPv2 cause IE = type 2)
        if msg_type in (33, 35, 37, 65, 67, 69, 96) and len(payload) > 12:
            body = payload[12:]  # skip GTPv2 fixed header
            idx = 0
            while idx + 4 <= len(body):
                ie_type = body[idx]
                ie_len  = struct.unpack_from(">H", body, idx + 1)[0]
                if ie_type == 2 and ie_len >= 1 and idx + 5 <= len(body):
                    cause_val = body[idx + 4]
                    cause_lbl = GTP_FAIL_CAUSES.get(cause_val, f"cause={cause_val}")
                    severity  = "ERROR" if cause_val not in (64, 65, 66, 67) else "INFO"
                    lines.append(
                        f"{_ts_str(ts)} [{layer}] pkt={pkt_num} "
                        f"{msg_label} {cause_lbl} TEID=0x{teid:08X} [{severity}]"
                    )
                    if cause_val not in (64,):  # 64 = accepted
                        lines.append(
                            f"{_ts_str(ts)} [GTP] GTP Context cause={cause_val} "
                            f"({cause_lbl}) TEID=0x{teid:08X}"
                        )
                    break
                idx += 4 + ie_len
    except Exception as e:
        logger.debug(f"GTP parse error pkt {pkt_num}: {e}")

    return lines


def _parse_sctp_payload(payload: bytes, src_ip: str, dst_ip: str,
                        dst_port: int, ts: float, pkt_num: int) -> List[str]:
    """
    Minimal SCTP chunk extraction. We look for DATA chunks (type=0)
    and report the stream/ssn, which maps to S1AP/NGAP messages.
    """
    lines = []
    if len(payload) < 12:
        return lines
    try:
        # SCTP common header: src_port(2) dst_port(2) vtag(4) checksum(4)
        offset = 12
        layer  = "NGAP" if dst_port == 38412 else "S1AP"
        while offset + 4 <= len(payload):
            chunk_type = payload[offset]
            chunk_flags = payload[offset + 1]
            chunk_len  = struct.unpack_from(">H", payload, offset + 2)[0]
            if chunk_len < 4:
                break
            if chunk_type == 0:  # DATA chunk
                if offset + 16 <= len(payload):
                    tsn    = struct.unpack_from(">I", payload, offset + 4)[0]
                    sid    = struct.unpack_from(">H", payload, offset + 8)[0]
                    ssn    = struct.unpack_from(">H", payload, offset + 10)[0]
                    ppid   = struct.unpack_from(">I", payload, offset + 12)[0]
                    data   = payload[offset + 16: offset + chunk_len]
                    lines.append(
                        f"{_ts_str(ts)} [{layer}] pkt={pkt_num} "
                        f"{src_ip} -> {dst_ip}:{dst_port} "
                        f"SCTP DATA tsn={tsn} sid={sid} ssn={ssn} ppid={ppid} "
                        f"payload_len={len(data)}"
                    )
                    # Try to infer NGAP/S1AP PDU type from first bytes of data
                    if len(data) >= 2:
                        ngap_hint = _hint_ngap(data, layer, ts, pkt_num,
                                               src_ip, dst_ip)
                        lines.extend(ngap_hint)
            offset += max(4, chunk_len + (4 - chunk_len % 4) % 4)
    except Exception as e:
        logger.debug(f"SCTP parse error pkt {pkt_num}: {e}")
    return lines


def _hint_ngap(data: bytes, layer: str, ts: float, pkt_num: int,
               src_ip: str, dst_ip: str) -> List[str]:
    """
    Heuristic: peek at first byte of NGAP/S1AP ASN.1 BER to guess PDU class.
    NGAP PDUs start with:
      0x00 = initiatingMessage
      0x20 = successfulOutcome
      0x40 = unsuccessfulOutcome
    Procedure codes (byte 2 in initiating/successful) are well-known.
    """
    lines = []
    try:
        pdu_class = data[0] & 0x60  # bits 6-5
        class_map = {0x00: "InitiatingMessage", 0x20: "SuccessfulOutcome",
                     0x40: "UnsuccessfulOutcome"}
        pdu_type  = class_map.get(pdu_class, "Unknown")

        # Procedure code is typically at byte index 2 after BER tag/length
        proc_code = None
        if len(data) >= 4:
            proc_code = data[2] if data[1] <= 127 else (
                data[3] if len(data) > 3 else None
            )

        ngap_procs = {
            0:  "AMFConfigurationUpdate",
            1:  "AMFCPRelocationIndication",
            4:  "AMFStatusIndication",
            10: "HandoverCancel",
            11: "HandoverNotification",
            12: "HandoverPreparation",
            13: "HandoverResourceAllocation",
            14: "InitialContextSetup",
            15: "LocationReportingControl",
            19: "NGSetup",
            20: "PathSwitchRequest",
            21: "PDUSessionResourceModify",
            22: "PDUSessionResourceModifyIndication",
            23: "PDUSessionResourceRelease",
            24: "PDUSessionResourceSetup",
            25: "PDUSessionResourceNotify",
            26: "PrivateMessage",
            27: "PWSCancel",
            28: "PWSFailureIndication",
            29: "PWSRestartIndication",
            30: "RANConfigurationUpdate",
            35: "UEContextModification",
            36: "UEContextRelease",
            37: "UEContextReleaseRequest",
            38: "UERadioCapabilityCheck",
            41: "UplinkNASTransport",
            46: "DownlinkNASTransport",
            48: "InitialUEMessage",
            58: "RerouteNASRequest",
            60: "UplinkRANStatusTransfer",
            61: "UplinkUETNLAInformationExchange",
        }

        proc_name = ngap_procs.get(proc_code, f"proc={proc_code}") if proc_code is not None else "unknown"

        line = (f"{_ts_str(ts)} [{layer}] pkt={pkt_num} "
                f"{src_ip} -> {dst_ip} "
                f"{pdu_type} procedure={proc_name}")
        lines.append(line)

        # Flag failure PDUs
        if pdu_type == "UnsuccessfulOutcome":
            lines.append(
                f"{_ts_str(ts)} [{layer}] pkt={pkt_num} "
                f"NGAP UnsuccessfulOutcome procedure={proc_name} "
                f"cause=radioNetwork/unspecified [ERROR]"
            )
            # Map procedure to specific failure type for log_parser detection
            fail_map = {
                "HandoverPreparation":        "NGAP HandoverPreparationFailure",
                "HandoverResourceAllocation": "NGAP HandoverPreparationFailure",
                "InitialContextSetup":        "NGAP InitialContextSetupFailure",
                "PDUSessionResourceSetup":    "NGAP PDUSessionResourceSetupFail",
                "NGSetup":                    "NGAP NGSetupFailure",
            }
            if proc_name in fail_map:
                lines.append(
                    f"{_ts_str(ts)} [{layer}] pkt={pkt_num} "
                    f"{fail_map[proc_name]} [ERROR]"
                )
    except Exception:
        pass
    return lines


def _ts_str(ts: float) -> str:
    from datetime import datetime, timezone
    try:
        dt = datetime.fromtimestamp(ts, tz=timezone.utc)
        return dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    except Exception:
        return f"{ts:.6f}"


# ── Main PCAP parser ──────────────────────────────────────────────────────────

def parse_pcap(data: bytes) -> str:
    """
    Parse a PCAP or PCAPNG binary blob.
    Returns a multi-line log string compatible with log_parser.parse().
    """
    try:
        import dpkt
    except ImportError:
        return "# ERROR: dpkt not installed — cannot parse PCAP files\n"

    lines: List[str] = []
    pkt_num = 0

    # Detect format
    if len(data) < 4:
        return "# ERROR: File too small to be a valid PCAP\n"

    magic = struct.unpack_from(">I", data, 0)[0]

    try:
        if magic == PCAPNG_MAGIC:
            # PCAPNG
            reader = dpkt.pcapng.Reader(io.BytesIO(data))
        elif magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE,
                       0xA1B23C4D, 0x4D3CB2A1):  # nanosec variants
            reader = dpkt.pcap.Reader(io.BytesIO(data))
        else:
            # Try pcap anyway
            reader = dpkt.pcap.Reader(io.BytesIO(data))

        lines.append(f"# PCAP file parsed — {len(data)} bytes")

        for ts, raw_pkt in reader:
            pkt_num += 1
            try:
                eth = dpkt.ethernet.Ethernet(raw_pkt)
            except Exception:
                try:
                    # Maybe raw IP (linktype 101)
                    ip = dpkt.ip.IP(raw_pkt)
                    _process_ip(ip, ts, pkt_num, lines)
                except Exception:
                    pass
                continue

            ip_pkt = None
            if isinstance(eth.data, dpkt.ip.IP):
                ip_pkt = eth.data
            elif isinstance(eth.data, dpkt.ip6.IP6):
                ip_pkt = eth.data
            else:
                continue

            _process_ip(ip_pkt, ts, pkt_num, lines)

    except Exception as e:
        lines.append(f"# PCAP parse error: {e}")
        logger.error(f"PCAP parse failed: {e}")

    lines.append(f"# Total packets processed: {pkt_num}")

    if not any(not l.startswith("#") for l in lines):
        lines.append("# No decodable 3GPP packets found in this capture")
        lines.append("# The PCAP may contain encrypted/encapsulated traffic")
        lines.append("# Tip: use Wireshark to pre-decode and export as text,")
        lines.append("#      then paste the text export into the log input.")

    return "\n".join(lines)


def _process_ip(ip_pkt, ts: float, pkt_num: int, lines: List[str]):
    """Extract transport layer and dispatch to protocol handlers."""
    try:
        src_ip = _ip_str(ip_pkt.src)
        dst_ip = _ip_str(ip_pkt.dst)
        transport = ip_pkt.data

        # UDP (GTP lives here)
        if isinstance(transport, __import__('dpkt').udp.UDP):
            udp = transport
            src_port = udp.sport
            dst_port = udp.dport
            payload  = bytes(udp.data)

            port_label = PORT_MAP.get(dst_port) or PORT_MAP.get(src_port, "UDP")

            # GTP-C or GTP-U
            if dst_port in (GTP_C_PORT, GTP_U_PORT) or src_port in (GTP_C_PORT, GTP_U_PORT):
                gtp_lines = _parse_gtp(payload, src_ip, dst_ip,
                                       src_port, dst_port, ts, pkt_num)
                lines.extend(gtp_lines)
            else:
                lines.append(
                    f"{_ts_str(ts)} [{port_label}] pkt={pkt_num} "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                    f"UDP len={len(payload)}"
                )

        # SCTP (NGAP / S1AP)
        elif hasattr(__import__('dpkt'), 'sctp') and isinstance(transport, __import__('dpkt').sctp.SCTP):
            sctp = transport
            dst_port = sctp.dport
            src_port = sctp.sport
            sctp_lines = _parse_sctp_payload(
                bytes(ip_pkt.data), src_ip, dst_ip, dst_port, ts, pkt_num
            )
            lines.extend(sctp_lines)

        # TCP
        elif isinstance(transport, __import__('dpkt').tcp.TCP):
            tcp = transport
            src_port = tcp.sport
            dst_port = tcp.dport
            port_label = PORT_MAP.get(dst_port) or PORT_MAP.get(src_port, "TCP")
            flags = []
            if tcp.flags & 0x02: flags.append("SYN")
            if tcp.flags & 0x01: flags.append("FIN")
            if tcp.flags & 0x04: flags.append("RST")
            if tcp.flags & 0x10: flags.append("ACK")
            flag_str = "+".join(flags) if flags else "DATA"
            payload_len = len(bytes(tcp.data))
            if payload_len > 0 or "RST" in flags or "SYN" in flags:
                lines.append(
                    f"{_ts_str(ts)} [{port_label}] pkt={pkt_num} "
                    f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} "
                    f"TCP {flag_str} len={payload_len}"
                )
                if "RST" in flags:
                    lines.append(
                        f"{_ts_str(ts)} [{port_label}] pkt={pkt_num} "
                        f"TCP RST {src_ip}:{src_port} -> {dst_ip}:{dst_port} [ERROR]"
                    )

        # ICMP
        elif isinstance(transport, __import__('dpkt').icmp.ICMP):
            icmp = transport
            lines.append(
                f"{_ts_str(ts)} [ICMP] pkt={pkt_num} "
                f"{src_ip} -> {dst_ip} type={icmp.type} code={icmp.code}"
            )

    except Exception as e:
        logger.debug(f"IP process error pkt {pkt_num}: {e}")


def is_pcap(data: bytes) -> bool:
    """Return True if data looks like a PCAP or PCAPNG file."""
    if len(data) < 4:
        return False
    magic = struct.unpack_from(">I", data, 0)[0]
    return magic in (PCAP_MAGIC_LE, PCAP_MAGIC_BE,
                     PCAPNG_MAGIC,
                     0xA1B23C4D, 0x4D3CB2A1,   # nanosec
                     0x0A0D0D0A)                # pcapng alt
