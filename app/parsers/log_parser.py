"""
Log Parser Module
Parses raw 3GPP protocol logs and extracts structured events and failure points.
Supports: sample logs, Ericsson ENM/OAM, Nokia NetAct, Huawei U2000/MML,
          Qualcomm QXDM/QCAT, Wireshark text exports, Android modem logs,
          3GPP ASN.1 decoded text, generic syslog-style outputs.
"""

import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional


# ──────────────────────────────────────────────────────────────────────────────
# Data Models
# ──────────────────────────────────────────────────────────────────────────────

@dataclass
class LogEvent:
    line_number: int
    timestamp: Optional[str]
    layer: str
    message: str
    raw_line: str
    severity: str = "INFO"


@dataclass
class FailurePoint:
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
    total_lines: int
    events: List[LogEvent] = field(default_factory=list)
    failures: List[FailurePoint] = field(default_factory=list)
    layers_found: List[str] = field(default_factory=list)
    summary: Dict = field(default_factory=dict)


# ──────────────────────────────────────────────────────────────────────────────
# Failure Signatures
# Broadly written to catch real-world vendor log formats:
#   Ericsson RANAP/ENM, Nokia NetAct, Huawei U2000/MML,
#   Qualcomm QXDM/QCAT, Wireshark ASN.1 decode, Android modem, syslog
# Each tuple: (pattern, layer, failure_type, spec_ref, description)
# ──────────────────────────────────────────────────────────────────────────────

FAILURE_SIGNATURES = [

    # ══════════════════════════════════════════════════════════════════════════
    # RRC — TS 38.331 / TS 36.331
    # ══════════════════════════════════════════════════════════════════════════

    # RRC Setup / Connection Failure
    (r"rrc.{0,20}(setup|conn(ection)?).{0,20}(fail|reject|error|refused|abort)"
     r"|rrcSetupFailure|rrcConnectionSetupFailure|rrcConSetupFail"
     r"|RRCSetup.*Fail|rrc_setup_fail|rrc\.setup\.fail"
     r"|t300.{0,10}expir|t300_expir|T300.*expir|timer.*t300",
     "RRC", "RRC Setup Failure",
     "TS 38.331 Sec 5.3.3",
     "UE failed to complete RRC connection setup. Possible: gNB overload, T300 expiry, coverage gap."),

    # RRC Rejection
    (r"rrcReject|rrc.{0,10}reject|RRCReject|rrc_reject|rrc\.reject"
     r"|congestion.{0,30}rrc|rrc.{0,30}congestion|waitTime.*rrc",
     "RRC", "RRC Rejection",
     "TS 38.331 Sec 5.3.3",
     "gNB rejected RRC setup request. Check congestion and waitTime value in RRCReject."),

    # RRC Re-establishment Failure
    (r"rrc.{0,20}re.?establi.{0,10}(fail|reject|error)"
     r"|rrcReestablishment(Reject|Failure|Fail)"
     r"|reestablishment.{0,10}(reject|fail)|t301.{0,10}expir|T301.*expir"
     r"|shortMAC.{0,5}(mismatch|fail|error)|context.{0,20}not.{0,10}found",
     "RRC", "RRC Re-establishment Failure",
     "TS 38.331 Sec 5.3.7",
     "RRC re-establishment rejected. Causes: context not found at target, shortMAC-I mismatch, T311/T301 expiry."),

    # Radio Link Failure
    (r"radio.{0,10}link.{0,10}(fail|loss|rlf)"
     r"|radioLinkFailure|rlf.{0,10}detect|rlf_detect|RLF"
     r"|rl.fail|rl_fail|radio_link_failure"
     r"|out.of.sync|OOS.{0,10}(N310|detect)|n310.{0,10}(expir|count|reach)"
     r"|t310.{0,10}expir|T310.*expir|T310_EXPIRY|timer310",
     "RRC", "Radio Link Failure",
     "TS 38.331 Sec 5.3.10 / TS 36.331 Sec 5.3.11",
     "Radio link failure declared. Physical layer quality dropped below threshold. Check T310/N310/N311 and SINR."),

    # Handover Failure
    (r"handover.{0,20}(fail|error|cancel|abort|timeout)"
     r"|ho.{0,10}(fail|error|abort|timeout)|HO_FAIL|HOFailure|handoverFailure"
     r"|HoFail|ho_fail|handover_fail|HandoverFail"
     r"|t304.{0,10}expir|T304.*expir|T304_EXPIRY|timer304"
     r"|too.{0,10}(late|early).{0,20}handover|ping.pong|wrong.cell.ho",
     "RRC", "Handover Failure",
     "TS 38.331 Sec 5.3.5 / TS 38.413",
     "Handover procedure failed. Check T304 timer, target cell availability, A3/A5 event config."),

    # RRC Reconfiguration Failure
    (r"rrc.{0,20}reconfig.{0,20}(fail|reject|error)"
     r"|rrcReconfiguration(Failure|Fail)|reconfiguration.fail"
     r"|rrc_reconfig_fail|mobilityControl.*fail",
     "RRC", "RRC Reconfiguration Failure",
     "TS 38.331 Sec 5.3.5",
     "UE rejected or failed RRC Reconfiguration. Check UE capabilities and config parameters."),

    # Measurement Report Issues
    (r"measurement.{0,20}(fail|miss|timeout|report.*miss)"
     r"|measReport.{0,20}(late|miss|fail)|no.*measReport"
     r"|a3.{0,20}(fail|miss|not.*trigger)|a5.{0,20}(fail|miss)"
     r"|TTT.{0,20}expir|time.to.trigger.*expir",
     "RRC", "Measurement Report Issue",
     "TS 38.331 Sec 5.5.5",
     "MeasurementReport not received or A3/A5 event threshold issue. Check offset and TTT configuration."),

    # ══════════════════════════════════════════════════════════════════════════
    # NAS — TS 24.501 (5GS) / TS 24.301 (EPS)
    # ══════════════════════════════════════════════════════════════════════════

    # Registration / Attach Reject
    (r"registr.{0,15}(reject|fail|refused|deny|denied)"
     r"|attach.{0,15}(reject|fail|refused|deny)"
     r"|Registration.Reject|RegistrationReject|AttachReject|Attach.Reject"
     r"|emm.{0,15}(reject|fail)|5gmm.{0,15}(reject|fail)"
     r"|registration_reject|attach_reject|reg.fail",
     "NAS", "Registration/Attach Reject",
     "TS 24.501 Sec 5.5.1 / TS 24.301",
     "NAS registration/attach rejected by network. Check cause code for specific reason."),

    # Authentication Failure
    (r"auth.{0,20}(fail|error|reject|refused)"
     r"|authentication.{0,10}(fail|error|reject)"
     r"|authenticationFailure|AuthFail|auth_fail"
     r"|mac.{0,10}(fail|failure|error).{0,20}(auth|nas|sim)"
     r"|MAC.failure|mac_failure|MAC_FAILURE"
     r"|synch.{0,10}fail|sync.fail.{0,10}(sim|usim|auth)"
     r"|sqn.{0,10}(mismatch|fail)|sequence.number.{0,10}(mismatch|fail)"
     r"|usim.{0,10}(fail|reject|error)|sim.{0,10}(fail|reject|error)",
     "NAS", "Authentication Failure",
     "TS 24.501 Sec 5.4.1 / TS 24.301 Sec 5.4.2",
     "NAS authentication failed. Check USIM credentials, AMF/AUSF key sync, SQN counter."),

    # Security Mode Failure
    (r"security.{0,15}(mode|cmd|command).{0,15}(reject|fail|error)"
     r"|SecurityModeReject|securityModeReject|security_mode_fail"
     r"|nas.{0,15}security.{0,15}(fail|reject)"
     r"|integrity.{0,15}(fail|check.fail|verify.fail).{0,20}nas"
     r"|nas.{0,15}integrity.{0,15}fail",
     "NAS", "Security Mode Command Failure",
     "TS 24.501 Sec 5.4.2",
     "NAS security mode command rejected. Check integrity algorithm, key derivation at AMF."),

    # PDU Session / Bearer Failure
    (r"pdu.{0,15}session.{0,20}(fail|error|reject|refused)"
     r"|PDUSessionFail|pduSession.*Fail|pdu_session_fail"
     r"|bearer.{0,20}(fail|setup.*fail|establish.*fail)"
     r"|eps.bearer.{0,20}(fail|reject)|default.bearer.{0,20}fail"
     r"|esm.{0,15}(fail|reject|error)|5gsm.{0,15}(fail|reject)"
     r"|cause.{0,10}#27|cause.{0,10}27.{0,5}(dnn|apn|unknown)"
     r"|unknown.{0,10}(dnn|apn)|apn.{0,10}(not.found|unknown|invalid)"
     r"|dnn.{0,10}(not.found|unknown|invalid|not.support)",
     "NAS", "PDU Session/Bearer Failure",
     "TS 24.501 Sec 6.4.1 / TS 24.301",
     "PDU session or EPS bearer setup failed. Check DNN/APN config, SMF/PGW availability, cause code."),

    # Congestion / Back-off
    (r"cause.{0,10}#22|cause.{0,10}22.{0,10}(congestion|overload)"
     r"|congestion.{0,15}(back.?off|timer|reject)"
     r"|t3346.{0,10}(start|active|expir)|back.?off.{0,15}timer"
     r"|overload.{0,15}(nas|registr|attach)|network.{0,10}overload",
     "NAS", "NAS Congestion / Back-off",
     "TS 24.501 Sec 5.5.1.3 / TS 24.301",
     "Network congestion detected. T3346 back-off timer active. Retry after timer expiry."),

    # PLMN/TA Not Allowed
    (r"cause.{0,10}#11|plmn.{0,15}(not.allow|deny|forbidden|reject)"
     r"|cause.{0,10}#12|tracking.area.{0,15}(not.allow|forbidden)"
     r"|cause.{0,10}#13|roaming.{0,15}(not.allow|forbidden|deny)"
     r"|cause.{0,10}#7|5gs.{0,10}service.{0,10}not.allow"
     r"|eps.{0,10}service.{0,10}not.allow",
     "NAS", "PLMN/TA Not Allowed",
     "TS 24.501 Sec 5.5.1",
     "PLMN or tracking area not allowed for this UE. Check SIM provisioning and network subscription."),

    # Deregistration
    (r"deregistr|de.registr|detach.{0,15}(request|accept|reject)"
     r"|deregister|de_register|UE.deregistered|imsi.detach",
     "NAS", "Deregistration / Detach",
     "TS 24.501 Sec 5.5.2",
     "UE deregistration or detach procedure. Check if triggered by network or UE."),

    # ══════════════════════════════════════════════════════════════════════════
    # NGAP — TS 38.413
    # ══════════════════════════════════════════════════════════════════════════

    # Handover Preparation Failure
    (r"(ngap|ng.ap).{0,20}handover.{0,20}(prep|preparation).{0,20}fail"
     r"|HandoverPreparationFailure|handoverPreparationFail"
     r"|target.{0,20}(not.allow|not.found|reject|refuse).{0,20}(ho|handover)"
     r"|no.radio.resource.{0,20}target|target.cell.{0,20}(full|no.resource)",
     "NGAP", "Handover Preparation Failure",
     "TS 38.413 Sec 8.4",
     "NGAP handover preparation failed at target AMF/gNB. Check target cell admission and resources."),

    # Initial Context Setup Failure
    (r"(ngap|ng.ap).{0,20}(initial|init).{0,20}context.{0,20}(setup|config).{0,20}fail"
     r"|InitialContextSetupFailure|initialContextSetupFail"
     r"|initial_context_fail|NG.setup.fail|ngSetupFail|NGSetupFailure",
     "NGAP", "Initial Context Setup Failure",
     "TS 38.413 Sec 8.3",
     "Initial UE context setup failed over NG interface. Check AMF-gNB connectivity."),

    # PDU Session Resource Failure
    (r"(ngap|ng.ap).{0,20}pdu.{0,20}session.{0,20}(resource.{0,10}setup|setup).{0,20}fail"
     r"|PDUSessionResourceSetupFail|pduSessionResourceFail"
     r"|e.?rab.{0,10}(setup|assign).{0,10}fail|E.RAB.*Fail"
     r"|erab.fail|eRABFail|e_rab_fail|erab_setup_fail",
     "NGAP", "PDU Session / E-RAB Setup Failure",
     "TS 38.413 Sec 8.2 / TS 36.413 Sec 8.2",
     "PDU session resource or E-RAB setup failed at gNB/eNB. Check QoS params and radio resources."),

    # UE Context Release — RLF
    (r"(ue.?context|ueContext).{0,20}(release|releas).{0,20}(radio|rlf|rl.fail)"
     r"|UEContextRelease.{0,30}(radio|rlf|lost|loss)"
     r"|ue_context_release.{0,20}radio|context.release.*radio.connection"
     r"|cause.{0,15}radio.{0,15}(connection.lost|link.fail|rl.fail)",
     "NGAP", "UE Context Release — RLF",
     "TS 38.413 Sec 8.3",
     "AMF triggered UE context release due to radio link failure."),

    # ══════════════════════════════════════════════════════════════════════════
    # S1AP — TS 36.413
    # ══════════════════════════════════════════════════════════════════════════

    (r"(s1.?ap|s1.ap).{0,20}(setup|handover|ho).{0,20}fail"
     r"|S1SetupFailure|s1SetupFail|S1AP.*Fail|s1_fail"
     r"|mme.{0,20}(unreachable|down|not.respond)|s1.interface.down"
     r"|ts1relocoverall|ts1relocprep|tS1.*expir",
     "S1AP", "S1AP Failure",
     "TS 36.413",
     "S1 interface or procedure failure. Check eNB-MME connectivity."),

    # ══════════════════════════════════════════════════════════════════════════
    # MAC — TS 38.321 / TS 36.321
    # ══════════════════════════════════════════════════════════════════════════

    # RACH Failure
    (r"rach.{0,20}(fail|error|timeout|max|exhaust)"
     r"|preamble.{0,20}(max|exhaust|limit|retry.max)"
     r"|preambleTransMax|preamble_trans_max|RACH_FAIL|rach_fail"
     r"|msg2.{0,20}(not.receiv|timeout|miss)|rar.{0,20}(not.receiv|timeout|miss)"
     r"|random.access.{0,20}(fail|error|exhaust|max)"
     r"|ra.{0,10}(fail|abort|timeout).{0,10}(mac|rach|access)"
     r"|no.msg2|msg4.{0,20}(not.receiv|fail)|contention.resolut.{0,10}fail",
     "MAC", "RACH Failure",
     "TS 38.321 Sec 5.1 / TS 36.321 Sec 5.1",
     "Random access procedure failed. Max preamble transmissions reached. Check PRACH coverage and config."),

    # HARQ Failure
    (r"harq.{0,20}(max|fail|error|exhausted)"
     r"|max.{0,15}retransmission.{0,15}(reach|exhaust|harq)"
     r"|HARQ_FAIL|harq_fail|harq.nack.max|harq.abort"
     r"|transport.block.{0,20}(discard|fail|drop)"
     r"|tb.{0,10}discard|ndi.{0,20}fail",
     "MAC", "HARQ Max Retransmissions",
     "TS 38.321 Sec 5.4 / TS 36.321 Sec 5.4",
     "HARQ maximum retransmissions exhausted. Transport block discarded. Poor radio conditions."),

    # Scheduling / Grant Failure
    (r"no.{0,10}(dl|ul).{0,10}(grant|schedule|alloc).{0,20}(fail|miss|timeout)"
     r"|scheduling.{0,15}(fail|error|stall)|sr.{0,10}(fail|no.resp|max)"
     r"|scheduling.request.{0,10}(fail|max|exhaust|no.response)"
     r"|bsr.{0,20}(overflow|fail|stall)|buffer.stall",
     "MAC", "Scheduling Failure",
     "TS 38.321 Sec 5.4",
     "Scheduling failure or no grant received. Check gNB scheduler and PDCCH coverage."),

    # ══════════════════════════════════════════════════════════════════════════
    # RLC — TS 38.322 / TS 36.322
    # ══════════════════════════════════════════════════════════════════════════

    # Max Retransmissions
    (r"maxRetxThreshold|max.?retx.{0,10}(threshold|reach|exhaust)"
     r"|rlc.{0,20}(max.retx|retransmission.max|retx.fail)"
     r"|RLC.{0,10}fail|rlc_fail|rlc_max_retx"
     r"|poll.retransmit.{0,15}(expir|timeout)|t.poll.retransmit",
     "RLC", "RLC Max Retransmission",
     "TS 38.322 Sec 5.3 / TS 36.322",
     "RLC AM mode maxRetxThreshold reached. Radio link failure will be declared. Check physical layer."),

    # Reordering Timeout
    (r"t.reorder.{0,15}(expir|timeout)|tReordering.{0,10}expir"
     r"|rlc.{0,15}reorder.{0,15}(timeout|expir|fail)"
     r"|rlc.{0,15}sdu.{0,15}(discard|drop|loss)"
     r"|rlc.{0,15}(out.of.order|window.stall|seq.*gap)"
     r"|sn.{0,10}gap.{0,10}(rlc|detect)|segment.{0,10}(miss|timeout)",
     "RLC", "RLC Reordering / SDU Failure",
     "TS 38.322 Sec 5.2",
     "RLC reordering timer expired or SDU discarded. Check radio conditions and window size."),

    # ══════════════════════════════════════════════════════════════════════════
    # PDCP — TS 38.323 / TS 36.323
    # ══════════════════════════════════════════════════════════════════════════

    # Integrity Failure
    (r"pdcp.{0,20}integrity.{0,20}(fail|error|check.fail|verif.fail)"
     r"|integrity.{0,15}(verif|check|protect).{0,15}(fail|error)"
     r"|MAC.I.{0,15}(mismatch|fail|error)|mac_i.fail|macI.fail"
     r"|integrity.fail|integrity_fail|INTEGRITY_FAIL"
     r"|pdcp.{0,15}(integ|security).{0,15}(fail|error)"
     r"|srb.{0,10}integrity.fail|drb.{0,10}integrity.fail",
     "PDCP", "PDCP Integrity Failure",
     "TS 38.323 Sec 5.9 / TS 36.323",
     "PDCP integrity verification failed. Security key mismatch, possibly after handover. Check key derivation."),

    # Ciphering Error
    (r"pdcp.{0,15}(cipher|crypt|decrypt).{0,15}(fail|error|mismatch)"
     r"|decipher.{0,15}(fail|error)|cipher.{0,15}(fail|error|mismatch)"
     r"|ciphering.fail|ciphering_fail|deciphering.fail"
     r"|pdcp.{0,15}security.{0,15}(fail|key.error)"
     r"|security.key.{0,15}(mismatch|fail|error).{0,15}(pdcp|srb|drb)",
     "PDCP", "PDCP Ciphering Error",
     "TS 38.323 Sec 5.8",
     "PDCP ciphering/deciphering error. Algorithm or key mismatch between UE and gNB."),

    # Discard Timer
    (r"discardTimer.{0,10}expir|discard.timer.{0,10}(expir|timeout)"
     r"|pdcp.{0,15}(sdu|pdu).{0,15}(discard|drop|loss)"
     r"|pdcp.discard|pdcp_discard|rohc.{0,15}(fail|mismatch|error)",
     "PDCP", "PDCP Discard / ROHC Failure",
     "TS 38.323 Sec 5.2",
     "PDCP discard timer expired or ROHC context mismatch. Application-level delay likely."),

    # ══════════════════════════════════════════════════════════════════════════
    # GTP / Core Network — TS 29.281, TS 29.274
    # ══════════════════════════════════════════════════════════════════════════

    # Context Not Found
    (r"gtp.{0,20}(context.not.found|teid.not.found|no.context|unknown.teid)"
     r"|cause.{0,10}73|cause.*context.not.found"
     r"|teid.{0,15}(not.found|invalid|mismatch|unknown)"
     r"|gtp.tunnel.{0,15}(not.found|fail|miss|lost)"
     r"|f.teid.{0,15}(mismatch|fail|not.found)"
     r"|GTP.*Context.*Not.*Found|gtp_context_not_found",
     "GTP", "GTP Context Not Found",
     "TS 29.281 / TS 29.274",
     "GTP tunnel context not found. F-TEID mismatch between UPF/SGW and gNB/eNB."),

    # UPF/SGW/PGW Interface Failure
    (r"upf.{0,20}(fail|down|unavail|unreachable|error)"
     r"|sgw.{0,20}(fail|down|unavail|error)|pgw.{0,20}(fail|down|error)"
     r"|n3.{0,20}(interface|iface|tunnel).{0,15}(down|fail|loss)"
     r"|n9.{0,20}(interface|iface).{0,15}(down|fail)"
     r"|s1u.{0,20}(down|fail|loss)|s5.{0,20}(down|fail)"
     r"|gw.{0,10}(unreachable|fail|down)|core.{0,15}(fail|down|unavail)"
     r"|ip.alloc.{0,15}(fail|error|exhaust)|no.ip.address",
     "GTP", "Core Network / UPF Failure",
     "TS 23.501 / TS 29.244",
     "Core network or UPF interface failure. Check N3/N9/S1-U/S5 connectivity."),

    # GTP Error Response
    (r"gtp.{0,20}(error.response|error.indication|err.ind)"
     r"|cause.{0,10}(64|65|66|67|68|69|70|94|95|96|99|100|101)"
     r".{0,20}(gtp|bearer|session|upf|sgw)"
     r"|gtp.cause.{0,10}(reject|deny|fail|not.support)"
     r"|bearer.{0,20}(not.found|not.exist|invalid)",
     "GTP", "GTP Error Response",
     "TS 29.274 Sec 8.4",
     "GTP error response received. Check cause code for specific reason."),

    # ══════════════════════════════════════════════════════════════════════════
    # DIAMETER / HSS / AAA — TS 29.272, TS 29.273
    # ══════════════════════════════════════════════════════════════════════════

    (r"diameter.{0,20}(fail|error|reject|timeout)"
     r"|hss.{0,20}(fail|error|reject|unreachable)"
     r"|aaa.{0,20}(fail|reject|error)|radius.{0,20}(fail|reject)"
     r"|diameter.cause.{0,10}(3001|3002|5001|5004|5012)"
     r"|result.code.{0,10}(3001|3002|5001|5004)"
     r"|avp.{0,15}(missing|invalid|unsupported)|unable.to.comply"
     r"|s6a.{0,15}(fail|error)|cx.{0,15}(fail|error)"
     r"|subscriber.{0,20}(not.found|unknown|deny)",
     "DIAMETER", "Diameter / HSS Failure",
     "TS 29.272 / TS 29.273",
     "Diameter or HSS failure. Check HSS connectivity, subscriber profile, and result code."),

    # ══════════════════════════════════════════════════════════════════════════
    # Ericsson-specific log patterns
    # ══════════════════════════════════════════════════════════════════════════

    (r"ALARM.{0,30}(RRC|NAS|RACH|HO|RLF|AUTH|PDU)"
     r"|FAULT.{0,30}(RRC|NAS|RACH|HANDOVER|RADIO)"
     r"|CELL.{0,15}(UNAVAILABLE|OUTAGE|DOWN|FAIL)"
     r"|ENB.{0,15}(FAIL|DOWN|OVERLOAD|CONGESTION)"
     r"|ericsson.{0,20}(alarm|fault|fail)"
     r"|CRITICAL.{0,20}(RRC|NAS|RADIO|CELL|ENB)",
     "RRC", "Ericsson Alarm — Protocol Failure",
     "Vendor: Ericsson ENM",
     "Ericsson-format alarm indicating protocol-level failure. Check alarm code and MO."),

    # ══════════════════════════════════════════════════════════════════════════
    # Nokia-specific log patterns
    # ══════════════════════════════════════════════════════════════════════════

    (r"(WBTS|RNC|BTS).{0,20}(FAIL|DOWN|FAULT|ERROR)"
     r"|nokia.{0,20}(fault|fail|alarm|error)"
     r"|CELLF.{0,10}(FAIL|DOWN)|CELL_FAIL"
     r"|NOBF.{0,10}|RLF.{0,5}(COUNT|THRESHOLD|ALARM)"
     r"|HSDPA.FAIL|HSUPA.FAIL",
     "RRC", "Nokia Alarm — Cell / BTS Failure",
     "Vendor: Nokia NetAct",
     "Nokia-format cell or BTS failure alarm. Check WBTS/BTS state and fault log."),

    # ══════════════════════════════════════════════════════════════════════════
    # Huawei-specific log patterns
    # ══════════════════════════════════════════════════════════════════════════

    (r"(eNodeB|gNodeB|NR).{0,20}(alarm|fault|fail|error|down)"
     r"|huawei.{0,20}(alarm|fault|fail)"
     r"|CELL.{0,10}INVALID|CELL_UNAVAIL|CELL_LOCK"
     r"|BBU.{0,15}(fail|down|alarm)|RRU.{0,15}(fail|down|alarm)"
     r"|alarmId.{0,10}:(2[0-9]{3}|3[0-9]{3}|4[0-9]{3})"
     r"|severityLevel.{0,10}:(CRITICAL|MAJOR|MINOR).{0,30}(RRC|NAS|LTE|NR)",
     "RRC", "Huawei Alarm — Node Failure",
     "Vendor: Huawei U2000/MML",
     "Huawei-format node or cell failure alarm. Check alarmId and severityLevel."),

    # ══════════════════════════════════════════════════════════════════════════
    # Qualcomm QXDM / Android modem log patterns
    # ══════════════════════════════════════════════════════════════════════════

    (r"LTE_RRC.{0,20}(FAIL|ERROR|OOS|CONN_FAIL)"
     r"|NR_RRC.{0,20}(FAIL|ERROR|OOS|CONN_FAIL)"
     r"|qxdm.{0,20}(fail|error|oos)|qcat.{0,20}fail"
     r"|modem.{0,20}(crash|reset|restart|fail|error)"
     r"|IMSM.{0,15}(FAIL|ERROR)|IMS.{0,15}(FAIL|ERROR|REGISTER.FAIL)"
     r"|DATA_CALL_FAIL|data_call_fail"
     r"|service.state.{0,15}(out.of.service|no.service|emergency)"
     r"|signal.lost|no.signal|signal.{0,10}(absent|drop)"
     r"|LTE_ML1.{0,20}(OOS|FAIL)|nr.ml1.{0,20}(oos|fail)",
     "RRC", "UE / Modem Failure",
     "3GPP UE Protocol Stack",
     "UE modem or protocol stack failure detected in device-side log. Check service state and modem crash."),

    # ══════════════════════════════════════════════════════════════════════════
    # Wireshark / Decoded ASN.1 text export patterns
    # ══════════════════════════════════════════════════════════════════════════

    (r"cause.{0,5}:.{0,10}(radioNetwork|transportNetwork|nas|protocol|misc)"
     r".{0,30}(unspecified|unknown|failure|error|reject)"
     r"|cause.value.{0,10}(radioLink|handover|radio|rlf|rrc|nas)"
     r"|failureCause.{0,10}:|rejection.{0,10}cause"
     r"|establishmentCause.{0,10}(fail|reject)"
     r"|Critical.Extension.Failure|criticalExtensionsFuture",
     "RRC", "Protocol Failure (ASN.1 Decoded)",
     "3GPP TS 38.331 / TS 38.413",
     "Failure cause detected in ASN.1-decoded protocol message. Check cause value field."),

    # ══════════════════════════════════════════════════════════════════════════
    # Generic / Syslog-style catch-all patterns
    # ══════════════════════════════════════════════════════════════════════════

    # Generic ERROR/CRITICAL with protocol keywords
    (r"(ERROR|CRITICAL|FATAL|ALARM|FAULT|SEVERE).{0,50}"
     r"(rrc|nas|rach|harq|rlc|pdcp|ngap|s1ap|gtp|handover|bearer|pdu.session|auth)",
     "RRC", "Protocol Error (Generic)",
     "3GPP Protocol Stack",
     "Protocol-level ERROR or CRITICAL log entry. Check full message and correlated events."),

    # Generic failure with protocol keywords
    (r"(rrc|nas|rach|rlc|pdcp|ngap|s1ap|gtp|handover|bearer).{0,50}"
     r"(ERROR|CRITICAL|FATAL|ALARM|FAULT|SEVERE|CRASH|ABORT)",
     "RRC", "Protocol Fault (Generic)",
     "3GPP Protocol Stack",
     "Protocol-level fault detected. Check message content and correlated events."),

    # Connection drop / service loss
    (r"connection.{0,20}(drop|lost|terminated|abort|reset|interrupt)"
     r"|service.{0,20}(interrupt|loss|unavail|drop).{0,20}(cell|ran|radio|lte|nr|5g)"
     r"|call.{0,20}(drop|fail|abort|disconnect).{0,20}(radio|rrc|nas|lte|nr)"
     r"|link.{0,20}(fail|drop|lost|down).{0,20}(radio|rrc|cell|ran)",
     "RRC", "Connection Drop",
     "3GPP Protocol Stack",
     "Radio connection drop or service interruption detected. Check RLF and handover logs."),
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
    "RRC":      ["RRC", "rrc", "RRCSetup", "RRCReject", "RRCReestablish",
                 "rrcConnection", "LTE_RRC", "NR_RRC", "mobilityControl"],
    "NAS":      ["NAS", "nas", "EMM", "ESM", "5GMM", "5GSM",
                 "Registration", "Attach", "Detach", "PDU Session",
                 "authenticationRequest", "securityModeCommand"],
    "MAC":      ["MAC", "mac", "RACH", "HARQ", "BSR", "SR ", "PDCCH",
                 "preamble", "RandomAccess", "random_access", "LTE_ML1"],
    "RLC":      ["RLC", "rlc", "AM mode", "UM mode", "t-Reordering",
                 "maxRetx", "pollRetransmit"],
    "PDCP":     ["PDCP", "pdcp", "integrity", "cipher", "ROHC",
                 "discardTimer", "MAC-I"],
    "NGAP":     ["NGAP", "ngap", "NG-AP", "AMF", "HandoverRequired",
                 "HandoverCommand", "InitialContextSetup"],
    "S1AP":     ["S1AP", "s1ap", "S1-AP", "MME", "E-RAB", "erab",
                 "S1Setup", "eNB-UE-S1AP"],
    "GTP":      ["GTP", "gtp", "TEID", "F-TEID", "UPF", "SGW", "PGW",
                 "N3", "N9", "S1-U", "S5", "bearer_id"],
    "DIAMETER": ["Diameter", "diameter", "AVP", "HSS", "AAA",
                 "Cx", "S6a", "result-code"],
}


# ──────────────────────────────────────────────────────────────────────────────
# Parser
# ──────────────────────────────────────────────────────────────────────────────

class LogParser:
    """Parses 3GPP protocol logs and detects failure points."""

    def __init__(self):
        self._ts_patterns  = [re.compile(p) for p in TIMESTAMP_PATTERNS]
        self._failure_sigs = [
            (re.compile(pat, re.IGNORECASE), layer, ftype, spec, desc)
            for pat, layer, ftype, spec, desc in FAILURE_SIGNATURES
        ]

    def _extract_timestamp(self, line: str) -> Optional[str]:
        for p in self._ts_patterns:
            m = p.search(line)
            if m:
                return m.group(0)
        return None

    def _detect_layer(self, line: str) -> str:
        for layer, keywords in LAYER_KEYWORDS.items():
            for kw in keywords:
                if kw in line:
                    return layer
        return "UNKNOWN"

    def _detect_severity(self, line: str) -> str:
        u = line.upper()
        if any(w in u for w in ["CRITICAL", "FATAL", "EMERGENCY", "SEVERE"]):
            return "CRITICAL"
        if any(w in u for w in ["ERROR", "FAIL", "FAILURE", "REJECT",
                                  "ABORT", "ALARM", "FAULT"]):
            return "ERROR"
        if any(w in u for w in ["WARN", "WARNING", "TIMEOUT", "EXPIRED",
                                  "RETRY", "DEGRADED"]):
            return "WARNING"
        return "INFO"

    def _extract_cause(self, line: str) -> Optional[str]:
        patterns = [
            r"cause\s*[=:]\s*([^\s,\]\)]+)",
            r"cause\s*=\s*#(\d+)",
            r"reject.cause\s*[=:]\s*([^\s,\]]+)",
            r"failure.cause\s*[=:]\s*([^\s,\]]+)",
            r"error.code\s*[=:]\s*([^\s,\]]+)",
            r"result.code\s*[=:]\s*([^\s,\]]+)",
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
            if not line or line.startswith("#"):
                continue

            ts       = self._extract_timestamp(line)
            layer    = self._detect_layer(line)
            severity = self._detect_severity(line)

            if layer != "UNKNOWN":
                layers_seen.add(layer)

            event = LogEvent(
                line_number=i,
                timestamp=ts,
                layer=layer,
                message=line[:300],
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
                    break  # one failure per line

        result.layers_found = sorted(layers_seen)
        result.summary      = self._build_summary(result)
        return result

    def _build_summary(self, result: ParseResult) -> dict:
        failure_counts: dict = {}
        layer_counts:   dict = {}
        for fp in result.failures:
            failure_counts[fp.failure_type] = failure_counts.get(fp.failure_type, 0) + 1
            layer_counts[fp.layer]          = layer_counts.get(fp.layer, 0) + 1
        return {
            "total_lines":         result.total_lines,
            "total_events":        len(result.events),
            "total_failures":      len(result.failures),
            "failure_types":       failure_counts,
            "failures_by_layer":   layer_counts,
            "layers_found":        result.layers_found,
            "most_critical_layer": max(layer_counts, key=layer_counts.get)
                                   if layer_counts else None,
        }


# ── Module-level singleton ─────────────────────────────────────────────────────
_parser = LogParser()


def parse_logs(log_text: str) -> ParseResult:
    return _parser.parse(log_text)


def failures_to_dict(result: ParseResult) -> list:
    return [
        {
            "line_number":    fp.line_number,
            "timestamp":      fp.timestamp,
            "layer":          fp.layer,
            "failure_type":   fp.failure_type,
            "cause":          fp.cause,
            "spec_reference": fp.spec_reference,
            "description":    fp.description,
            "raw_line":       fp.raw_line,
            "severity":       fp.severity,
        }
        for fp in result.failures
    ]
