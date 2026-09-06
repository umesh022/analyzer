# 3GPP Error Codes Quick Reference

## RRC Failure Causes (TS 38.331)
| Code | Meaning | Likely RCA |
|------|---------|-----------|
| t300-Expiry | RRCSetupRequest timeout | gNB overloaded or no coverage |
| t301-Expiry | Re-establishment no response | Context lost at target, T311 short |
| t304-Expiry | Handover execution timeout | Target cell sync failure |
| t310-Expiry | (T310 runs then expires after N310) | Radio link failure, poor SINR |
| radioLinkFailure | Physical layer declared RLF | SINR below threshold, interference |
| handoverFailure | HO procedure did not complete | Cell config mismatch, load |
| otherFailure | Unspecified | Check combined logs |
| reconfigurationFailure | RRC Reconfiguration rejected | UE capability mismatch |

## NAS 5GMM Cause Codes (TS 24.501)
| Cause | Value | Meaning |
|-------|-------|---------|
| Illegal UE | #3 | USIM blocked/invalid |
| Illegal ME | #6 | IMEI barred |
| 5GS not allowed | #7 | Subscription missing |
| PLMN not allowed | #11 | SIM not provisioned for PLMN |
| TA not allowed | #12 | Tracking area restriction |
| Roaming not allowed | #13 | Roaming barred in TA |
| No suitable cells | #15 | Coverage/frequency issue |
| Congestion | #22 | Network overload, T3346 active |
| Auth failure | #20 | MAC/synch failure |

## NAS ESM / 5GSM Cause Codes
| Cause | Value | Meaning |
|-------|-------|---------|
| Operator barring | #8 | Barring list applied |
| Insufficient resources | #26 | No GBR capacity |
| Unknown DNN/APN | #27 | DNN misconfigured |
| Unknown PDU type | #28 | PDU type not supported |
| Auth/authz failed | #29 | UE authentication failed by SMF/PGW |
| Network failure | #38 | SMF/UPF internal error |
| Missing/unknown QoS | #43 | Invalid QoS parameters |

## DIAMETER / GTP Error Codes
| Code | Meaning |
|------|---------|
| GTP Cause 73 | Context Not Found |
| GTP Cause 64 | APN Access Denied |
| GTP Cause 65 | APN Restriction Mismatch |
| GTP Cause 66 | Running Version Not Supported |
| GTP Cause 67 | No Resources Available |
| GTP Cause 68 | UE Not Responding |
| GTP Cause 69 | UE Refuses |
| GTP Cause 70 | Service Denied |
| Diameter 3001 | Realm Not Served |
| Diameter 3002 | Unable To Deliver |
| Diameter 5001 | AVP Unsupported |
| Diameter 5004 | Invalid AVP Value |
| Diameter 5012 | Unable To Comply |

## Common Alarm / Log Keywords for Failure Detection
- "RLF": Radio Link Failure
- "HO_FAIL" / "HandoverFailure": Handover failed
- "AUTH_FAIL" / "Authentication Failure": Auth/security issue
- "ATTACH_REJECT" / "Registration Reject": NAS rejection
- "PDU_FAIL" / "PDU Session Establishment Failure": Bearer/session issue
- "RACH_FAIL": Random access channel failure
- "T310 expired": RLF timer fired
- "maxRetxThreshold": RLC layer failure
- "preambleTransMax": RACH max attempts
- "INTEGRITY_FAIL": PDCP integrity failure
- "CIPHERING_FAIL": PDCP ciphering failure
