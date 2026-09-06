# 3GPP NAS (Non-Access Stratum) - TS 24.501 (5G) / TS 24.301 (LTE)

## Overview
NAS protocol manages mobility and session management between UE and AMF (5G) / MME (LTE).
Defined in 3GPP TS 24.501 (5GS NAS) and TS 24.301 (EPS NAS).

## NAS 5GMM (5G Mobility Management) Causes

### Registration Failure Causes
- Cause #3: Illegal UE
- Cause #6: Illegal ME
- Cause #7: 5GS services not allowed
- Cause #11: PLMN not allowed
- Cause #12: Tracking area not allowed
- Cause #13: Roaming not allowed in this tracking area
- Cause #15: No suitable cells in tracking area
- Cause #22: Congestion (T3346 timer active)
- Cause #71: ngKSI already in use
- Cause #72: Non-3GPP access to 5GCN not allowed
- Cause #73: Serving network not authorized
- Cause #76: Temporarily not authorized for this SNPN
- Cause #78: LADN not available

### Authentication Failure
- Specification: TS 24.501 Section 5.4.1
- Cause: MAC failure, Synch failure, AMF key mismatch
- Failure Indication: Authentication Failure (cause = MAC failure / synch failure)
- Resolution: Check USIM credentials, AMF/AUSF key sync, sequence number (SQN)

### Security Mode Command Failure
- Specification: TS 24.501 Section 5.4.2
- Cause: UE integrity check failure, replay attack detection
- Failure Message: Security Mode Reject
- Resolution: Check NAS security algorithms, key derivation at AMF

### PDU Session Establishment Failure (5GSM)
- Specification: TS 24.501 Section 6.4.1
- Cause #8: Operator Determined Barring
- Cause #26: Insufficient resources
- Cause #27: Missing or unknown DNN
- Cause #28: Unknown PDU session type
- Cause #29: User authentication or authorization failed
- Cause #38: Network failure
- Cause #39: Reactivation requested
- Cause #43: Invalid QoS rule
- Cause #50: PDU session type IPv4 only allowed
- Cause #51: PDU session type IPv6 only allowed

## NAS EMM (LTE EPS Mobility Management) Causes
- Cause #5: IMEI not accepted
- Cause #11: PLMN not allowed
- Cause #12: Location Area not allowed
- Cause #13: Roaming not allowed
- Cause #14: EPS services not allowed in PLMN
- Cause #15: No suitable cells
- Cause #17: Network failure
- Cause #22: Congestion
- Cause #25: Not authorized for this CSG
- Cause #35: Requested service option not authorized
- Cause #39: CS domain temporarily not available

## Key Timers
- T3510: Registration Request timer (15s default)
- T3511: Re-registration attempt timer
- T3512: Periodic registration timer (54min default)
- T3521: De-registration timer (15s)
- T3346: Congestion back-off timer
- T3396: PDU session back-off timer

## Common Log Patterns
- "NAS: Registration Reject cause=11" → PLMN configuration issue
- "NAS: Authentication Failure MAC failure" → SIM/key mismatch
- "NAS: PDU Session Establishment Failure cause=27" → DNN misconfiguration
- "EMM: Attach Reject cause=17" → Core network failure
