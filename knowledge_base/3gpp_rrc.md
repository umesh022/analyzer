# 3GPP RRC (Radio Resource Control) - TS 38.331 / TS 36.331

## Overview
RRC (Radio Resource Control) protocol is defined in 3GPP TS 38.331 (NR) and TS 36.331 (LTE).
It handles connection establishment, mobility, and configuration between UE and gNB/eNB.

## RRC States
- RRC_IDLE: UE not connected, no radio resources allocated
- RRC_INACTIVE (NR only): UE maintains context, reduced signaling
- RRC_CONNECTED: Active data/signaling connection established

## Common RRC Failure Points

### RRC Setup Failure (cause: radioLinkFailure)
- Specification: TS 38.331 Section 5.3.7 (RRC connection re-establishment)
- Trigger: T310 expiry after N310 out-of-sync indications
- Root Cause: Poor radio conditions, interference, UE mobility at cell edge
- Failure Code: RRCSetupFailure / RRCConnectionSetupFailure
- Resolution: Check RSRP/RSRQ thresholds, T310/N310/N311 timer values

### RRC Connection Rejection
- Specification: TS 38.331 Section 5.3.3
- Cause: congestion, waitTime present in RRCReject
- Failure Code: RRCReject with cause = congestion
- Resolution: Check gNB load, admission control config

### RRC Re-establishment Failure
- Specification: TS 38.331 Section 5.3.7
- Causes: shortMAC-I mismatch, no context at target cell, T311 expiry
- Failure Codes: RRCReestablishmentReject
- Resolution: Verify UE context transfer via Xn/X2, check T311 value

### RRC Release with Redirect
- Specification: TS 38.331 Section 5.3.8
- Normal operation but can indicate forced offload
- Contains redirectedCarrierInfo

### MeasurementReport Missing / Late
- Specification: TS 38.331 Section 5.5.5
- Triggers A3/A5 event thresholds not properly configured
- Leads to missed handover, eventual radio link failure

## Key Timers (NR - TS 38.331)
- T300: RRCSetupRequest timeout (default 1000ms)
- T301: RRCReestablishmentRequest timeout (default 1000ms)
- T302: RRCReject waitTime
- T304: Handover execution timer
- T310: Radio link failure detection (default 1000ms)
- T311: Re-establishment search timer (default 1000ms)
- N310: Out-of-sync counter (default 1)
- N311: In-sync counter (default 1)

## Error Codes and Meanings
- cause: unspecified - generic failure
- cause: t300-Expiry - UE did not receive RRCSetup in time
- cause: t301-Expiry - Re-establishment response not received
- cause: t304-Expiry - Handover not completed in time
- cause: radioLinkFailure - Physical layer failure detected
- cause: handoverFailure - Handover procedure failed
- cause: otherFailure - Miscellaneous RRC failure
