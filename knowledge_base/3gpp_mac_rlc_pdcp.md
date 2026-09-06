# 3GPP MAC / RLC / PDCP Layer Failures - TS 38.321, TS 38.322, TS 38.323

## MAC Layer (TS 38.321)

### RACH Failures
- Specification: TS 38.321 Section 5.1
- Random Access Procedure: Msg1 (preamble) → Msg2 (RAR) → Msg3 (RRCSetupRequest) → Msg4
- Failure: preamble transmission counter = preambleTransMax → RadioLinkFailure declared
- Causes: Poor coverage, PRACH configuration mismatch, congestion
- Log Pattern: "MAC: RACH failure, preamble attempts=preambleTransMax"

### HARQ Failures
- Specification: TS 38.321 Section 5.4
- Maximum HARQ retransmissions exhausted → RLC status PDU / NACK cascade
- Log Pattern: "MAC: HARQ max retransmissions reached, TB discarded"

### BSR and Buffer Stall
- Buffer Status Report not sent or ignored → UE buffer stall
- Log Pattern: "MAC: BSR overflow, SR triggered"

### Scheduling Failures
- No PDCCH grants received for extended period
- Log Pattern: "MAC: No DL grant for > 100ms"

## RLC Layer (TS 38.322)

### RLC AM Failure
- Specification: TS 38.322 Section 5.3
- t-PollRetransmit expiry without ACK → RLC re-establishment or RLF
- maxRetxThreshold reached → triggers RadioLinkFailure
- Log Pattern: "RLC: maxRetxThreshold reached, RLF triggered"

### RLC SDU Discard
- t-Reordering expiry without all segments → SDU discarded
- Log Pattern: "RLC: SDU discarded, t-Reordering expired"

### RLC UM Out-of-Order
- Specification: TS 38.322 Section 5.2
- t-Reassembly expiry → data loss in UM mode
- Log Pattern: "RLC: UM reordering timeout, SN gap detected"

## PDCP Layer (TS 38.323)

### PDCP Integrity Failure
- Specification: TS 38.323 Section 5.9
- MAC-I mismatch on received PDCP PDU
- Triggers: Security key mismatch after handover
- Log Pattern: "PDCP: Integrity verification failed, PDU discarded"

### PDCP Ciphering Error
- Algorithm mismatch or key not applied
- Log Pattern: "PDCP: Deciphering error, SRB/DRB id=X"

### PDCP Discard Timer
- discardTimer expiry before DRB data transmitted → packet loss
- Log Pattern: "PDCP: discardTimer expired, SN=X dropped"

### PDCP ROHC Failure
- Header compression context mismatch after handover
- Log Pattern: "PDCP: ROHC context mismatch, fallback to uncompressed"

## Combined Failure Scenarios
1. RACH failure → No Msg4 received → RRC setup fails → NAS registration fails
2. RLC maxRetxThreshold → RadioLinkFailure → RRC Re-establishment → if fails → Detach
3. PDCP integrity fail after HO → Security key mismatch → RRC release
4. HARQ max retx → MAC failure → RLC SDU discard cascade → Application timeout
