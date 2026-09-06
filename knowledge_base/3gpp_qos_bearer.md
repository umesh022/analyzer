# 3GPP QoS and Bearer Management - TS 23.501, TS 38.401

## 5G QoS Framework (TS 23.501)

### QoS Flows and QFI
- QFI (QoS Flow Identifier): 0-63, maps to SDAP/PDCP DRB
- GBR (Guaranteed Bit Rate) flows: Audio, Video conferencing
- Non-GBR flows: Best-effort data

### 5QI (5G QoS Indicator) Values
- 5QI 1: Conversational Voice (GBR, 100ms PDB)
- 5QI 2: Conversational Video (GBR, 150ms PDB)
- 5QI 3: Real-time Gaming (GBR, 50ms PDB)
- 5QI 4: Non-conversational Video (GBR, 300ms PDB)
- 5QI 5: IMS Signaling (Non-GBR, 100ms PDB)
- 5QI 6: Video TCP (Non-GBR, 300ms PDB)
- 5QI 7: Voice Video Interactive (Non-GBR, 100ms PDB)
- 5QI 8/9: Video TCP buffered (Non-GBR, 300ms PDB)
- 5QI 65: Mission Critical Push-to-Talk (GBR)
- 5QI 69: Mission Critical Video (GBR)
- 5QI 70: Mission Critical Data (GBR)

### QoS Failure Patterns
- "QoS: GBR flow admission failed" → Insufficient radio resources
- "SMF: PDU Session Modification Failure, 5QI not supported" → gNB QoS profile mismatch
- "SDAP: QFI mapping failed" → DRB-QoS mapping configuration error

## LTE Bearer Management (TS 23.401)

### EPS Bearer Types
- Default Bearer: Always-on, established during attach
- Dedicated Bearer: QCI-specific, GBR/Non-GBR

### QCI (QoS Class Identifier) Values
- QCI 1: Conversational Voice (GBR)
- QCI 2: Conversational Video (GBR)
- QCI 3: Real-time Gaming (GBR)
- QCI 4: Non-conversational Video (GBR)
- QCI 5: IMS Signaling (Non-GBR)
- QCI 6: Video TCP (Non-GBR)
- QCI 7: Voice/Video (Non-GBR)
- QCI 8/9: Best Effort (Non-GBR)

### Bearer Failure Patterns
- "E-RAB Setup Failure cause=radioNetwork/no-radio-resources-available" → Congestion
- "E-RAB Release cause=radioNetwork/release-due-to-eutran-generated-reason"
- "Dedicated Bearer Activation Failure cause=26" → Insufficient resources (NAS)
- "Bearer Modification Failure" → QoS renegotiation failed

## UPF/GW Failures
- "UPF: Packet forwarding failure, N3 tunnel not found" → F-TEID mismatch
- "SGW: S1-U bearer not found" → eNB-SGW tunnel lost
- "PGW: IP allocation failure" → IP pool exhausted
- "UPF: N9 interface down" → Core network topology issue
