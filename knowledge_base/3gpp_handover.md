# 3GPP Handover Procedures - TS 38.300, TS 38.331, TS 38.413

## Intra-gNB Handover
- No NGAP signaling needed
- RRC Reconfiguration with mobilityControlInfo
- Failure: T304 expiry → RRC Re-establishment (cause = handoverFailure)

## Xn-based Inter-gNB Handover (5G)
- Specification: TS 38.300 Section 9.2.3
- Flow: MeasReport → HO Decision → XnAP:HandoverRequest → XnAP:HandoverRequestAck → RRCReconfiguration → XnAP:SN Status Transfer → XnAP:UE Context Release
- Failure Points:
  - XnAP:HandoverPreparationFailure → target rejected
  - T304 expiry at UE → HO execution failed
  - Path switch failure → data forwarding failed

## NG-based Inter-gNB Handover (5G)
- Specification: TS 38.413 Section 8.4
- Flow: NGAP:HandoverRequired → NGAP:HandoverCommand → RRCReconfiguration → NGAP:HandoverNotify
- Failure Points:
  - NGAP:HandoverPreparationFailure (cause in failure message)
  - NGAP:HandoverCancelAcknowledge (T304 expiry or UE failure)
  - AMF cannot find target AMF context

## X2-based Handover (LTE)
- Specification: TS 36.300
- Flow: X2AP:HandoverRequest → X2AP:HandoverRequestAcknowledge → RRCConnectionReconfiguration → X2AP:SNStatusTransfer → X2AP:UEContextRelease
- Failure: X2AP:HandoverPreparationFailure or tRelocPrep expiry

## S1-based Handover (LTE)
- Specification: TS 36.413
- S1AP:HandoverRequired → S1AP:HandoverCommand → RRCConnectionReconfiguration → S1AP:HandoverNotify
- Failure: S1AP:HandoverPreparationFailure, tS1relocOverall expiry

## Common Handover Failure Causes and RCA

### Too-Late Handover (HO too late)
- Symptoms: RLF shortly after RRC Reconfiguration
- Cause: A3 offset too high, TTT too long
- 3GPP Reference: TS 36.331 / TS 38.331 measurement event A3
- RCA: Reduce A3 offset, reduce TTT (Time To Trigger)

### Too-Early Handover (HO too early / ping-pong)
- Symptoms: Re-establishment on source cell shortly after HO
- Cause: A3 offset too low, TTT too short
- RCA: Increase A3 offset, increase TTT

### Wrong Cell Handover
- Symptoms: RLF in target cell, re-establishment on third cell
- Cause: Neighbor list misconfiguration
- RCA: Update ANR (Automatic Neighbor Relations), verify neighbor list

### T304 Expiry
- Timer: T304 (handover execution at UE)
- Cause: UE could not sync to target cell frequency
- RCA: Check target cell configuration, SSB beam alignment, frequency planning

## Measurement Events (TS 38.331 Section 5.5.4)
- A1: Serving cell > threshold (stop measurement)
- A2: Serving cell < threshold (start measurement)  
- A3: Neighbor cell > serving cell + offset
- A4: Neighbor cell > threshold
- A5: Serving cell < threshold1 AND neighbor > threshold2
- A6: Neighbor cell > secondary cell + offset (CA)
- B1: Inter-RAT neighbor > threshold
- B2: Serving < threshold1 AND inter-RAT neighbor > threshold2
