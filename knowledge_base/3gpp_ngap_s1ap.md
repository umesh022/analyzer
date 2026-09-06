# 3GPP NGAP (TS 38.413) and S1AP (TS 36.413) - Interface Protocols

## NGAP - NG Application Protocol (5G)
Defined in 3GPP TS 38.413. Used between gNB and AMF over NG interface.

## NGAP Failure Causes

### Initial UE Message Failures
- Cause: radioNetwork / unspecified
- Cause: radioNetwork / unknown-local-UE-NGAP-ID
- Cause: radioNetwork / inconsistent-remote-UE-NGAP-ID

### UE Context Release Causes
- radioNetwork / radio-connection-with-ue-lost
- radioNetwork / release-due-to-5gc-generated-reason
- radioNetwork / handover-cancelled
- radioNetwork / partial-handover
- radioNetwork / handover-failure-in-target-5GC-NgRAN-node-or-target-system
- radioNetwork / message-not-compatible-with-receiver-state
- nas / normal-release
- nas / authentication-failure
- nas / deregister
- misc / om-intervention

### Handover Failures (NGAP)
- Specification: TS 38.413 Section 8.4
- HandoverRequired → HandoverCommand → HandoverNotify (success path)
- HandoverPreparationFailure: target AMF/gNB rejected
- HandoverCancelAcknowledge: source cancelled due to T304 expiry
- Cause: targetNotAllowed, noRadioResourcesAvailableInTargetCell

### PDU Session Resource Failures
- PDUSessionResourceSetupFailure
- Cause: radioNetwork / multiple-PDU-session-ID-instances
- Cause: radioNetwork / encryption-and-or-integrity-protection-algorithms-not-supported
- Cause: transport / transport-resource-unavailable

## S1AP - S1 Application Protocol (LTE)
Defined in 3GPP TS 36.413. Used between eNB and MME over S1 interface.

### S1AP Failure Causes
- radioNetwork / unspecified
- radioNetwork / tx2relocOverall-Expiry (Handover T2 timer)
- radioNetwork / successful-handover
- radioNetwork / release-due-to-eutran-generated-reason
- radioNetwork / handover-cancelled
- radioNetwork / partial-handover
- radioNetwork / ho-failure-in-target-EPC-eNB-or-target-system
- radioNetwork / ho-target-not-allowed
- radioNetwork / tS1relocoverall-expiry
- radioNetwork / tS1relocprep-expiry
- radioNetwork / cell-not-available
- radioNetwork / unknown-targetID
- radioNetwork / no-radio-resources-available-in-target-cell
- radioNetwork / unknown-mme-ue-s1ap-id
- nas / detach
- nas / authentication-failure

## Error Log Patterns
- "NGAP: UEContextRelease cause=radio-connection-with-ue-lost" → Radio link failure
- "NGAP: HandoverPreparationFailure cause=targetNotAllowed" → Target gNB rejected HO
- "S1AP: UEContextRelease cause=authentication-failure" → NAS auth failed
- "S1AP: InitialContextSetupFailure" → UE context could not be established
- "NGAP: PDUSessionResourceSetupFailure" → Bearer setup failed at gNB
