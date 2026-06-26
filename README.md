# BruteForceRemediation
Investigated and responded to a successful brute-force attack against Azure virtual machines using Microsoft Defender XDR and KQL. Identified compromised systems, performed endpoint containment in MDE, analyzed authentication logs, hardened Azure NSGs, documented findings, and mapped attacker activity to the MITRE ATT&amp;CK framework.



# Brute Force Incident Investigation

## Analysis

<img width="1339" height="469" alt="Screenshot 2026-06-25 at 11 03 32 PM" src="https://github.com/user-attachments/assets/f9befea0-54b9-4511-9aab-07c4f42c86af" />


Investigation identified **six virtual machines** that were targeted by brute-force login attempts originating from **two external IP addresses**.

| Source IP | Device | Action | Failed Logons |
|-----------|--------|--------|--------------:|
| 10.0.0.8 | ann-vm-final-pr | LogonFailed | 82 |
| 10.0.0.8 | vm-final-lab-ba | LogonFailed | 67 |
| 10.0.0.8 | moshvm2 | LogonFailed | 52 |
| 10.0.0.8 | vm-final-lab-co | LogonFailed | 134 |
| 91.92.40.36 | linux-arget-1.p2zfvso05mlezjev3ck4vqd3kd.cx.internal.cloudapp.net | LogonFailed | 62 |
| 10.0.0.8 | em-winserv-2025 | LogonFailed | 57 |

The following Microsoft Defender XDR query was executed:

```kusto
DeviceLogonEvents
| where RemoteIP in ("10.0.0.8", "91.92.40.36")
| where ActionType != "LogonFailed"
```

The investigation confirmed that **IP address 10.0.0.8 successfully authenticated**, indicating a successful compromise.

## Containment

- Isolated affected devices in Microsoft Defender for Endpoint (MDE).
- Ran Microsoft Defender Antivirus scans on the isolated devices.
- Updated the NSG to block RDP access from the public Internet except for a trusted management IP.
- Recommended enforcing this restriction across all virtual machines.
