# SOC Incident Response Case Study — SOC-IR-001

**Case:** Authorized PowerShell → cmd.exe → whoami.exe simulation on Windows 11 ARM64.  
**Endpoint:** `SOC-WIN11-01` | **SIEM:** Wazuh (`wazuh-siem-01`)  
**Disposition:** Benign, authorized test; no containment or escalation required for this simulated activity.

## Objective
Demonstrate an analyst workflow: verify telemetry, execute an authorized controlled test, triage SIEM alerts, correlate independent logs, reconstruct a UTC timeline, assess severity, and document disposition.

## Observed evidence
- PowerShell Script Block Logging **4104** captured the simulation commands and case marker `SOC-IR-001`.
- Windows Security **4688** logged `cmd.exe` and `whoami.exe` process creation.
- Sysmon **Event ID 1** recorded parent/child process metadata, correlating `powershell.exe → cmd.exe → whoami.exe`.
- Wazuh rules **92004** (PowerShell spawned command shell) and **92032** (suspicious command shell execution) triggered on the test activity; rule **67027** reported Windows process creation.

## Timeline (UTC, 2026-11-24)
| Time | Evidence |
| --- | --- |
| 02:14:48 approx. | PowerShell 4104 captured script block (originally displayed as Nov 23 18:14:48 Pacific time). |
| 02:14:49.039 | Wazuh-received Windows Security 4688 for `cmd.exe`. |
| 02:14:49.043 | Wazuh-received Windows Security 4688 for `whoami.exe`. |
| 02:14:49.069 | Wazuh rule 92004 for `cmd.exe`. |
| 02:14:49.071 | Wazuh rule 92032 for `whoami.exe`. |

**Time-zone note:** The Windows VM initially used Pacific Standard Time (UTC−08:00); it was subsequently configured for Central Standard Time (UTC−06:00). Underlying UTC event times were not changed. All timestamps are from lab screenshots and are approximate where the screenshot provides only whole seconds.

## Analyst assessment
The process chain can merit triage because shell spawning and user discovery occur in both administrative and malicious contexts. In this case, the operator intentionally ran a harmless `echo` and `whoami.exe` test with a unique marker, so the activity is classified as an **authorized simulation**, not evidence of a real compromise. No claim is made that a full forensic review ruled out all other threats.

## Evidence index
| Screenshot | Purpose |
| --- | --- |
| [01 — Windows services](screenshots/01-Windows-Sysmon-Wazuh-Services.png) | Sysmon and Wazuh agent running. |
| [02 — Wazuh server](screenshots/02-Wazuh-Server-Services.png) | Manager, indexer and dashboard active. |
| [03 — Agent connectivity](screenshots/03-Wazuh-Agent-Connected.png) | Endpoint agent active. |
| [04 — Simulation](screenshots/04-Controlled-Incident-Simulation.png) | Authorized commands and resulting output. |
| [05 — Alerts](screenshots/05-Wazuh-Correlated-Alerts.png) | Case marker correlated with Wazuh alerts. |
| [06 — Sysmon](screenshots/06-Sysmon-Process-Chain.jpeg) | Process GUIDs and parent-child chain. |
| [07 — Security 4688](screenshots/07-Windows-Security-4688-Correlation.jpeg) | Independent Windows process telemetry. |
| [08 — PowerShell 4104](screenshots/08-PowerShell-4104-ScriptBlock.png) | Original script block content. |
| [09 — Time zone](screenshots/09-Central-Timezone-Verification.png) | Central time configuration validated. |

## Limitations
This was a controlled exercise, not a real attack. Evidence is screenshot-based, not a forensic image or complete exported EVTX/JSON collection. No containment action was necessary, and absence of malicious behavior beyond the scoped test is not established.
