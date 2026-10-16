# Living-off-the-Land (LotL) Detection Engineering Lab

![SIEM](https://img.shields.io/badge/SIEM-Wazuh_v4.14-blue)
![Telemetry](https://img.shields.io/badge/Telemetry-Sysmon_v15.22-informational)
![OS](https://img.shields.io/badge/Endpoint-Windows_Server_2022-0078D6)
![Rules](https://img.shields.io/badge/Rules-Sigma_%7C_PCRE2-critical)
![License](https://img.shields.io/badge/License-MIT-green)

## 1. Executive Summary
Modern adversaries frequently bypass traditional signature-based antivirus solutions by abusing built-in, digitally signed Windows utilities—a paradigm known as **Living-off-the-Land (LotL / LOLBins)**. 

This project implements a full-lifecycle **Detection Engineering Pipeline**. Using **Sysmon** modular telemetry ingested into **Wazuh**, I emulated multi-stage LotL attacks, extracted raw process and file-system telemetry, engineered high-fidelity custom detection rules in **Wazuh (PCRE2 XML)** and **Sigma (YAML)**, and validated rule resilience against binary masquerading techniques.

![SOC Dashboard](assets/lotl-soc-dashboard.png)

---

## 2. Lab Architecture & Methodology

### Infrastructure Stack
* **SIEM Server / Manager:** Wazuh Manager & OpenSearch Indexer (`v4.14.8`) on Ubuntu 24.04 LTS (`192.168.68.157`)
* **Target Endpoint:** Windows Server 2022 Standard (`WIN-SERVER-2022-JA` / `192.168.68.201`)
* **Endpoint Sensor:** Microsoft Sysinternals Sysmon (`v15.22`) configured with the **SwiftOnSecurity** modular schema (`sysmonconfig-export.xml`)
* **Telemetry Channels Monitored:**
  * `Sysmon Event ID 1`: Process Creation (Full `CommandLine`, `ParentImage`, `Hashes`, `OriginalFileName`)
  * `Sysmon Event ID 11`: FileCreate (Target file creation & NTFS stream modifications)
  * `Wazuh Syscheck`: Real-time File Integrity Monitoring (FIM)

### Detection Engineering Lifecycle
1. **Threat Modeling & Technique Selection:** Scoping dual-use Windows utilities abused for Ingress Tool Transfer (`T1105`) and Defense Evasion (`T1564.004`).
2. **Adversary Emulation & Telemetry Capture:** Executing controlled attack simulations and harvesting raw JSON alerts from `/var/ossec/logs/alerts/alerts.json`.
3. **Detection Rule Engineering:** Elevating low-priority informational events (Level 3) into actionable high-severity incidents (Levels 10–12) using PCRE2 regular expressions.
4. **Evasion Testing:** Attempting detection bypasses via binary renaming (`certutil.exe` $\rightarrow$ `updater.exe`) to verify metadata-level inspection.
5. **Sigma Standardization:** Translating validated logic into vendor-agnostic Sigma rules.

---

## 3. Scenario 1: Ingress Tool Transfer via `certutil.exe` & `bitsadmin.exe` (MITRE T1105)

### Threat Context
`certutil.exe` is a legitimate Windows tool meant for managing certificates. However, attackers abuse its `-urlcache` and `-split` parameters to turn it into a stealthy HTTP download cradle. Similarly, `bitsadmin.exe` is abused to stage malicious payloads via background transfer jobs (`T1197`).

### Adversary Emulation
Executed in an elevated PowerShell session on `WIN-SERVER-2022-JA`:
```powershell
# Technique 1A: Certutil URL Cache Download
certutil.exe -urlcache -split -f "[https://raw.githubusercontent.com/SigmaHQ/sigma/master/README.md](https://raw.githubusercontent.com/SigmaHQ/sigma/master/README.md)" "C:\Tools\certutil_stage1.txt"

# Technique 1B: Bitsadmin Background Transfer Job
bitsadmin.exe /transfer lotl_job /download /priority normal "[https://raw.githubusercontent.com/SigmaHQ/sigma/master/LICENSE.Detection.Rules.md](https://raw.githubusercontent.com/SigmaHQ/sigma/master/LICENSE.Detection.Rules.md)" "C:\Tools\bits_stage2.txt"
