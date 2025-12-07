🛡️ T1003 – Credential Dumping (LSASS Access Detection)
📌 1. Overview

MITRE ATT&CK Technique:
T1003 – Credential Dumping
Sub-technique: T1003.001 – LSASS Memory

In this lab, we simulate an attacker attempting to access the LSASS.exe process memory to dump credentials.
This type of activity is commonly performed using tools like:

Mimikatz

ProcDump

comsvcs.dll MiniDump API

Process Hacker

Task Manager (Run As SYSTEM)

The goal is to detect this attack using Sysmon (Event ID 10) and create detections in Splunk.

🖥️ 2. Lab Environment
Component	Version / Info
Windows OS	Windows 10 / Windows 11
Sysmon	v15.15 (installed & configured)
Sysmon Config	SwiftOnSecurity + custom Event ID 10 rule
Splunk	Installed on WSL Ubuntu
Attack Simulation	ProcDump-like LSASS access test
⚔️ 3. Attack Simulation
🔹 3.1 — Baseline Check (LSASS Process Info)

Command used:

Get-Process lsass | Format-List *


✔ Confirms LSASS is running
✔ Shows Process ID (PID)
✔ Used later to validate access attempts

🔹 3.2 — Simulate Credential Dump Attempt

We simulate LSASS memory access using Windows built-in MiniDump API:

rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump lsass.exe C:\lsass.dmp full


If access is blocked, Windows returns:

Access is denied.


🔹 Even if the dump fails, Sysmon logs the access attempt, which is what SOC teams detect.

📊 4. Sysmon Logs (Event ID 10 – ProcessAccess)
➤ What Event ID 10 means

Sysmon logs when one process accesses the memory of another process, which is exactly what credential dumping tools do.

➤ What we checked in Event Viewer

Path:

Event Viewer  
→ Applications and Services Logs  
→ Microsoft  
→ Windows  
→ Sysmon  
→ Operational  
→ Event ID 10

✔ Key fields in LSASS access events:
Field	Meaning
SourceImage	The process trying to access LSASS
TargetImage	Should be C:\Windows\System32\lsass.exe
GrantedAccess	Value like 0x1010, 0x1FFFFF indicates sensitive access
CallTrace	Shows loaded DLLs, often reveals dumping tools

Screenshots include:

Event ID 10 triggered

LSASS as target process

ProcessAccess details

Rundll32.exe attempt

🔍 5. Splunk Detections (SPL Queries)
✔ Query 1 — Detect LSASS Access
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| table _time, Image, TargetImage, GrantedAccess, CallTrace, ProcessId, TargetProcessId

✔ Query 2 — Suspicious Access Rights (Credential Dumping Behavior)
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| where GrantedAccess=="0x1010" OR GrantedAccess=="0x1FFFFF"
| table _time, Image, GrantedAccess, TargetImage

✔ Query 3 — Flag well-known dumping tools
index=sysmon EventCode=10 TargetImage="*lsass.exe"
| search Image="*rundll32.exe" OR Image="*procdump.exe" OR Image="*mimikatz.exe"
| table _time, Image, TargetImage, GrantedAccess, CallTrace

🚨 6. SOC Playbook (How Analysts Should Triage)
🔹 Step 1 — Validate LSASS Access

Check if the process is trusted (rundll32.exe vs unknown EXE)

Confirm path is legitimate

Look at GrantedAccess value

🔹 Step 2 — Check CallTrace

Loaded DLLs reveal intent:

comsvcs.dll → MiniDump

dbghelp.dll → ProcDump

abnormal DLLs → malware

🔹 Step 3 — Search for Related Events

Event ID 1 (Process Creation)

Event ID 7 (Image Load)

Event ID 3 (Network Connections)

🔹 Step 4 — Investigate LSASS Dump File

Check if file exists:

C:\lsass.dmp

🔹 Step 5 — Containment (If malicious)

☑ Disable account
☑ Isolate host
☑ Revoke tokens
☑ Reset passwords
☑ Scan memory/disk

📁 7. Files in This Folder
File	Description
README.md	Full MITRE ATT&CK documentation
screenshots/	Event ID 10, commands, LSASS metadata
lsass_dump_attempt.png	Credential dump simulation
sysmon_event10.png	LSASS access detection
