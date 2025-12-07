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

