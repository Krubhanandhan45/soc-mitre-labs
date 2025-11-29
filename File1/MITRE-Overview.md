# MITRE ATT&CK – Overview (SOC Analyst Guide)

## What is MITRE ATT&CK?
MITRE ATT&CK (Adversarial Tactics, Techniques & Common Knowledge) is a globally used 
cybersecurity framework that documents real-world attacker behaviors.  
SOC Analysts use it to detect, analyze, and respond to threats by mapping alerts 
to specific adversary techniques.

---

##  Why SOC Teams Use MITRE
MITRE helps SOC analysts to:
- Map alerts to tactics & techniques  
- Build threat detection rules in SIEM  
- Create threat-hunting hypotheses  
- Understand attacker behavior patterns  
- Improve incident triage and reporting  
- Build standard SOC Use-Cases  

Example:  
Failed logins → **T1110 (Brute Force)**  
Suspicious PowerShell → **T1059.001 (PowerShell Execution)**  
Phishing email → **T1566.002 (Phishing Link)**

---

##  MITRE ATT&CK Structure
MITRE is organized into:

### **Tactic** → The goal of the attacker (WHY)  
### **Technique** → The method used (HOW)  
### **Sub-technique** → Specific variation (DETAIL)

Example:  
- **Tactic:** Execution  
- **Technique:** T1059 (Command Execution)  
- **Sub-technique:** T1059.001 (PowerShell)

---

##  MITRE Tactics (14 Total)
| Tactic # | Tactic Name | Meaning |
|---------|-------------|---------|
| 1 | Reconnaissance | Collecting information |
| 2 | Resource Development | Preparing infrastructure for attack |
| 3 | Initial Access | Gaining entry into the environment |
| 4 | Execution | Running malicious code |
| 5 | Persistence | Maintaining access |
| 6 | Privilege Escalation | Becoming admin/root |
| 7 | Defense Evasion | Avoiding detection |
| 8 | Credential Access | Stealing passwords |
| 9 | Discovery | Understanding the environment |
| 10 | Lateral Movement | Moving across systems |
| 11 | Collection | Gathering sensitive data |
| 12 | Exfiltration | Sending data out |
| 13 | Command & Control | Attacker communicating with victim |
| 14 | Impact | Destroying/encrypting systems (e.g., ransomware) |

---

##  Common MITRE Techniques in SOC
These techniques appear in real SOC alerts:

- **T1110 – Brute Force**
- **T1059 – Command Execution**
- **T1566 – Phishing**
- **T1021 – Remote Services / Lateral Movement**
- **T1003 – Credential Dumping (Mimikatz)**
- **T1047 – WMI Execution**
- **T1078 – Valid Accounts**
- **T1027 – Defense Evasion (Obfuscation)**

Learning these gives strong SOC L1/L2 knowledge.

---

##  How SOC Uses MITRE ATT&CK Daily
### 1. **Alert Mapping**
Every detection rule is linked to a MITRE technique.

### 2. **Threat Hunting**
Examples:
- Hunt for suspicious PowerShell → T1059  
- Hunt for unusual network connections → T1071  

### 3. **Use-Case Development**
Security engineers build SIEM rules mapped to MITRE.

### 4. **Incident Response**
IR analysts map each step of the attack chain.

### 5. **Reporting**
SOC summaries often include:
- “Mapped to MITRE T1110 (Credential Access)”
- “Technique used: T1566.002 Spearphishing Link”

---

##  Conclusion
MITRE ATT&CK provides a structured way to understand attacker behavior and build effective SOC detections.  
It is essential knowledge for SOC Analysts, Threat Hunters, and Incident Responders.

