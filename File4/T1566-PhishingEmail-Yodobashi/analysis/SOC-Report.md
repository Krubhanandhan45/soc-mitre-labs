SOC Analysis Report – T1566.002 Phishing Email (Yodobashi Impersonation)
📌 Summary

A phishing email impersonating Yodobashi.com (ヨドバシカメラ) was received.
The attacker attempted to trick the user into clicking a malicious verification link that leads to a credential-harvesting domain.

This activity maps to:

MITRE ATT&CK Technique: T1566.002 — Phishing: Spearphishing Link

Objective: Credential Theft

📨 Email Header Analysis
Field	Value
From	info.ihvosjjm@ztwenqo.cn

Return-Path	info.ihvosjjm@ztwenqo.cn

Sender IP	34.84.5.251 (Google Cloud)
SPF	Pass (attacker using allowed sending server)
DKIM	None
DMARC	Pass (policy=none → attacker advantage)

Findings:

Domain ztwenqo.cn does not belong to Yodobashi.

Email originates from a cloud provider → common technique for bulk phishing.

DMARC policy = none → no enforcement, attacker exploited this.

🧪 Body Content Analysis

The email contained:

✔ Base64-Encoded Plaintext Section

Decoded message shows urgency and security scare tactics.

✔ Base64-Encoded HTML Section

Contained a fake button:

<a href="https://fumious.umfqrit.cn/login_index/">アカウントを確認</a>


Meaning: “Confirm your account”

This is the phishing URL.

🌐 URL & Domain Analysis
🔗 Phishing URL Extracted
https://fumious.umfqrit.cn/login_index/

VirusTotal Results:

2 vendors flagged as Phishing / Malicious

Hosted on a newly created domain (high risk)

URLScan:

Failed DNS resolution → domain taken offline (common after phishing campaigns)

Passive DNS:

No historical records → newly created domain (highly suspicious)

WHOIS:

Registered under Chinese provider

Recently created

No legitimate business association

🧩 MITRE ATT&CK Mapping
Stage	Technique
Delivery	T1566.002 — Spearphishing Link
Obfuscation	Email body encoded using Base64
Credential Harvesting	Fake login page requesting account verification
📌 Indicators of Compromise (IOCs)

(Also included in IOCs.csv)

Type	Value
Sender	info.ihvosjjm@ztwenqo.cn

Domain	ztwenqo.cn / umfqrit.cn
URL	https://fumious.umfqrit.cn/login_index/

IP	34.84.5.251
🛡️ Recommended SOC Actions
1. Block Indicators

Block domain: umfqrit.cn

Block URL path: /login_index/

Block sender domain: ztwenqo.cn

Block IP: 34.84.5.251

2. User Awareness

Inform targeted users.

Advise not to interact with similar emails.

3. Hunting Queries (SIEM)

Look for:

Emails containing Base64-encoded HTML parts

Subjects with Japanese characters + urgency

URLs with newly registered .cn domains

4. Preventive Controls

Enable strict DMARC (reject) for your org.

Strengthen email filtering rules.

Enable URL sandboxing.

✅ Conclusion

This lab demonstrates a complete SOC workflow:

✔ Email header analysis
✔ Base64 decoding
✔ URL extraction
✔ Domain reputation lookup
✔ IOC documentation
✔ MITRE mapping
✔ SOC remediation steps

This is a full, end-to-end SOC investigation of a phishing campaign impersonating Yodobashi.
