# T1566.002 – Phishing Email with Malicious Link (Yodobashi Impersonation)

> **MITRE ATT&CK:**  
> - Tactic: Initial Access (TA0001)  
> - Technique: T1566 – Phishing  
> - Sub-technique: T1566.002 – Spearphishing Link  

This lab reproduces the workflow of a SOC analyst investigating a suspected phishing email
written in Japanese and impersonating **Yodobashi.com**.  
The goal is to show a full investigation pipeline:

1. Email header & body analysis  
2. Decoding Base64-encoded content with CyberChef  
3. Extracting and analysing the phishing URL  
4. Enriching the domain with VirusTotal, urlscan.io, passive DNS and WHOIS  
5. Mapping the activity to MITRE ATT&CK and documenting IOCs & response actions  

---

## 1. Lab Environment

- **Workstation:** Windows 10
- **Tools used:**
  - Text editor / email viewer (`.eml` file)
  - [CyberChef](https://gchq.github.io/CyberChef/)
  - [VirusTotal](https://www.virustotal.com/)
  - [urlscan.io](https://urlscan.io/)
  - [passivedns.mnemonic.no](https://passivedns.mnemonic.no/)
  - [who.is](https://who.is/)
- **Data source:** Public phishing dataset from [malware-traffic-analysis.net]  
  (Japanese phishing emails – 2025-10-06 collection)

---

## 2. Scenario

A user reports a suspicious email in Japanese that appears to come from **Yodobashi.com**.
The subject mentions account verification and the body claims:

- “Suspicious access detected”
- “Please confirm your account”
- “If you don’t respond in 72 hours, your account may be suspended”

The email contains an HTML body encoded in **Base64** and a large **“Confirm account”** button.

Your task as SOC analyst is to decide whether this is phishing, extract IOCs, and
recommend response actions.

---

## 3. Investigation Steps

### 3.1 Email Header & Metadata

**File:** [`artefacts/2025-09-22-sample-email.eml`](artefacts/2025-09-22-sample-email.eml)

Key points:

- `Return-Path`: `info.ihvosjjm@ztwenqo.cn`
- `From`: encoded Japanese display name, domain `ztwenqo.cn`
- `To`: `admin@malware-traffic-analysis.net`
- `Authentication-Results`:
  - `dmarc=pass` (policy=none)
  - `spf=pass` for `ztwenqo.cn` via `34.84.5.251`
  - `dkim=none`

**Observations**

- Sender domain is **`ztwenqo.cn`**, not an official `yodobashi.com` domain.
- SPF/DMARC passing only means the sender is allowed to use that domain – not that
  the domain is legitimate.
- Message is `multipart/alternative` with both `text/plain` and `text/html`
  bodies encoded in Base64.

---

### 3.2 Decode Base64 Content (CyberChef)

Screenshots:
- [`screenshots/cyberchef-from-base64.png`](screenshots/cyberchef-from-base64.png)

Steps:

1. Copy the Base64 blob from the `text/plain` and `text/html` parts.
2. In CyberChef:
   - Recipe: **`From Base64`**
   - Paste Base64 into *Input* and click **BAKE**.
3. Read the decoded Japanese text.

**Decoded content (summary)**

- Plaintext & HTML say:
  - “Thank you for using our service.”
  - “Suspicious access detected.”
  - “Please confirm your account at the link below.”
  - “If you do not respond within 72 hours, your account may be suspended.”
- HTML body contains a large **CTA button**: “アカウントを確認 (Confirm account)”.

**Social-engineering patterns**

- Urgency and fear: 72-hour deadline, account suspension.
- Security scare: “suspicious access detected”.
- Brand impersonation: Yodobashi branding, Japanese language, customer-service style.

---

### 3.3 Extract the Phishing URL

Screenshot:
- [`screenshots/cyberchef-extract-url.png`](screenshots/cyberchef-extract-url.png)

Steps:

1. In CyberChef, build this recipe:
   - `From Base64`
   - `Extract URLs`
2. Paste the Base64-encoded **HTML** part into the input.
3. Click **BAKE**.

**Resulting URL**

```text
https://fumious.umfqrit.cn/login_index/
This is the main phishing URL linked from the “Confirm account” button.

3.4 URL & Domain Reputation
3.4.1 VirusTotal – URL
Screenshot:

screenshots/virustotal-url-result.png

URL submitted: https://fumious.umfqrit.cn/login_index/

Some engines classify as:

Phishing (Fortinet, etc.)

Malicious / Webroot

Others still Clean or Undetected.

Conclusion: Reputation already trending malicious / phishing.

3.4.2 urlscan.io
Screenshot:

screenshots/urlscan-dns-error.png

Scan result: HTTP 400 – DNS Error (could not resolve domain)

Domain no longer resolves → likely taken offline or never fully deployed.

Conclusion: Infrastructure is currently down, but still indicators are valid.

3.4.3 Passive DNS
Screenshot:

screenshots/passivedns-no-results.png

Query: fumious.umfqrit.cn

Result: No records.

Interpretation: Very new or short-lived subdomain; no historical DNS.

3.4.4 WHOIS – Parent Domain umfqrit.cn
Screenshot:

screenshots/whois-umfqrit-cn.png

Domain umfqrit.cn is registered via a Chinese registrar.

No obvious link to Yodobashi or a legitimate brand.

Likely attacker-controlled disposable domain.

4. MITRE ATT&CK Mapping
Stage	Technique ID	Name
Initial access via email link	T1566.002	Spearphishing Link
User clicking HTML link	T1204.002	User Execution – Malicious Link
Obfuscated email content	T1027	Obfuscated/Encrypted Content
Credential harvesting via fake login page (expected)	T1056.003	Input Capture – Web Forms
Disposable domain for phishing	T1583.001	Acquire Infrastructure – Domains

5. Indicators of Compromise (IOCs)
See: analysis/IOCs.csv

Example entries:

Type	Value	Note
URL	https://fumious.umfqrit.cn/login_index/	Main phishing landing page
Domain	fumious.umfqrit.cn	Malicious subdomain
Domain	umfqrit.cn	Suspicious parent domain
Sender	info.ihvosjjm@ztwenqo.cn	Phishing sender address
IP	34.84.5.251	Mail-sending IP (Google Cloud)

6. SOC Response Playbook
If this email is reported inside a company:

Containment

Block fumious.umfqrit.cn and umfqrit.cn on web proxy/DNS.

Add URL to email security blocklists.

Search mailboxes and remove all emails containing this URL or sender.

Detection & Hunting

Search Proxy / Firewall logs for any traffic to
fumious.umfqrit.cn (HTTP/HTTPS).

Search email gateways for sender *@ztwenqo.cn.

If any user clicked, check:

Authentication logs for unusual logins.

Password reset or account lock events.

User Impact

If users clicked link and entered credentials, force password reset.

Review MFA logs and suspicious sessions for those accounts.

Lessons Learned

Add detections for similar patterns:

Non-corporate .cn domains claiming to be Japanese brands.

Emails with Base64-encoded HTML parts and urgent “account verification”.

7. Files in This Lab
artefacts/2025-09-22-sample-email.eml – raw email used for analysis

artefacts/decoded_body_plaintext.txt – decoded Japanese text body

artefacts/decoded_body_html.txt – decoded HTML body (contains phishing link)

analysis/IOCs.csv – all indicators extracted from the email

analysis/SOC-Report.md – narrative SOC report, written like a real case

screenshots/*.png – visual evidence from each step

8. How This Lab Helps a SOC Analyst
This mini-project demonstrates that you can:

Analyse raw email headers & MIME structure.

Decode and interpret Base64-encoded content.

Extract malicious URLs from HTML.

Use public threat-intel tools to assess domain/URL reputation.

Map findings to MITRE ATT&CK.

Document a clear SOC investigation with IOCs and response actions.

yaml
Copy code

You can shorten or expand any section, but this structure is perfect for recruiters.

---

## 4. `IOCs.csv` template

In `analysis/IOCs.csv`:

```csv
type,value,description,confidence
url,https://fumious.umfqrit.cn/login_index/,Phishing login page,high
domain,fumious.umfqrit.cn,Malicious subdomain,high
domain,umfqrit.cn,Suspicious parent domain,medium
email,info.ihvosjjm@ztwenqo.cn,Phishing sender address,high
ip,34.84.5.251,Mail sending IP (Google Cloud),medium
