Phishing is one of the most common and dangerous forms of cyber attack. Attackers craft malicious URLs that look legitimate to trick users into giving up credentials, personal data, or financial information.

This tool automatically inspects any given URL and scores it across **14 security checks**, producing a clear risk verdict: **LOW**, **MEDIUM**, or **HIGH** risk. It is designed as a learning and awareness tool for security interns, students, and anyone wanting to understand what makes a URL suspicious.

---

## ✨ Features

| Feature | Python Version | C Version |
|---|---|---|
| HTTPS / HTTP detection | ✅ | ✅ |
| Raw IP address as host | ✅ | ✅ |
| Suspicious keyword scan | ✅ | ✅ |
| Suspicious TLD detection | ✅ | ✅ |
| URL length analysis | ✅ | ✅ |
| Subdomain depth check | ✅ | ✅ |
| Hyphen in domain name | ✅ | ✅ |
| @ symbol detection | ✅ | ✅ |
| Double-slash redirect | ✅ | ✅ |
| Punycode / homograph attack | ✅ | ✅ |
| Non-standard port | ✅ | ✅ |
| Brand impersonation | ✅ | ✅ |
| SSL certificate validation | ✅ (OpenSSL) | ✅ (OpenSSL) |
| Domain age via WHOIS | ✅ (python-whois) | ✅ (raw TCP) |
| Interactive mode | ✅ | ✅ |
| Batch file mode | ✅ | ✅ |
| JSON export | ✅ | ❌ |
| Cross-platform (Win/Linux/Mac) | ✅ | ✅ |

---

## 🔍 How Each Check Works

### 1. HTTPS Protocol
Checks if the URL uses `https://` (encrypted) vs `http://` (plain text). Legitimate sites, especially those handling login or payment, always use HTTPS.
**Risk: 20 pts if HTTP**

### 2. IP Address as Host
Legitimate websites use domain names (e.g., `paypal.com`), not raw IP addresses (e.g., `192.168.1.1`). Phishing sites often use IPs to avoid domain registration scrutiny.
**Risk: 20 pts**

### 3. Suspicious Keywords
Scans the full URL for words commonly used in phishing URLs: `login`, `verify`, `account`, `secure`, `paypal`, `password`, `urgent`, `suspended`, etc.
**Risk: 10 pts per keyword, capped at 20 pts**

### 4. Suspicious Top-Level Domain (TLD)
Certain TLDs are heavily abused by phishing campaigns due to free or anonymous registration: `.tk`, `.ml`, `.xyz`, `.top`, `.click`, `.work`, etc.
**Risk: 15 pts**

### 5. URL Length
URLs longer than 75 characters are often crafted to hide the real destination or embed encoded payloads. Legitimate URLs are usually concise.
**Risk: 10 pts**

### 6. Subdomain Depth
More than 2 subdomains (e.g., `secure.login.paypal.evil.com`) is a classic trick to make the real malicious domain appear further right in the URL.
**Risk: 10 pts**

### 7. Hyphens in Domain Name
Hyphens in the primary domain (e.g., `pay-pal.com`, `google-secure.com`) are a common phishing indicator. Most legitimate brands do not hyphenate their primary domain.
**Risk: 10 pts**

### 8. @ Symbol in URL
The `@` character in a URL causes browsers to ignore everything before it. For example, `http://google.com@evil.com` actually loads `evil.com`.
**Risk: 15 pts**

### 9. Double-Slash Redirect
A `//` in the URL path (after the scheme) can be used to redirect browsers to a different host entirely, exploiting how some parsers handle paths.
**Risk: 10 pts**

### 10. Punycode / Homograph Attack
Attackers register domains using Unicode characters that look identical to ASCII letters (e.g., Cyrillic `а` vs Latin `a`). These are encoded as `xn--...` in URLs and can fool the human eye entirely.
**Risk: 15 pts**

### 11. Non-Standard Port
Legitimate websites use port 80 (HTTP) or 443 (HTTPS). A URL like `https://bank.com:8080/login` using a non-standard port is suspicious.
**Risk: 10 pts**

### 12. Brand Impersonation
Checks if a well-known brand name (Google, PayPal, Amazon, Apple, etc.) appears in the subdomain or path rather than the actual registered domain. For example, `paypal.login.evil.com` is impersonation.
**Risk: 20 pts**

### 13. SSL Certificate Validation
Connects to the server on port 443 and verifies the SSL certificate using OpenSSL. Checks for invalid, self-signed, or nearly-expired certificates.
**Risk: 15 pts if invalid or expired**

### 14. Domain Age (WHOIS)
Queries WHOIS records to find when the domain was registered. Phishing domains are typically very new — attackers register them, use them briefly, and abandon them. Domains under 6 months old are high risk.
**Risk: 20 pts if < 6 months old, 10 pts if < 12 months old**

---

## 📊 Risk Scoring

| Score | Verdict | Meaning |
|---|---|---|
| 0 – 29 | 🟢 LOW RISK | URL appears relatively safe |
| 30 – 59 | 🟡 MEDIUM RISK | Some suspicious traits — proceed with caution |
| 60+ | 🔴 HIGH RISK | Multiple phishing indicators — do NOT visit |

---

## 🐍 Python Version

### Requirements

```bash
pip install python-whois requests
```

### Usage

```bash
# Interactive mode
python phishing_detector.py

# Single URL
python phishing_detector.py https://suspicious-login.tk

# Batch mode (one URL per line in a .txt file)
python phishing_detector.py --batch urls.txt

# Export result as JSON
python phishing_detector.py https://example.com --json report.json
```

### Sample Output

```
  URL ANALYZED: https://paypal-secure.login.tk/verify/account
  ──────────────────────────────────────────────────────────
  CHECK                               STATUS    RISK PTS
  ──────────────────────────────────────────────────────────
  HTTPS Protocol                      ✅ PASS    +0
  IP Address as Host                  ✅ PASS    +0
  Suspicious Keywords                 ❌ FAIL    +20
  Top-Level Domain (TLD)              ❌ FAIL    +15
  ...

  TOTAL RISK SCORE : 75 / 100+
  VERDICT          : 🔴 HIGH RISK
  RECOMMENDATION   : Do NOT visit this URL.
```

---

## ⚙️ C Version

The C version replicates all 14 checks using only the C standard library and OpenSSL — no Python runtime required. WHOIS queries are performed over raw TCP sockets.

### Dependencies

Only **OpenSSL** is required as an external library.

```bash
# Ubuntu / Debian
sudo apt install libssl-dev build-essential

# macOS (Homebrew)
brew install openssl

# Windows (MSYS2/MinGW)
pacman -S mingw-w64-x86_64-openssl
```

### Compile

```bash
# Linux / macOS
gcc -o phishing_detector phishing_detector.c -lssl -lcrypto

# macOS with Homebrew OpenSSL
gcc -o phishing_detector phishing_detector.c \
    -I$(brew --prefix openssl)/include \
    -L$(brew --prefix openssl)/lib \
    -lssl -lcrypto

# Windows (MinGW)
gcc -o phishing_detector phishing_detector.c -lws2_32 -lssl -lcrypto
```

### Usage

```bash
# Interactive mode
./phishing_detector

# Single URL
./phishing_detector https://suspicious-login.tk

# Batch mode
./phishing_detector --batch urls.txt
```

---

## 📁 Project Structure

```
phishing-awareness-tool/
│
├── phishing_detector.py     # Python implementation (full-featured)
├── phishing_detector.c      # C implementation (no runtime dependencies)
└── README.md                # This file
```

---

## 🧪 Test URLs to Try

```
# These should score HIGH RISK:
http://paypal-secure.login.tk/verify/account
https://192.168.1.1/login
http://google.com@evil.com/signin

# These should score LOW RISK:
https://github.com
https://google.com
https://microsoft.com
```

---

## ⚠️ Limitations

- **WHOIS accuracy**: Some registrars hide domain age behind WHOIS privacy services. In these cases the tool reports the check as unknown.
- **SSL check**: The tool connects to port 443 — if a firewall blocks this, the SSL check is skipped gracefully.
- **Not a blocklist**: This tool uses heuristics and pattern analysis. It does NOT query Google Safe Browsing, VirusTotal, or any threat-intelligence feed. A low score does not guarantee a URL is safe.
- **No JavaScript rendering**: The tool analyzes the URL string itself. It does not browse or execute any web content.

---

## 🚀 Possible Extensions

- Integrate the **VirusTotal API** for reputation-based checking
- Add a **Flask / FastAPI web UI** for the Python version
- Include **Google Safe Browsing API** lookup
- Add **DNS-over-HTTPS** resolution to detect DNS spoofing
- Export reports as **PDF** for documentation purposes

---

## 👨‍💻 Author

Built as a **Cyber Security Intern Project** to demonstrate URL threat analysis concepts including:
- Cryptographic certificate validation (OpenSSL)
- Internet protocol usage (WHOIS over TCP, DNS resolution)
- Heuristic pattern matching for threat detection
- Cross-language implementation (Python & C)

---

## 📄 License

This project is intended for **educational and awareness purposes only**. Do not use it to facilitate any illegal activity. Always obtain proper authorization before testing URLs or systems you do not own.
