
# Zano-CFLeak

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Version](https://img.shields.io/badge/version-2.1.0-green.svg)]()
[![Platform](https://img.shields.io/badge/platform-linux%20%7C%20macos%20%7C%20windows-lightgrey.svg)]()
[![Tool Type](https://img.shields.io/badge/tool-recon-red.svg)]()
[![Built for](https://img.shields.io/badge/built%20for-pentesting-red.svg)]()

[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)]()
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A reconnaissance tool developed by **Zano Security** to identify real origin IP addresses hidden behind Cloudflare protection by analyzing subdomains, DNS records, and infrastructure misconfigurations.

Designed for **authorized penetration testing**, **OSINT**, and **security research**.

---

## Table of Contents

- [What it does](#what-it-does)
- [Installation](#installation)
- [How to use it](#how-to-use-it)
- [Examples](#examples)
- [Output Formats](#output-formats)
- [Version History](#version-history)
- [Legal Notice](#legal-notice)

---

## What it does

- **IPv4 & IPv6 support** – Resolves both A and AAAA DNS records
- **Multiple IP discovery** – Detects all IPs associated with a domain
- **Cloudflare detection** – Identifies IPs belonging to Cloudflare ranges
- **Progress bar** – Real-time scan progress with live statistics
- **Dynamic Cloudflare ranges** – Fetches latest IP ranges from official Cloudflare endpoints
- **Fast subdomain scanning** – Multi-threaded execution
- **Multiple wordlists** – Combine several wordlists in one scan
- **Wordlist comments support** – Lines starting with `#` are ignored
- **Multiple output formats** – Normal, JSON, YAML, CSV
- **Verbose & quiet modes** – Full control over scan verbosity
- **Origin IP filtering** – Focus on non-Cloudflare backend servers
- **Custom wordlists** – Use your own or the bundled default list
- **Result export** – Save findings to file
- **Rate limiting** – Prevents DNS abuse and blocking
- **Structured reports** – Clear categorized scan results

---

## Installation

### Requirements

- Python 3.8 or higher
- pip (Python package manager)

### Setup

Clone the repository:
```bash
git clone https://github.com/zano-security/Zano-CFLeak.git
cd Zano-CFLeak
````

Create a virtual environment and install dependencies:

**Linux / macOS**

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**Windows**

```powershell
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
```

> [!TIP]
> Using a virtual environment is highly recommended to avoid dependency conflicts.

---

## How to use it

Basic scan:

```bash
python3 zanocfleak.py example.com
```

Full scan with options:

```bash
python3 zanocfleak.py example.com -w wordlist1.txt -w wordlist2.txt -t 20 -o report.json -f json
```

### Options

| Option           | Description                                  |
| ---------------- | -------------------------------------------- |
| `<domain>`       | Target domain (e.g. example.com)             |
| `-w, --wordlist` | Wordlist file(s), can be used multiple times |
| `-t, --threads`  | Number of threads (default: 10)              |
| `-o, --output`   | Output file path                             |
| `-f, --format`   | Output format: normal, json, yaml, csv       |
| `-v, --verbose`  | Show all scan results                        |
| `-q, --quiet`    | Only show confirmed origin IPs               |

---

## Examples

**Basic scan**

```bash
python3 zanocfleak.py example.com
```

**Multiple wordlists + JSON output**

```bash
python3 zanocfleak.py example.com -w subs1.txt -w subs2.txt -o report.json -f json
```

**Fast scan**

```bash
python3 zanocfleak.py example.com -t 50 -o results.csv -f csv
```

**Verbose mode**

```bash
python3 zanocfleak.py example.com -v
```

**Quiet mode**

```bash
python3 zanocfleak.py example.com -q -o found.txt
```

---

## Output Formats

### Normal (default)

```
Zano-CFLeak Scan Report
============================================================
Target: example.com
Date: 2025-11-28T12:00:00+00:00
Total checked: 150

[FOUND] Origin IPs:
  mail.example.com
    v4:[192.168.1.1, 192.168.1.2]

[CLOUDFLARE] Protected:
  www.example.com
    v4:[104.16.1.1 [CF]] | v6:[2606:4700::1 [CF]]
```

### JSON

```json
{
  "target_domain": "example.com",
  "scan_date": "2025-12-28T12:00:00+00:00",
  "summary": {
    "found": 3,
    "cloudflare": 5,
    "not_found": 142,
    "errors": 0
  }
}
```

### CSV

```csv
domain,ipv4,ipv4_cloudflare,ipv6,ipv6_cloudflare,status
mail.example.com,192.168.1.1;192.168.1.2,,,,found
www.example.com,104.16.1.1,104.16.1.1,2606:4700::1,2606:4700::1,cloudflare
```

---

## Version History

See `CHANGELOG.md` for full version history and release notes.

---
## 👋 About TechTalent

**Zano-CFLeak** is developed and maintained by **:contentReference[oaicite:0]{index=0}** —  
a specialized Iraqi tech brand focused on **Cybersecurity, Ethical Hacking, Software Development, and Practical Technical Training**.

We have trained **12,000+ students** across Iraq and the region through:
- Online & in-person technical courses
- Hands-on cybersecurity bootcamps
- Professional penetration testing and security consulting services

### 🌍 Our Platforms & Community
- 📌 **Instagram / LinkedIn:** Educational cybersecurity content & real-world case studies  
- 📌 **Telegram Group & Channel:**  
  - Daily tips & tools  
  - Cybersecurity discussions  
  - Job opportunities & announcements  
  - Updates about courses and projects  

> Join our Telegram community to stay updated and connect with learners and professionals in cybersecurity.

### 🎯 Our Mission
To build a strong, practical, and ethical cybersecurity community by delivering **real skills**, **real tools**, and **real experience** — not just theory.

---

## Legal Notice

> [!WARNING]
> **AUTHORIZED TESTING ONLY**

Zano-CFLeak must only be used on systems you own or have explicit written permission to test.

Unauthorized scanning may violate local and international laws including (but not limited to):

* CFAA (USA)
* Computer Misuse Act (UK)
* Local cybercrime regulations

**The author assumes no responsibility for misuse.**
You are solely responsible for compliance with all applicable laws.

---

<div align="center">

**Developed by Zano Security**

</div>
