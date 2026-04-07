#  NetSentinel — AI-Powered Network Vulnerability Scanner

<div align="center">

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?style=for-the-badge&logo=python)
![Scikit-Learn](https://img.shields.io/badge/ML-scikit--learn-orange?style=for-the-badge&logo=scikitlearn)
![Nmap](https://img.shields.io/badge/Scanner-Nmap-green?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-purple?style=for-the-badge)

**An intelligent network vulnerability scanner that combines Nmap with Machine Learning to detect risks, classify threat levels, and identify anomalous host behavior.**

</div>

---

##  What is NetSentinel?

NetSentinel is a **pentesting tool** that goes beyond traditional port scanning. It uses **AI/ML models** to:

-  **Scan** open ports and enumerate services (via Nmap)
-  **Classify** risk level (LOW / MEDIUM / HIGH) using a **Random Forest classifier**
-  **Detect anomalies** in port profiles using **Isolation Forest** (unsupervised ML)
-  **Generate** beautiful HTML + JSON vulnerability reports
-  **Display** rich, color-coded terminal output

---

##  AI/ML Architecture

| Component | Algorithm | Purpose |
|-----------|-----------|---------|
| **Risk Classifier** | Random Forest (100 trees) | Classifies host risk: LOW / MEDIUM / HIGH |
| **Anomaly Detector** | Isolation Forest | Flags unusual port combinations vs normal baseline |
| **Feature Engineering** | Custom | Extracts 6 features from scan data |

### Feature Vector
```
[num_open_ports, has_critical_ports, has_db_ports, has_remote_access, has_legacy_services, risk_score]
```

### Why Isolation Forest?
Traditional scanners just look up known bad ports. NetSentinel goes further — it learns what a **normal server profile** looks like and flags anything statistically unusual, even if individual ports seem fine.

---

##  Quick Start

### Prerequisites
- Python 3.9+
- **Nmap** installed on your system
  - Linux: `sudo apt install nmap`
  - Mac: `brew install nmap`
  - Windows: [nmap.org/download](https://nmap.org/download.html)

### Installation

```bash
git clone https://github.com/yourusername/NetSentinel.git
cd NetSentinel
pip install -r requirements.txt
```

### Usage

```bash
# Basic scan (ports 1-1024)
sudo python main.py --target 192.168.1.1

# Full port scan
sudo python main.py --target 192.168.1.1 --ports 1-65535

# Aggressive scan (OS + version detection)
sudo python main.py --target 192.168.1.0/24 --type aggressive

# Custom output directory
sudo python main.py --target scanme.nmap.org --output results/
```

>  **Note:** `sudo` is required for SYN scanning. Run as admin on Windows.

---

##  Sample Output

### Terminal (Rich CLI)
```
 NetSentinel v1.0

  ✓ Random Forest (100 estimators) loaded
  ✓ Isolation Forest loaded
  ✓ Trained on 21 samples

  Scanning 192.168.1.1 (ports 1-1024)...

─────────────── 192.168.1.1 · router.local ───────────────
  Risk Level: HIGH  |  AI Confidence: 87.5%  |  OS: Linux 4.x

  Port      Service    Version      Risk     Reason
  ──────────────────────────────────────────────────────
  22/tcp    ssh        OpenSSH 8.2  MEDIUM   Brute force target
  23/tcp    telnet     —            CRITICAL Plaintext protocol
  3306/tcp  mysql      MySQL 5.7    HIGH     Direct DB exposure

   AI Analysis:
   • Found 3 open port(s) with a total risk score of 9.
   •   Critical services detected (Telnet)
   •   Database ports are publicly exposed.
   •  Legacy/insecure protocols detected (Telnet).
```

### HTML Report
A styled, dark-themed HTML report is generated in your output directory with:
- Full host summary with risk badges
- Per-port risk breakdown table
- AI analysis explanation
- Top threat list
- Anomaly detection status

---

##  Project Structure

```
NetSentinel/
├── main.py               # CLI entry point
├── requirements.txt
├── scanner/
│   └── scanner.py        # Nmap wrapper + feature extraction
├── ml/
│   └── model.py          # Random Forest + Isolation Forest
├── report/
│   └── report.py         # HTML & JSON report generator
└── README.md
```

---

##  Configuration

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | Required | IP, hostname, or CIDR |
| `--ports` | `1-1024` | Port range to scan |
| `--type` | `basic` | `basic` or `aggressive` |
| `--output` | `output/` | Report output directory |

---

## 🔬 Extending NetSentinel

### Adding Custom Risk Rules
Edit `KNOWN_RISKY_PORTS` in `scanner/scanner.py`:
```python
8888: {"service": "Jupyter", "risk": "CRITICAL", "reason": "Unauthenticated RCE via notebooks"},
```

### Retraining the ML Model
Add samples to `TRAINING_DATA` and `TRAINING_LABELS` in `ml/model.py` — the model retrains on each run.

### Adding More Features
Extend `get_feature_vector()` in `scanner.py` and update `FEATURE_NAMES` in `model.py`.

---

##  Legal Disclaimer

> **NetSentinel is for authorized security testing only.**
> 
> Only use this tool on:
> - Networks you own
> - Systems you have **explicit written permission** to test
> 
> Unauthorized port scanning may be **illegal** in your jurisdiction. The author assumes **no liability** for misuse.

---

##  License

MIT License — see [LICENSE](LICENSE) for details.

---

##  Contributing

PRs welcome! Ideas for contribution:
- CVE integration (match service versions to known CVEs)
- Export to PDF
- Web UI / Flask dashboard
- Integration with Shodan API
- More ML features (banner grabbing NLP)

---

<div align="center">

**Made with ❤️ and Python · Pentesting Domain · AI/ML Integration**

</div>
