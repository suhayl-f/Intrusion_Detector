# 🛡️ Real-Time SSH Log Intrusion Detection System (HIDS)

A lightweight, zero-dependency Host-Based Intrusion Detection System (HIDS) and micro-SIEM built in **Java 17+**. It monitors Linux SSH authentication logs (`/var/log/auth.log`) in real time, applies stateful behavioral detection rules to identify active cyberattacks, enriches attacker IPs with geolocation and ISP threat intelligence, and exports structured JSON incident reports.

---

## 🚀 Key Features

*   **Real-Time Log Tailing:** Uses `RandomAccessFile` pointer tracking to continuously tail log files (`tail -f` behavior) and gracefully handle log rotation/truncation.
*   **Stateful Threat Detection Engine:** Tracks sliding 60-second time windows per source IP to detect brute-force bursts and post-failure compromises while preventing alert fatigue.
*   **Automated Threat Intelligence Enrichment:** Queries `ip-api.com` via Java's native `HttpClient` (with in-memory caching and RFC 1918 private-IP filtering) to append attacker country and ISP metadata to alerts.
*   **ANSI Color-Coded Console Alerting:** Prioritizes incidents visually by severity (`MEDIUM`, `HIGH`, `CRITICAL`).
*   **Structured SIEM JSON Export:** Automatically serializes triggered incidents into `logs/alerts.json` for downstream ingestion.

---

## 🎯 Detection Rules & MITRE ATT&CK Mapping

| Severity | Detection Rule | Trigger Condition | MITRE ATT&CK Technique |
| :--- | :--- | :--- | :--- |
| **CRITICAL** | **Post-Failure Compromise** | Successful SSH login from an IP with failed attempts in the prior 60s | `T1110` / `T1078` (Valid Accounts) |
| **CRITICAL** | **Direct Root Login** | Any successful SSH authentication directly as `root` | `T1078.003` (Local Accounts) |
| **HIGH** | **SSH Brute-Force Attempt** | 5+ failed login attempts from a single IP within a 60-second window | `T1110.001` (Password Guessing) |
| **MEDIUM** | **Failed Root Probe** | Any failed login attempt targeting the `root` account | `T1110` (Brute Force) |
| **MEDIUM** | **Off-Hours Login Anomaly** | Successful authentication outside business hours (`06:00 – 22:00`) | `T1078` (Valid Accounts) |

---

## 🏗️ Project Architecture

```text
Intrusion_Detector/
├── README.md
├── .gitignore
└── java_files/
    ├── Main.java               # CLI entry point & real-time file tailing loop
    ├── LogParser.java          # Regex-based syslog/sshd parser into structured records
    ├── LogEntry.java           # Immutable Java record representing a parsed SSH event
    ├── ThreatDetector.java     # Stateful detection rules engine & ANSI console alerter
    ├── IpEnricher.java         # HttpClient threat-intel lookup with local caching
    ├── SecurityAlert.java      # Structured incident model & JSON serializer
    ├── SimulateAttacks.sh      # Bash script to simulate normal & malicious SSH traffic
    └── logs/
        └── auth.log            # Sample SSH authentication log
