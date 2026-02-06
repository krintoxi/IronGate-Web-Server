# 🛡️ IronGate Web Server

**IronGate** is a hardened, self-contained Python 3 web server engineered for hostile or untrusted environments. It combines real-time traffic inspection, adaptive threat scoring, automatic IP bans, forensic logging, and a full-screen Textual TUI dashboard.

This is not a framework. It is an **operational defensive system** intended for direct exposure to the internet.

Developed by **[Krintoxi](https://github.com/krintoxi)**.

---

## 🚀 Key Features

* **Threaded HTTP Engine** – High-concurrency handling with a minimal footprint.
* **Adaptive Threat Scoring** – Dynamic IP reputation system that decays over time.
* **Auto-Ban Engine** – Immediate, persistent blocking of malicious actors.
* **Forensic Logging** – SQLite-backed traffic analysis and per-IP evidence exporting.
* **Live TUI Dashboard** – A full-screen terminal interface for real-time monitoring and operator control.
* **PHP-CGI Sandbox** – Secure execution of PHP scripts via a controlled interface.

---

## 📂 Project Layout

- **server.py**: Main server, defense logic & TUI
- **WWW/**: Web root (served content)
    - **index.html**: Operator guide
    - **index.php**: Optional PHP entrypoint
    - **.htaccess**: Optional access rules
- **logs.db**: SQLite traffic database
- **geoip.mmdb**: MaxMind GeoIP database
- **evidence/**: Exported forensic IP evidence

---

## 🛡️ Security Architecture

### WWW Directory Behavior
* **Strict Isolation:** Only files inside `WWW/` are reachable.
* **Traversal Prevention:** Realpath enforcement prevents `../` attacks.
* **Extension Blacklisting:** Dangerous files (`.py`, `.env`, `.db`, etc.) are blocked by default.
* **Directory Stealth:** Directory listing is disabled; requires `index.html` or `index.php`.

### Threat Scoring & Auto-Bans
Each request is scored based on behavior. Scores decay over time to reduce false positives.

| Event                     | Score |
| :------------------------ | :---- |
| HTTP status ≥ 400         | +1    |
| 404 responses             | +2    |
| Overlong URLs             | +10   |
| Suspicious file probes    | +15   |

**Score ≥ 25 → Automatic IP Ban.** Bans are enforced at the socket level before request processing and persisted in SQLite.

---

## 🛠️ Installation & Setup

### 1. Install Dependencies
`pip install psutil maxminddb textual rich requests`

### 2. Configuration (Optional)
Enable **AbuseIPDB** integration for enhanced threat intelligence:
`export ABUSEIPDB_KEY="your_api_key"`

### 3. Execution
Root privileges are required to bind to port 80. IronGate automatically falls back to port **8080** if 80 is unavailable.
`sudo python3 server.py`

---

## 🎮 TUI Operator Controls

The TUI allows for active defense during a live session:

| Key      | Action                                     |
| :------- | :----------------------------------------- |
| **b** | **Ban** selected IP                        |
| **a** | **AbuseIPDB** lookup                       |
| **s** | **Export** forensic evidence to `evidence/` |
| **DEL** | **Delete** log entry                       |
| **Ctrl+C** | **Shutdown** server                      |

---

## ⚖️ License
Developed by Krintoxi.
*If this page loads, the perimeter is active.*