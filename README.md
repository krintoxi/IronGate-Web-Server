# 🛡️ IronGate Web Server
<pre><code>
██╗██████╗  ██████╗ ███╗   ██╗ ██████╗  █████╗ ████████╗███████╗
██║██╔══██╗██╔═══██╗████╗  ██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝
██║██████╔╝██║   ██║██╔██╗ ██║██║  ███╗███████║   ██║   █████╗  
██║██╔══██╗██║   ██║██║╚██╗██║██║   ██║██╔══██║   ██║   ██╔══╝  
██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝██║  ██║   ██║   ███████╗
╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝

        ACTIVE DEFENSIVE PERIMETER
        UNAUTHORIZED ACTIVITY LOGGED
        ADAPTIVE THREAT RESPONSE ENABLED
</code></pre>


**IronGate** is a hardened, self-contained Python 3 web server engineered for hostile or untrusted environments. It combines real-time traffic inspection, adaptive threat scoring, automatic IP bans, forensic logging, and a full-screen Textual TUI dashboard.

This is **not a framework**.  
This is an **operational defensive perimeter** intended for **direct internet exposure**.

Developed by **[Krintoxi](https://github.com/krintoxi)**.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Docker](https://img.shields.io/badge/docker-supported-2496ED)
![Platform](https://img.shields.io/badge/platform-linux-critical)
![Status](https://img.shields.io/badge/status-active_defense-red)
![License](https://img.shields.io/badge/license-proprietary-black)
---

## 🚀 Capabilities

- **Threaded HTTP Engine**  
  High-concurrency request handling with a minimal attack surface

- **Adaptive Threat Scoring**  
  Behavior-based IP reputation with time-decay to mitigate false positives

- **Automated Ban Enforcement**  
  Persistent IP bans enforced *before* request processing

- **Forensic Traffic Logging**  
  SQLite-backed request capture with per-IP evidence export

- **Live Operator TUI**  
  Full-screen terminal dashboard for monitoring, triage, and response

- **PHP-CGI Containment**  
  Controlled execution of PHP scripts through a hardened interface

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
Scores decay by 1 point every 10 seconds to reduce false positives.

| Event                     | Score |
| :------------------------ | :---- |
| HTTP status ≥ 400         | +1    |
| 404 responses             | +2    |
| Overlong URLs             | +10   |
| Suspicious file probes    | +15   |

**Score ≥ 25 → Automatic IP Ban.** Bans are enforced at the socket level before request processing and persisted in SQLite.

# 🚀 Quick Start Installation (Recommended) (Docker)

The fastest way to deploy the perimeter without messing with local dependencies.

#### 1. Build the Image by opening terminal inside of project folder and running:

<code>*docker build -t irongate .*</code>

#### 2. Run the Server

This maps port 8080 on your machine to port 80 inside the container.

<code>docker run -it -p 8080:80 irongate</code>

#### TIP: Cloudflare Users: Point your tunnel to 127.0.0.1:8080. Docker handles the internal translation to Port 80 for you.
---

## 🛠️ Manual Installation (No Docker)

### 1. Install Dependencies
`pip install psutil maxminddb textual rich requests --break-system-packages`

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