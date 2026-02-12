#!/usr/bin/env python3
import os
import re
import mimetypes
import subprocess
import shutil
import sys
import time
import threading
import sqlite3
import random
import secrets
import csv
import math
from collections import Counter, deque, defaultdict
from datetime import datetime

# --- Dependency Checker ---
MISSING_LIBS = []
try: import psutil
except ImportError: MISSING_LIBS.append("psutil")
try: import maxminddb
except ImportError: MISSING_LIBS.append("maxminddb")
try: import requests  
except ImportError: MISSING_LIBS.append("requests")
try:
    from rich.text import Text
    from textual.app import App, ComposeResult
    from textual.containers import Container, Vertical, Horizontal, Grid
    from textual.widgets import Footer, Static, Input, RichLog, TabbedContent, TabPane, DataTable, Button, Label
    from textual.binding import Binding
except ImportError: MISSING_LIBS.append("textual")

if MISSING_LIBS:
    print(f"\n[!] Missing Dependencies. Run: pip install {' '.join(MISSING_LIBS)}")
    sys.exit(1)

from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn

# --- Configuration ---
PORT = 80
PROJECT_ROOT = os.path.abspath(os.path.dirname(__file__))
SITE_ROOT = os.path.join(PROJECT_ROOT, "WWW")
PHP_CGI = shutil.which("php-cgi") or "/usr/bin/php-cgi"
MMDB_PATH = os.path.join(PROJECT_ROOT, "geoip.mmdb")
DB_PATH = os.path.join(PROJECT_ROOT, "logs.db")
EVIDENCE_DIR = os.path.join(PROJECT_ROOT, "evidence")
HTACCESS_PATH = os.path.join(SITE_ROOT, ".htaccess")

# API Key
ABUSEIPDB_KEY = "paste-your-key-here"

# --- Security & UI Assets ---
FORBIDDEN_EXT = {".py", ".conf", ".sql", ".sqlite", ".db", ".log", ".env", ".bak", ".ini", ".htaccess"}
FORBIDDEN_FILES = {"server.py", "vhosts.conf", "composer.json", "Dockerfile", "docker-compose.yml"}
SPARK_CHARS = " ▂▃▄▅▆▇█"

# --- Stats & Global State ---
stats = {"requests": 0, "php_hits": 0, "last_origin": "N/A", "rps": 0}
log_buffer = deque(maxlen=2000) 
req_timestamps = []
ip_counter = Counter()
ip_scores = defaultdict(int)
spark_cpu = deque(maxlen=15)
spark_rps = deque(maxlen=15)
paused = False 
alert_trigger = False 

system_stats = {
    "cpu": 0.0,
    "ram": 0.0,
    "disk": 0.0,
    "rps": 0
}

# --- GeoIP Loader ---
try:
    geo_reader = maxminddb.open_database(MMDB_PATH)
    print(f"✅ GEOIP DATABASE LOADED: {MMDB_PATH}")
except Exception as e:
    print(f"⚠️ GEOIP ERROR: {e}")
    geo_reader = None

# --- Helper Functions ---

def sparkline(values, max_val=100):
    if not values: return ""
    safe_values = list(values) 
    out = ""
    for v in safe_values:
        idx = int((v / (max_val or 1)) * (len(SPARK_CHARS) - 1))
        out += SPARK_CHARS[min(max(0, idx), len(SPARK_CHARS) - 1)]
    return out

def get_geo_country(ip):
    """Helper to get full country name from IP"""
    if ip in ("127.0.0.1", "::1") or ip.startswith("192.168."): return "LOCAL"
    if not geo_reader: return "N/A"
    try:
        res = geo_reader.get(ip)
        if res: return res.get("country", {}).get("names", {}).get("en", "Unknown").upper()
    except: pass
    return "Unknown"

def score_request(ip, status, path, query=""):
    full_url = (path + query).lower()
    
    if path.strip("/") in ["favicon.ico", "robots.txt", "sitemap.xml", "manifest.json"]:
        return 0

    score = 0
    
    if status == 404:
        if path.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.ttf')): 
            return 0 
        if path.endswith(('.zip', '.tar', '.gz', '.log', '.sql', '.bak', '.old', '.env', '.config')):
            return 40 
        score += 5 
        
    elif status == 403:
        score += 25 
        
    elif status >= 500:
        score += 0 
    
    # SQLi & XSS Detection
    attack_pattern = re.compile(
        r"union\s+select|' OR '1'='1|waitfor\s+delay|;.*drop\s+table|"
        r"<script|javascript:|onerror=|onload=|eval\(|"
        r"\.\./\.\./|/etc/passwd|/boot.ini|C:\\Windows|"
        r"cmd=|exec=|system\(|shell_exec",
        re.IGNORECASE
    )

    if attack_pattern.search(full_url):
        return 100 

    if re.search(r"\.env|wp-config|\.git|\.bak|\.sql|/admin/|/phpmyadmin/", path, re.I): 
        score += 50 
        
    return score

def export_ip_evidence(ip):
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute("SELECT ts, method, path, status, ua FROM access_logs WHERE ip=?", (ip,)).fetchall()
        conn.close()
        os.makedirs(EVIDENCE_DIR, exist_ok=True)
        fname = f"{EVIDENCE_DIR}/{ip.replace(':', '_')}.txt"
        with open(fname, "w") as f:
            f.write(f"--- DETAILED EVIDENCE LOG: {ip} ---\n")
            for r in rows: f.write(f"[{r[0]}] {r[1]} {r[2]} {r[3]} UA:{r[4]}\n")
        return fname
    except: return "Error"

def abuseipdb_check(ip):
    if not ABUSEIPDB_KEY: return None
    try:
        r = requests.get("https://api.abuseipdb.com/api/v2/check", 
                         params={"ipAddress": ip, "maxAgeInDays": 90},
                         headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"}, timeout=5)
        return r.json().get("data")
    except Exception as e:
        return None

# --- Database Manager ---
def init_db():
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("PRAGMA journal_mode=WAL;") 
        c = conn.cursor()
        
        c.execute("""CREATE TABLE IF NOT EXISTS access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT, req_hex TEXT, ts TEXT, ip TEXT, 
            country TEXT, domain TEXT, path TEXT, status INTEGER, method TEXT, 
            ms REAL, ua TEXT, ref TEXT, hit_count INTEGER
        )""")
        
        c.execute("CREATE TABLE IF NOT EXISTS ip_bans (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE, reason TEXT, banned_at TEXT, country TEXT DEFAULT '??')")
        
        # --- MIGRATIONS ---
        c.execute("PRAGMA table_info(access_logs)")
        cols = [info[1] for info in c.fetchall()]
        
        if "country" not in cols:
            print(">> MIGRATING DB: Adding 'country' to access_logs...")
            c.execute("ALTER TABLE access_logs ADD COLUMN country TEXT DEFAULT '??'")
            
        if "ua" not in cols: c.execute("ALTER TABLE access_logs ADD COLUMN ua TEXT DEFAULT '-'")
        if "ref" not in cols: c.execute("ALTER TABLE access_logs ADD COLUMN ref TEXT DEFAULT '-'")
        if "req_hex" not in cols: c.execute("ALTER TABLE access_logs ADD COLUMN req_hex TEXT DEFAULT '0000'")
        if "hit_count" not in cols: c.execute("ALTER TABLE access_logs ADD COLUMN hit_count INTEGER DEFAULT 1")
        
        c.execute("PRAGMA table_info(ip_bans)")
        ban_cols = [info[1] for info in c.fetchall()]
        if "country" not in ban_cols: 
            print(">> MIGRATING DB: Adding 'country' to ip_bans...")
            c.execute("ALTER TABLE ip_bans ADD COLUMN country TEXT DEFAULT '??'")

        conn.commit()
        conn.close()
    except Exception as e: 
        print(f"[DB INIT ERROR] {e}")

def retro_fill_countries():
    if not geo_reader: return
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute("SELECT DISTINCT ip FROM access_logs WHERE country IN ('??', 'N/A', 'Unknown', '') OR country IS NULL")
        ips_to_fix = c.fetchall()
        count = 0
        for (ip,) in ips_to_fix:
            cn = get_geo_country(ip)
            if cn not in ("N/A", "Unknown"):
                c.execute("UPDATE access_logs SET country=? WHERE ip=?", (cn, ip))
                count += 1
        
        c.execute("SELECT ip FROM ip_bans WHERE country IN ('??', 'N/A', 'Unknown', '') OR country IS NULL")
        bans_to_fix = c.fetchall()
        for (ip,) in bans_to_fix:
            cn = get_geo_country(ip)
            if cn not in ("N/A", "Unknown"):
                c.execute("UPDATE ip_bans SET country=? WHERE ip=?", (cn, ip))
                count += 1

        if count > 0:
            print(f"✅ DB REPAIR: Auto-filled countries for {count} records.")
            conn.commit()
        conn.close()
    except Exception as e:
        print(f"[BACKFILL ERROR] {e}")

def is_banned(ip):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=1)
        c = conn.cursor()
        c.execute("SELECT 1 FROM ip_bans WHERE ip=?", (ip,))
        r = c.fetchone()
        conn.close()
        return bool(r)
    except: return False

def ban_ip_db(ip, reason="Admin Tool", country="??"):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if country in ("??", "N/A"): country = get_geo_country(ip)
        c.execute("INSERT OR REPLACE INTO ip_bans (ip, reason, banned_at, country) VALUES (?,?,?,?)", 
                  (ip, reason, datetime.now().isoformat(), country))
        conn.commit()
        conn.close()
        return True
    except: return False

def unban_ip_db(ip):
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.execute("DELETE FROM ip_bans WHERE ip=?", (ip,))
        conn.commit()
        conn.close()
        if ip in ip_scores: ip_scores[ip] = 0
        return True
    except: return False

def fetch_bans():
    try:
        conn = sqlite3.connect(DB_PATH)
        rows = conn.execute("SELECT ip, country, reason, banned_at FROM ip_bans ORDER BY banned_at DESC").fetchall()
        conn.close()
        return rows
    except: return []

def log_request_db(req_hex, ts, ip, country, domain, path, status, method, ms, ua, ref):
    try:
        conn = sqlite3.connect(DB_PATH, timeout=5)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM access_logs WHERE ip=?", (ip,))
        row = c.fetchone()
        hit_count = (row[0] + 1) if row else 1
        
        c.execute("""INSERT INTO access_logs 
            (req_hex, ts, ip, country, domain, path, status, method, ms, ua, ref, hit_count) 
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""", 
            (req_hex, ts, ip, country, domain, path, status, method, ms, ua, ref, hit_count))
        conn.commit()
        conn.close()
    except: pass

def fetch_logs_paginated(page=1, page_size=50, filter_ip=None, filter_status=None, filter_geo=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        where_clause = "1=1"
        params = []
        if filter_ip:
            where_clause += " AND ip LIKE ?"
            params.append(f"%{filter_ip}%")
        if filter_status:
            where_clause += " AND status = ?"
            params.append(filter_status)
        if filter_geo:
            where_clause += " AND country LIKE ?"
            params.append(f"%{filter_geo}%")
        
        c.execute(f"SELECT COUNT(*) FROM access_logs WHERE {where_clause}", params)
        total_records = c.fetchone()[0]
        offset = (page - 1) * page_size
        query = f"SELECT id, req_hex, ts, ip, method, status, path, country, ua FROM access_logs WHERE {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([page_size, offset])
        c.execute(query, params)
        rows = c.fetchall()
        conn.close()
        return rows, total_records
    except: return [], 0

def delete_logs_db(filter_ip=None, filter_status=None, delete_id=None):
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        if delete_id: c.execute("DELETE FROM access_logs WHERE id = ?", (delete_id,))
        elif filter_ip: c.execute("DELETE FROM access_logs WHERE ip = ?", (filter_ip,))
        elif filter_status: c.execute("DELETE FROM access_logs WHERE status = ?", (filter_status,))
        else: return 0 
        count = c.rowcount
        conn.commit()
        conn.close()
        return count
    except: return 0

init_db()
retro_fill_countries()

# --- System Stats Sampler ---
def system_stats_sampler():
    global system_stats, req_timestamps
    decay_timer = 0
    while True:
        try:
            system_stats["cpu"] = psutil.cpu_percent(interval=None)
            system_stats["ram"] = psutil.virtual_memory().percent
            system_stats["disk"] = psutil.disk_usage("/").percent
            now = time.time()
            req_timestamps[:] = [t for t in req_timestamps if now - t <= 1]
            system_stats["rps"] = len(req_timestamps)
            spark_cpu.append(system_stats["cpu"])
            spark_rps.append(system_stats["rps"])

            decay_timer += 1
            if decay_timer >= 30: 
                decay_timer = 0
                for ip in list(ip_scores):
                    if ip_scores[ip] > 0:
                        ip_scores[ip] -= 1
                        if ip_scores[ip] <= 0: del ip_scores[ip]

        except Exception as e:
            print(f"[ERROR STATS] {e}")
        time.sleep(0.5)

# --- .htaccess Helper ---
def get_htaccess_rules():
    dynamic_forbidden = []
    allow_indexes = True
    if os.path.exists(HTACCESS_PATH):
        try:
            with open(HTACCESS_PATH, "r") as f:
                content = f.read()
                if re.search(r"Options\s+-Indexes", content, re.I): allow_indexes = False
                matches = re.findall(r'<FilesMatch\s+"([^"]+)">', content, re.I)
                dynamic_forbidden = matches
        except: pass
    return dynamic_forbidden, allow_indexes

# --- Server Logic ---
class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 100 

class HardenedPHPServer(BaseHTTPRequestHandler):
    server_version = "IronGate/17.0"

    def log_message(self, format, *args): pass

    def add_security_headers(self):
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        self.send_header("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: https: http:; frame-ancestors *;")

    def send_custom_404(self):
        self.send_response(404)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        html = """<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>404 Not Found</title>
        <style>body{background-color:#0f0f0f;color:#00ff00;font-family:'Courier New',monospace;text-align:center;margin-top:10%;}
        h1{font-size:80px;margin:0;text-shadow:0 0 10px #00ff00;}p{font-size:20px;color:#888;}
        .box{border:2px solid #333;display:inline-block;padding:20px;background:#111;box-shadow:0 0 20px rgba(0,255,0,0.1);}
        a{color:#00ff00;text-decoration:none;border-bottom:1px dotted #00ff00;}a:hover{background:#00ff00;color:#000;}
        </style></head><body><div class="box"><h1>404</h1><p>The file you are looking for has vanished into the void.</p>
        <p><a href="/">Return to Home Base</a></p></div></body></html>"""
        self.wfile.write(html.encode("utf-8"))

    def handle_request(self):
        global alert_trigger
        start_ts = time.time()
        
        if self.headers.get("CF-Connecting-IP"):
            client_ip = self.headers.get("CF-Connecting-IP")
        elif self.headers.get("X-Forwarded-For"):
            client_ip = self.headers.get("X-Forwarded-For").split(",")[0].strip()
        else:
            client_ip = self.client_address[0]
            
        origin = get_geo_country(client_ip)
            
        host_domain = self.headers.get('Host', 'unknown-host')
        user_agent = self.headers.get('User-Agent', '-')
        referrer = self.headers.get('Referer', '-')
        req_id = secrets.token_hex(2).upper()
        status_code = 200
        url_path = "-"
        
        try:
            if is_banned(client_ip):
                alert_trigger = True 
                self.send_error(403, "IP banned")
                status_code = 403
                url_path = "BANNED"
                return

            ip_counter[client_ip] += 1
            htaccess_files, allow_indexes = get_htaccess_rules()
            url_parts = self.path.split("?", 1)
            url_path = url_parts[0]
            query_string = url_parts[1] if len(url_parts) > 1 else ""
            full_path = os.path.realpath(os.path.join(SITE_ROOT, url_path.lstrip("/")))

            if not full_path.startswith(os.path.realpath(SITE_ROOT)):
                self.send_error(403); status_code = 403; return
            filename = os.path.basename(full_path)
            ext = os.path.splitext(full_path)[1].lower()
            is_blocked = False
            if filename in FORBIDDEN_FILES or ext in FORBIDDEN_EXT: is_blocked = True
            else:
                for pattern in htaccess_files:
                    if re.search(pattern, filename, re.I): is_blocked = True; break
            if is_blocked: self.send_error(403, "Access Denied"); status_code = 403; return

            if os.path.isdir(full_path):
                if not url_path.endswith("/"):
                    self.send_response(301); self.send_header("Location", url_path + "/" + (f"?{query_string}" if query_string else "")); self.end_headers(); status_code = 301; return
                index_found = False
                for idx in ("index.php", "index.html"):
                    test = os.path.join(full_path, idx)
                    if os.path.exists(test): full_path = test; index_found = True; break
                if not index_found and not allow_indexes: self.send_error(403, "Directory Listing Forbidden"); status_code = 403; return

            if not os.path.exists(full_path):
                self.send_custom_404(); status_code = 404
            elif full_path.endswith(".php"):
                status_code = int(self.run_php(full_path, url_path, query_string))
            else:
                status_code = int(self.serve_static(full_path))

        except Exception as e:
            print(f"[ERROR REQUEST] {e}")
            status_code = 500
        finally:
            req_timestamps.append(time.time())
            
            ip_scores[client_ip] += score_request(client_ip, status_code, url_path, query_string)
            
            if ip_scores[client_ip] >= 100:
                ban_ip_db(client_ip, f"Automated Defense: Score {ip_scores[client_ip]}", origin)
                alert_trigger = True

            duration = (time.time() - start_ts) * 1000
            
            threading.Thread(target=log_request_db, 
                args=(req_id, datetime.now().isoformat(), client_ip, origin, host_domain, url_path, status_code, self.command, duration, user_agent, referrer)).start()
            
            log_entry = { "id": req_id, "time": datetime.now().strftime('%H:%M:%S'), "origin": origin, "ip": client_ip, "domain": host_domain, "path": url_path, "status": status_code, "ms": duration, "method": self.command, "ua": user_agent, "ref": referrer }
            log_buffer.append(log_entry)
            if status_code != 403: stats["requests"] += 1; stats["last_origin"] = origin

    def run_php(self, script_path, url_path, query_string):
        try:
            stats["php_hits"] += 1
            env = os.environ.copy()
            for h, v in self.headers.items(): env[f"HTTP_{h.replace('-', '_').upper()}"] = v
            content_length = self.headers.get("Content-Length")
            if content_length: env["CONTENT_LENGTH"] = content_length
            env["CONTENT_TYPE"] = self.headers.get("Content-Type", "")
            env.update({
                "GATEWAY_INTERFACE": "CGI/1.1", "REQUEST_METHOD": self.command,
                "SCRIPT_FILENAME": script_path, "SCRIPT_NAME": url_path,
                "REQUEST_URI": self.path, "QUERY_STRING": query_string,
                "REDIRECT_STATUS": "200", "REMOTE_ADDR": self.client_address[0],
                "SERVER_SOFTWARE": self.server_version, "DOCUMENT_ROOT": SITE_ROOT
            })
            try:
                body = self.rfile.read(int(content_length)) if content_length else b""
            except ValueError:
                body = b""
            proc = subprocess.Popen([PHP_CGI], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=os.path.dirname(script_path))
            stdout, stderr = proc.communicate(input=body)
            if b"\r\n\r\n" not in stdout: return 502
            raw_headers, body = stdout.split(b"\r\n\r\n", 1)
            status = 200
            headers_to_send = []
            for line in raw_headers.splitlines():
                if b":" in line:
                    k, v = line.split(b":", 1)
                    key, val = k.decode().strip(), v.decode().strip()
                    if key.lower() == "status": status = int(val.split()[0])
                    elif key.lower() not in ["x-frame-options", "content-security-policy"]: headers_to_send.append((key, val))
            self.send_response(status)
            self.add_security_headers()
            for k, v in headers_to_send: self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            return status
        except Exception as e:
            print(f"[ERROR PHP] {e}")
            return 500

    def serve_static(self, path):
        try:
            mime, _ = mimetypes.guess_type(path)
            self.send_response(200)
            self.add_security_headers()
            self.send_header("Content-Type", mime or "application/octet-stream")
            self.send_header("Content-Length", os.path.getsize(path))
            self.end_headers()
            with open(path, "rb") as f: shutil.copyfileobj(f, self.wfile)
            return 200
        except: return 500

    def do_GET(self): self.handle_request()
    def do_POST(self): self.handle_request()

# --- TUI Dashboard ---

class InspectorPanel(Static):
    # UPDATED CSS: Removed buttons, reduced height to be a status bar
    DEFAULT_CSS = """
    InspectorPanel { 
        height: 5; dock: bottom; border-top: solid green; background: #111; padding: 1;
    }
    .info-col { width: 100%; color: white; }
    .label { color: #888; text-style: bold; }
    .val { color: cyan; }
    """
    selected_ip = None
    selected_cn = "??"
    selected_id = None
    
    def compose(self) -> ComposeResult:
        with Vertical(classes="info-col"):
            yield Label("[SELECT AN ENTRY]", id="insp-title", classes="val")
            yield Label("SCORE: 0", id="insp-score", classes="label")
            yield Label("SOURCE: -", id="insp-source", classes="label")
        # Buttons removed as requested

    def update_target(self, ip, cn="??", db_id=None, source="Unknown"):
        self.selected_ip = ip
        self.selected_cn = cn
        self.selected_id = db_id
        
        self.query_one("#insp-title", Label).update(f"TARGET: {ip} [{cn}]")
        self.query_one("#insp-score", Label).update(f"LOCAL SCORE: {ip_scores[ip]}")
        self.query_one("#insp-source", Label).update(f"SOURCE: {source}")

class ServerApp(App):
    CSS = """
    Screen { background: #0f0f0f; }
    #header { height: 3; dock: top; content-align: center middle; background: #004400; color: #00ff00; text-style: bold; }
    .alert-header { background: #FF0000 !important; color: white !important; }
    #logs-box { width: 85%; height: 100%; border: solid green; }
    #side-box { width: 15%; height: 100%; border: solid blue; dock: right; }
    #controls-bar { dock: bottom; height: 3; layout: horizontal; }
    #input-box { width: 85%; border: solid yellow; }
    #btn-pause { width: 15%; background: #333; color: white; border: none; }
    .vault-container { layout: vertical; padding: 1; }
    .vault-controls { height: 3; layout: horizontal; margin-bottom: 1; }
    .vault-table { height: 1fr; border: solid cyan; }
    .filter-input { width: 20; margin-right: 1; background: #222; border: none; color: white; }
    .btn-hammer { margin-right: 1; border: none; color: white; text-style: bold; min-width: 15; content-align: center middle; }
    .btn-h-blue { background: #2980B9; }
    .btn-h-red { background: #C0392B; }
    .btn-h-gray { background: #7F8C8D; }
    .title { color: #00FF00; text-style: bold; border-bottom: solid green; margin-bottom: 1; }
    """
    
    BINDINGS = [
        ("ctrl+c", "quit", "Quit"),
        ("s", "save_log", "Evidence Export"),
        ("b", "ban_ip", "Ban IP"),
        ("a", "check_abuse", "AbuseIPDB"),
        ("delete", "delete_row", "Delete Log"),
    ]

    def compose(self) -> ComposeResult:
        yield Static(f"🛡️ IronGate v17.0 |By: Krintoxi| Root: {SITE_ROOT}", id="header")
        with TabbedContent():
            with TabPane("LIVE TRAFFIC"):
                with Horizontal(id="main-layout"):
                    with Vertical(id="logs-box"):
                        # REPLACED RichLog with DataTable for interactivity
                        yield DataTable(id="live-table")
                    with Vertical(id="side-box"):
                        yield Static("SYSTEM STATS", classes="title")
                        yield Static(id="system-stats")
                        yield Static("")
                        yield Static("TOP CLIENTS", classes="title")
                        yield Static(id="top-clients")
                with Horizontal(id="controls-bar"):
                    yield Input(placeholder="CMD: 'ban <ip>'...", id="input-box")
                    yield Button("PAUSE", id="btn-pause")

            with TabPane("LOG VAULT"):
                with Vertical(classes="vault-container"):
                    with Horizontal(classes="vault-controls"):
                        yield Input(placeholder="IP...", id="db-filter-ip", classes="filter-input")
                        yield Input(placeholder="Status...", id="db-filter-status", classes="filter-input")
                        yield Input(placeholder="Geo...", id="db-filter-geo", classes="filter-input")
                        yield Button("QUERY", id="btn-query", classes="btn-hammer btn-h-blue")
                        yield Button("< PREV", id="btn-prev", classes="btn-hammer btn-h-gray")
                        yield Label("Page 1/1", id="page-label")
                        yield Button("NEXT >", id="btn-next", classes="btn-hammer btn-h-gray")
                    yield DataTable(id="vault-table")

            with TabPane("BAN HAMMER"):
                with Vertical(classes="vault-container"):
                    with Horizontal(classes="vault-controls"):
                        yield Input(placeholder="Reason...", id="ban-reason-input", classes="filter-input")
                        yield Button("UPDATE REASON", id="btn-update-ban", classes="btn-hammer btn-h-blue")
                        yield Button("UNBAN", id="btn-unban", classes="btn-hammer btn-h-red")
                        yield Button("REFRESH", id="btn-refresh-bans", classes="btn-hammer btn-h-gray")
                        yield Button("EXPORT CSV", id="btn-export-csv", classes="btn-hammer btn-h-blue")
                    yield DataTable(id="ban-table")
        
        # GLOBAL INSPECTOR (Outside Tabs)
        yield InspectorPanel(id="inspector")
        yield Footer()

    def on_mount(self):
        self.live_table = self.query_one("#live-table", DataTable)
        self.client_widget = self.query_one("#top-clients", Static)
        self.system_widget = self.query_one("#system-stats", Static)
        self.inspector = self.query_one("#inspector", InspectorPanel)
        self.vault_table = self.query_one("#vault-table", DataTable)
        self.ban_table = self.query_one("#ban-table", DataTable)
        
        # Setup Live Table
        self.live_table.cursor_type = "row"
        self.live_table.add_columns("Time", "IP", "CN", "Method", "Path", "Status")
        
        # Setup Vault Table
        self.vault_table.cursor_type = "row"
        self.vault_table.add_columns("ID", "HEX", "Time", "IP", "Method", "Status", "Path", "CN", "UA")
        
        # Setup Ban Table
        self.ban_table.cursor_type = "row"
        self.ban_table.add_columns("IP Address", "CN", "Reason", "Date Banned")
        
        self.set_interval(0.1, self.refresh_live_logs)
        self.set_interval(1.0, self.refresh_clients)
        self.set_interval(0.2, self.check_alerts)
        self.set_interval(0.5, self.refresh_system_stats)
        
        self.last_log_count = 0
        self.current_page = 1
        self.page_size = 50
        self.run_db_query()
        self.refresh_ban_table()

    def refresh_system_stats(self):
        s = system_stats
        out = (
            f"CPU  : {s['cpu']:5.1f}% {sparkline(spark_cpu)}\n"
            f"RAM  : {s['ram']:5.1f}%\n"
            f"DISK : {s['disk']:5.1f}%\n"
            f"RPS  : {s['rps']:5d} {sparkline(spark_rps, 50)}\n"
            f"REQS : {stats['requests']}"
        )
        self.system_widget.update(out)

    def check_alerts(self):
        global alert_trigger
        header = self.query_one("#header")
        if alert_trigger:
            header.add_class("alert-header")
            alert_trigger = False
            self.set_timer(0.2, lambda: header.remove_class("alert-header"))

    def get_plain(self, val):
        return str(val.plain) if hasattr(val, "plain") else str(val)

    def on_data_table_row_highlighted(self, message: DataTable.RowHighlighted):
        # UNIFIED HANDLER FOR ALL 3 TABLES
        table_id = message.data_table.id
        row = message.data_table.get_row(message.row_key)
        
        ip = "0.0.0.0"
        cn = "??"
        db_id = None
        source = "Unknown"

        if table_id == "live-table":
            # Cols: "Time", "IP", "CN", "Method", "Path", "Status"
            ip = self.get_plain(row[1])
            cn = self.get_plain(row[2])
            source = "LIVE TRAFFIC"

        elif table_id == "vault-table":
            # Cols: "ID", "HEX", "Time", "IP", "Method", "Status", "Path", "CN", "UA"
            ip = self.get_plain(row[3])
            cn = self.get_plain(row[7])
            db_id = self.get_plain(row[0])
            source = "LOG VAULT"
            
        elif table_id == "ban-table":
            # Cols: "IP Address", "CN", "Reason", "Date Banned"
            ip = self.get_plain(row[0])
            cn = self.get_plain(row[1])
            source = "BAN HAMMER"

        self.inspector.update_target(ip, cn, db_id, source)

    def action_check_abuse(self):
        ip = self.inspector.selected_ip
        if not ip: 
            self.notify("No IP Selected!", severity="error")
            return

        # 🚫 Stop checking local IPs to save credits and avoid errors
        if ip in ("127.0.0.1", "::1") or ip.startswith("192.168.") or ip.startswith("10."):
            self.notify(f"⚠️ Skipped Local IP: {ip}", severity="warning")
            return

        self.notify(f"🔎 Checking AbuseIPDB for: {ip}...")
        
        intel = abuseipdb_check(ip)
        if intel:
            score = intel.get('abuseConfidenceScore', 0)
            domain = intel.get('domain', 'Unknown')
            reports = intel.get('totalReports', 0)
            self.notify(f"🚨 Score: {score}% | Reports: {reports} | Host: {domain}", timeout=10)
        else:
            self.notify("❌ Lookup Failed (API Error or Rate Limit)", severity="error")

    def refresh_ban_table(self):
        self.ban_table.clear()
        for r in fetch_bans(): self.ban_table.add_row(*r)

    def on_button_pressed(self, event: Button.Pressed):
        bid = event.button.id
        # Removed act-abuse, act-save, act-ban, act-del checks
        if bid == "btn-refresh-bans": self.refresh_ban_table()
        elif bid == "btn-unban":
            ip = self.inspector.selected_ip
            if ip and unban_ip_db(ip):
                self.notify(f"Unbanned {ip}"); self.refresh_ban_table()
        elif bid == "btn-pause":
            global paused
            paused = not paused
            event.button.label = "RESUME" if paused else "PAUSE"
        elif bid in ("btn-query", "btn-prev", "btn-next"):
            if bid == "btn-query": self.current_page = 1
            elif bid == "btn-prev" and self.current_page > 1: self.current_page -= 1
            elif bid == "btn-next" and self.current_page < self.total_pages: self.current_page += 1
            self.run_db_query()

    def run_db_query(self):
        self.vault_table.clear()
        f_ip = self.query_one("#db-filter-ip", Input).value.strip()
        f_stat = self.query_one("#db-filter-status", Input).value.strip()
        f_geo = self.query_one("#db-filter-geo", Input).value.strip()
        rows, total_records = fetch_logs_paginated(page=self.current_page, filter_ip=f_ip or None, filter_status=f_stat or None, filter_geo=f_geo or None)
        self.total_pages = math.ceil(total_records / self.page_size) or 1
        self.query_one("#page-label", Label).update(f"Page {self.current_page}/{self.total_pages}")
        for r in rows:
            stat_style = "green" if r[5] < 400 else "red"
            self.vault_table.add_row(str(r[0]), Text(r[1], style="dim"), r[2], Text(r[3], style="cyan"), r[4], Text(str(r[5]), style=stat_style), r[6], Text(r[7], style="yellow"), r[8])

    def refresh_live_logs(self):
        if paused: return
        current_len = len(log_buffer)
        if current_len > self.last_log_count:
            new_entries = list(log_buffer)[self.last_log_count:]
            for entry in new_entries:
                # Add to Live Table instead of RichLog
                # Cols: "Time", "IP", "CN", "Method", "Path", "Status"
                geo_tag = entry['origin'] if entry['origin'] != "N/A" else "-"
                s_style = "bold green" if entry['status'] < 400 else "bold red"
                
                self.live_table.add_row(
                    entry['time'],
                    Text(entry['ip'], style="cyan"),
                    Text(geo_tag, style="yellow"),
                    entry['method'],
                    entry['path'][:30],
                    Text(str(entry['status']), style=s_style)
                )
            
            # Keep table clean (max 100 rows visible in TUI to prevent lag)
            if self.live_table.row_count > 100:
                self.live_table.remove_row(self.live_table.rows[0])
                
            self.live_table.scroll_end(animate=False)
            self.last_log_count = current_len

    def refresh_clients(self):
        out = ""
        for ip, count in ip_counter.most_common(10): 
            out += f"{ip:<15} : {count} [S:{ip_scores[ip]}]\n"
        self.client_widget.update(out)

    def action_save_log(self):
        ip = self.inspector.selected_ip
        if ip:
            path = export_ip_evidence(ip)
            self.notify(f"Evidence Locker: {path}")

    def action_ban_ip(self):
        ip = self.inspector.selected_ip
        cn = self.inspector.selected_cn
        if ip:
            if ban_ip_db(ip, "CyberDeck Manual", cn):
                self.notify(f"BANNED: {ip} [{cn}]"); self.refresh_ban_table()

    def action_delete_row(self):
        # Only allows deletion if we have a DB ID (which comes from Vault)
        did = self.inspector.selected_id
        if did:
            delete_logs_db(delete_id=did)
            self.run_db_query(); self.notify("Log Deleted")
        else:
            self.notify("Can only delete from Vault", severity="warning")

def start_server_thread():
    mimetypes.init()
    os.makedirs(SITE_ROOT, exist_ok=True)
    try:
        httpd = ThreadedHTTPServer(("0.0.0.0", PORT), HardenedPHPServer)
        httpd.serve_forever()
    except PermissionError:
        print(f"\n[!] Port {PORT} denied. Falling back to 8080...")
        httpd = ThreadedHTTPServer(("0.0.0.0", 8080), HardenedPHPServer)
        httpd.serve_forever()

if __name__ == "__main__":
    threading.Thread(target=start_server_thread, daemon=True).start()
    threading.Thread(target=system_stats_sampler, daemon=True).start()
    ServerApp().run()
