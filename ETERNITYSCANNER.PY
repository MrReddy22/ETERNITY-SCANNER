import os
import time
import subprocess
import sqlite3
import logging
import threading
import socket
from collections import defaultdict
from http.server import SimpleHTTPRequestHandler, HTTPServer
from scapy.all import sniff, IP, TCP, UDP, ICMP

# Configuration
BLOCK_DURATION = 3600  # Block duration in seconds (1 hour)
LOG_FILE = "scan_detector.log"
WEB_DASHBOARD_PORT = 8081
DB_FILE = "scan_logs.db"


def find_free_port():
    for port in range(8080, 9090):  # Try ports from 8080 to 8089
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            if s.connect_ex(('0.0.0.0', port)) != 0:
                return port
    return 8080  # Default if no free port found

WEB_DASHBOARD_PORT = find_free_port()


target_ip = "0.0.0.0"  # Listen on all interfaces
scan_attempts = defaultdict(int)
blocked_ips = set()
log_entries = []
adaptive_blocking = defaultdict(int)

# Database Setup
def setup_database():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            action TEXT
        )
    """)
    conn.commit()
    conn.close()

setup_database()

def log_to_database(ip, action):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO scans (ip, action) VALUES (?, ?)", (ip, action))
    conn.commit()
    conn.close()

# Logging setup
def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
    )

# Ask for network interface
def get_interface():
    available_interfaces = os.popen("ip -o link show | awk -F': ' '{print $2}'").read().split()
    print("\nAvailable network interfaces:", ", ".join(available_interfaces))
    interface = input("Enter the network interface to monitor (default: auto-detect): ").strip()
    return interface if interface else available_interfaces[0]

# Whitelist IPs
def get_whitelisted_ips():
    whitelisted_ips = input("Enter whitelisted IPs (comma-separated): ").strip()
    return set(whitelisted_ips.split(",")) if whitelisted_ips else set()

# Scan threshold
def get_scan_threshold():
    while True:
        try:
            threshold = int(input("Enter scan detection threshold: ").strip())
            if threshold > 0:
                return threshold
            else:
                print("Threshold must be a positive integer.")
        except ValueError:
            print("Invalid input. Please enter a number.")

# Block an IP
def block_ip(ip):
    if ip in blocked_ips or ip in WHITELISTED_IPS:
        return
    print(f"[BLOCKING] IP {ip} exceeded scan limit.")
    result = subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode == 0:
        print(f"[BLOCKED] Successfully blocked {ip}")
        blocked_ips.add(ip)
        log_entries.append(f"Blocked: {ip}")
        log_to_database(ip, "Blocked")
        adaptive_blocking[ip] += 1
        duration = BLOCK_DURATION * adaptive_blocking[ip]
        threading.Timer(duration, unblock_ip, [ip]).start()
    else:
        logging.error(f"Failed to block {ip}")

# Unblock an IP
def unblock_ip(ip):
    if ip not in blocked_ips:
        print(f"[INFO] IP {ip} is not blocked.")
        return
    print(f"[UNBLOCKING] Removing {ip} from iptables.")
    subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True)
    blocked_ips.remove(ip)
    log_entries[:] = [entry for entry in log_entries if entry != f"Blocked: {ip}"]  # Remove from the list of log entries
    logging.info(f"Unblocked IP: {ip}")
    log_to_database(ip, "Unblocked")

# Detect scan (monitoring network)
def detect_scan(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        if src_ip in WHITELISTED_IPS or src_ip in blocked_ips:
            return
        scan_attempts[src_ip] += 1
        if scan_attempts[src_ip] >= SCAN_THRESHOLD:
            block_ip(src_ip)

# Sniff network traffic
def start_sniffing():
    print(f"[*] Monitoring interface {MONITOR_INTERFACE} for scans...")
    sniff(iface=MONITOR_INTERFACE, filter="ip", prn=detect_scan, store=0)

# Web Dashboard
def start_web_dashboard():
    class DashboardHandler(SimpleHTTPRequestHandler):
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            # HTML content with integrated CSS
            response = """
            <html>
                <head>
                    <title>Port Scan Detector</title>
                    <style>
                        body {
                            font-family: Arial, sans-serif;
                            background-color: #f4f4f9;
                            margin: 0;
                            padding: 0;
                        }

                        header {
                            background-color: #333;
                            color: white;
                            padding: 10px 0;
                            text-align: center;
                        }

                        header h1 {
                            margin: 0;
                        }

                        nav ul {
                            list-style-type: none;
                            padding: 0;
                            text-align: center;
                        }

                        nav ul li {
                            display: inline;
                            margin: 0 15px;
                        }

                        nav ul li a {
                            color: white;
                            text-decoration: none;
                            font-weight: bold;
                        }

                        .container {
                            margin: 20px;
                            padding: 20px;
                            background-color: white;
                            box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
                        }

                        h2 {
                            color: #333;
                        }

                        table {
                            width: 100%;
                            border-collapse: collapse;
                            margin: 20px 0;
                        }

                        table, th, td {
                            border: 1px solid #ddd;
                        }

                        th, td {
                            padding: 10px;
                            text-align: left;
                        }

                        th {
                            background-color: #f2f2f2;
                        }

                        form {
                            margin-top: 15px;
                        }

                        input[type="text"], input[type="submit"] {
                            padding: 10px;
                            font-size: 16px;
                        }

                        input[type="text"] {
                            width: 250px;
                            margin-right: 10px;
                        }

                        input[type="submit"] {
                            cursor: pointer;
                            background-color: #007bff;
                            color: white;
                            border: none;
                            transition: background-color 0.3s;
                        }

                        input[type="submit"]:hover {
                            background-color: #0056b3;
                        }
                    </style>
                </head>
                <body>
                    <header>
                        <h1>Port Scan Detector</h1>
                        <nav>
                            <ul>
                                <li><a href="/">Home</a></li>
                            </ul>
                        </nav>
                    </header>
                    <div class="container">
                        <h2>Blocked IPs</h2>
                        <table>
                            <tr><th>IP Address</th><th>Action</th></tr>
                            """
            response += "".join(f"<tr><td>{entry}</td><td><form action='/unblock_ip' method='POST'><input type='hidden' name='ip' value='{entry}'><input type='submit' value='Unblock'></form></td></tr>" for entry in log_entries)
            response += """
                        </table>
                        <h3>Unblock an IP</h3>
                        <form action='/unblock_ip' method='POST'>
                            <input type="text" name="ip" placeholder="Enter IP to unblock" required>
                            <input type="submit" value="Unblock IP">
                        </form>
                    </div>
                </body>
            </html>
            """
            self.wfile.write(response.encode())

        def do_POST(self):
            if self.path == '/unblock_ip':
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                ip = post_data.decode().split('=')[1]
                unblock_ip(ip)  # Call the unblock function
                self.send_response(302)
                self.send_header('Location', '/')
                self.end_headers()

    httpd = HTTPServer(('0.0.0.0', WEB_DASHBOARD_PORT), DashboardHandler)
    print(f"[WEB] Dashboard running at http://{target_ip}:{WEB_DASHBOARD_PORT}")
    httpd.serve_forever()

# Main
if __name__ == "__main__":
    setup_logging()
    MONITOR_INTERFACE = get_interface()
    WHITELISTED_IPS = get_whitelisted_ips()
    SCAN_THRESHOLD = get_scan_threshold()
    threading.Thread(target=start_web_dashboard, daemon=True).start()
    start_sniffing()
