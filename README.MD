# Port Scan Detector

## Overview
This project is a **real-time intrusion detection and prevention system (IDPS)** that detects and blocks **port scans** using `iptables` (Linux) or firewall rules. It also includes a **web dashboard** to view and manage blocked IPs.

## Features
✅ **Real-time Port Scan Detection** – Monitors suspicious TCP, UDP, and ICMP connections.
✅ **Automatic IP Blocking** – Uses `iptables` to block attackers after exceeding scan limits.
✅ **Adaptive Blocking** – Increases block duration for repeat offenders.
✅ **Whitelist Trusted IPs** – Prevents false positives by allowing specific IPs.
✅ **Auto-Unblocking** – IPs are unblocked after `BLOCK_DURATION` expires.
✅ **Logging System** – Stores scan attempts and blocking events in a database (`SQLite`).
✅ **Web Dashboard** – View blocked IPs, unblock them, and track attack history.

---

## Installation

### Windows (via WSL)
1. **Enable Windows Subsystem for Linux (WSL):**
   ```sh
   wsl --install
   ```
2. **Launch Ubuntu (or another distro) from WSL.**
3. **Install dependencies:**
   ```sh
   sudo apt update && sudo apt install python3 python3-pip iptables sqlite3 -y
   pip install scapy
   ```
4. **Clone the repository & run the script:**
   ```sh
   https://github.com/MrReddy22/ETERNITY-SCANNER.git
   cd ETERNITY-SCANNER
   sudo python3 ETERNITYSCANNER.py
   ```

### macOS
1. **Install dependencies:**
   ```sh
   brew install python3 iproute2mac sqlite3
   pip3 install scapy
   ```
2. **Clone the repository & run the script:**
   ```sh
   git clone https://github.com/MrReddy22/ETERNITY-SCANNER.git
   cd ETERNITY-SCANNER
   sudo python3 ETERNITYSCANNER.py
   ```

### Linux (Ubuntu/Debian)
1. **Install dependencies:**
   ```sh
   sudo apt update && sudo apt install python3 python3-pip iptables sqlite3 -y
   pip install scapy
   ```
2. **Clone the repository & run the script:**
   ```sh
   git clone https://github.com/MrReddy22/ETERNITY-SCANNER.git
   cd ETERNITY-SCANNER
   sudo python3 ETERNITYSCANNER.py
   ```

---

## Usage

1. **Start the program:**
   ```sh
   sudo python3 ETERNITYSCANNER.py
   ```
2. **Choose Network Interface:** Select the interface to monitor (e.g., `eth0`, `wlan0`).
3. **Enter Whitelisted IPs:** Add any IPs that should never be blocked.
4. **Set Scan Threshold:** Define how many scans trigger a block.
5. **View the Web Dashboard:**
   - Open: `http://localhost:8080`
   - View blocked IPs & unblock them.
6. **Test the Detector:** Run an Nmap scan to see detection:
   ```sh
   nmap -sS -p 22,80,443 <your_ip>
   ```

---

## Troubleshooting

**Error: Address already in use (Port 8080)**
- Run: `sudo lsof -i :8080` to find the process using the port.
- Kill the process: `sudo kill -9 <PID>`.
- Restart the script.

**Error: ModuleNotFoundError: No module named 'scapy'**
- Run: `pip install scapy` (or `pip3 install scapy`).

**Error: Permission Denied when modifying iptables**
- Ensure you run the script as `sudo`.

---

## License
This project is open-source under the MIT License.

## Contributing
Pull requests are welcome! For major changes, please open an issue first.

## Contact
For any issues, reach out via GitHub Issues or email `cybercafestu@gmail.com`.

