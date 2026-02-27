# ⬡ NetScope — Real-Time Network Sniffer & Analyzer

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![PyQt5](https://img.shields.io/badge/GUI-PyQt5-41CD52?style=flat-square&logo=qt&logoColor=white)
![Scapy](https://img.shields.io/badge/Capture-Scapy-FF6B35?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=flat-square)

A fully-featured, dark-themed desktop network packet sniffer and traffic analyzer built with Python. Capture, inspect, filter, and analyze live network traffic — all in a native GUI with no browser required.

---

## 📸 Screenshot

> Launch the app and start capturing — everything updates in real time.

![alt text](<Screenshot (162).png>) ![alt text](<Screenshot (161).png>) ![alt text](<Screenshot (160).png>) ![alt text](<Screenshot (159).png>) ![alt text](<Screenshot (158).png>) ![alt text](<Screenshot (157).png>) ![alt text](<Screenshot (156).png>) ![alt text](<Screenshot (155).png>)

---

## ✨ Features

### 🔴 Live Capture
- Capture packets from **any network interface** in real time
- Set **BPF filters** (e.g. `tcp port 80`, `host 8.8.8.8`, `udp`, `icmp`)
- Set a **packet count limit** or capture indefinitely
- Runs on Windows (as Administrator), Linux and macOS (with sudo)

### 📋 Packet Table
- Color-coded by protocol — TCP, UDP, DNS, HTTP, HTTPS, ICMP, ARP, IPv6
- Shows timestamp, source/dest IP & port, size, TCP flags, and decoded info
- **Live quick-filter** by IP, keyword, port, or protocol
- **Threats-only** filter to focus on suspicious traffic
- Auto-scroll with toggle, configurable max row limit

### 📊 Statistics Tab
- Protocol breakdown table
- Top source IPs and destination IPs
- Top destination ports with service names (HTTP, SSH, RDP, etc.)
- All tables update live during capture

### 🛡️ Threat Detection
Automatic detection of:
| Threat | Description |
|---|---|
| **SYN Scan** | Port scanning via half-open TCP connections |
| **NULL Scan** | TCP packets with no flags set |
| **XMAS Scan** | TCP packets with FIN+PSH+URG flags |
| **RST Flood** | Excessive TCP RST packets |
| **Telnet** | Unencrypted Telnet traffic on port 23 |
| **FTP Cleartext** | Unencrypted FTP on port 21 |
| **Large Packet** | Packets over 8000 bytes |
| **ICMP Flood** | High volume ICMP traffic |

Each threat type has its own counter card and a dedicated log table.

### 🔍 DNS Logger
- Separate tab logging every DNS query and response
- Shows source IP, query name, and answer count

### 💬 Conversations
- Auto-groups traffic by IP pairs
- Shows packet count, total bytes, protocols used, start time, and last seen time

### 🔬 Packet Inspector
- Click any row to see full packet decode
- Layer-by-layer field breakdown (IPs, ports, TTL, flags)
- Raw payload viewer
- **Hex dump** with ASCII sidebar

### 📈 Charts (requires pyqtgraph)
- Live **traffic timeline** — bytes per second
- **Protocol distribution** bar chart
- **Top talkers** visual bar list

### 💾 Import / Export
- Save capture to **JSON**
- Load and replay a JSON capture
- Load and analyze existing **.pcap / .pcapng** files
- Export all packets to **CSV** for spreadsheet analysis

---

## 🚀 Installation

### 1. Clone the repo
```bash
git clone https://github.com/dawood-ayub/netscope.git
cd netscope
```

### 2. Install dependencies
```bash
pip install scapy PyQt5 pyqtgraph
```

> `pyqtgraph` is optional — the app works without it, charts just won't display.

### 3. Windows — install Npcap
Scapy requires a packet capture driver on Windows.
Download and install **Npcap** from: https://npcap.com

---

## ▶️ Running

### Windows
Run your terminal **as Administrator**, then:
```bash
python NetScope.py
```

### Linux / macOS
```bash
sudo python3 NetScope.py
```

> Root/Administrator access is required because raw socket capture is a privileged OS operation.

---

## 🎛️ How to Use

| Action | How |
|---|---|
| Start capturing | Select interface → set optional BPF filter → click **▶ START** |
| Stop capturing | Click **■ STOP** |
| Filter packets | Type in the Quick Filter box or pick a protocol from the dropdown |
| Inspect a packet | Click any row in the Packets tab |
| View hex dump | Click a packet → switch to the **HEX** tab on the right |
| See threats | Click the **THREATS** tab |
| Export data | Use the **↓ Save JSON** or **↓ Export CSV** buttons |
| Load a pcap | Click **↑ Load PCAP** and select your file |

### BPF Filter Examples
```
tcp                          # TCP only
udp port 53                  # DNS traffic
host 192.168.1.1             # traffic to/from a specific host
tcp port 80 or tcp port 443  # HTTP and HTTPS
not port 22                  # exclude SSH
icmp                         # ping traffic only
src net 192.168.1.0/24       # from your local subnet
```

---

## 📁 Project Structure

```
netscope/
├── NetScope.py       # Main application — all-in-one file
├── README.md         # This file
└── screenshot.png    # UI screenshot 
```

---

## 🔧 Requirements

| Package | Version | Purpose |
|---|---|---|
| Python | 3.8+ | Runtime |
| scapy | 2.5+ | Packet capture & parsing |
| PyQt5 | 5.15+ | GUI framework |
| pyqtgraph | 0.13+ | Charts (optional) |
| Npcap | latest | Windows packet driver |

---

## ⚠️ Legal Disclaimer

This tool is intended for **educational purposes**, **network diagnostics**, and **monitoring traffic on networks you own or have explicit permission to monitor**.

Capturing traffic on networks without authorization may be **illegal** under computer misuse laws in your country. The author takes no responsibility for misuse.

---

## 🤝 Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

1. Fork the repo
2. Create your feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'Add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a pull request


---

<p align="center">Built with Python, PyQt5 & Scapy</p>
