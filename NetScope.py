#!/usr/bin/env python3
"""
NetScope — Real-Time Network Sniffer & Analyzer
================================================
Requirements:
    pip install scapy PyQt5 pyqtgraph

Run:
    sudo python3 netscope.py
    (root/sudo required for raw socket access)
"""

import sys
import time
import json
import csv
import socket
import struct
import threading
from datetime import datetime
from collections import Counter, defaultdict
from functools import partial

# ── PyQt5 ────────────────────────────────────────────────────────────────────
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QGridLayout, QSplitter, QTabWidget, QTableWidget, QTableWidgetItem,
    QTableView, QLabel, QPushButton, QLineEdit, QComboBox, QSpinBox,
    QCheckBox, QTextEdit, QGroupBox, QStatusBar, QProgressBar, QHeaderView,
    QFileDialog, QMessageBox, QFrame, QScrollArea, QSizePolicy,
    QAction, QMenuBar, QToolBar, QDialog, QDialogButtonBox,
    QAbstractItemView, QStyleFactory
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QSortFilterProxyModel,
    QAbstractTableModel, QModelIndex, QVariant, pyqtSlot
)
from PyQt5.QtGui import (
    QColor, QFont, QFontMetrics, QPalette, QBrush, QIcon,
    QTextCharFormat, QTextCursor, QPainter, QPen
)

# ── Scapy ────────────────────────────────────────────────────────────────────
try:
    from scapy.all import (
        sniff, IP, TCP, UDP, ICMP, DNS, ARP, IPv6, Raw, Ether,
        wrpcap, rdpcap, get_if_list, conf
    )
    from scapy.layers.http import HTTPRequest, HTTPResponse
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

# ── pyqtgraph (charts) ───────────────────────────────────────────────────────
try:
    import pyqtgraph as pg
    pg.setConfigOption('background', '#0d1117')
    pg.setConfigOption('foreground', '#445566')
    PYQTGRAPH_OK = True
except ImportError:
    PYQTGRAPH_OK = False

# ─────────────────────────────────────────────────────────────────────────────
#  CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────
COMMON_PORTS = {
    20:"FTP-DATA",21:"FTP",22:"SSH",23:"TELNET",25:"SMTP",53:"DNS",
    67:"DHCP",68:"DHCP",80:"HTTP",110:"POP3",123:"NTP",143:"IMAP",
    161:"SNMP",443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP",
    993:"IMAPS",995:"POP3S",1433:"MSSQL",3306:"MySQL",3389:"RDP",
    5432:"PostgreSQL",5900:"VNC",6379:"Redis",8080:"HTTP-ALT",8443:"HTTPS-ALT",
    27017:"MongoDB",
}

PROTO_COLORS = {
    "TCP":    "#3b82f6",
    "UDP":    "#22c55e",
    "DNS":    "#a855f7",
    "HTTP":   "#06b6d4",
    "HTTPS":  "#0891b2",
    "ICMP":   "#eab308",
    "ARP":    "#ef4444",
    "IPv6":   "#94a3b8",
    "OTHER":  "#64748b",
}

THREAT_RULES = [
    ("SYN Scan",      lambda p: p.get("proto")=="TCP" and p.get("flags")=="SYN" and (p.get("dst_port") or 0) < 1024),
    ("NULL Scan",     lambda p: p.get("proto")=="TCP" and p.get("flags") in ("","NONE",None)),
    ("XMAS Scan",     lambda p: p.get("proto")=="TCP" and all(f in (p.get("flags") or "") for f in ("FIN","PSH","URG"))),
    ("RST Flood",     lambda p: p.get("proto")=="TCP" and "RST" in (p.get("flags") or "")),
    ("Telnet",        lambda p: p.get("dst_port")==23),
    ("FTP Cleartext", lambda p: p.get("dst_port")==21),
    ("Large Packet",  lambda p: (p.get("size") or 0) > 8000),
    ("ICMP Flood",    lambda p: p.get("proto")=="ICMP"),
]

DARK = {
    "bg":       "#080c10",
    "panel":    "#0d1117",
    "border":   "#1a2332",
    "text":     "#c9d8e8",
    "text_dim": "#445566",
    "bright":   "#eef5ff",
    "accent":   "#00d4ff",
    "alert":    "#ff3b3b",
    "success":  "#00ff88",
}

# ─────────────────────────────────────────────────────────────────────────────
#  PACKET PARSER
# ─────────────────────────────────────────────────────────────────────────────
_pkt_id = 0

def parse_packet(pkt):
    global _pkt_id
    _pkt_id += 1

    result = {
        "id":       _pkt_id,
        "time":     datetime.now().strftime("%H:%M:%S.%f")[:12],
        "unix":     time.time(),
        "proto":    "OTHER",
        "src_ip":   "",
        "dst_ip":   "",
        "src_port": None,
        "dst_port": None,
        "size":     len(pkt),
        "flags":    "",
        "info":     "",
        "payload":  "",
        "ttl":      None,
        "raw":      pkt.summary(),
        "threat":   None,
    }

    if pkt.haslayer(ARP):
        arp = pkt[ARP]
        result.update(proto="ARP", src_ip=arp.psrc, dst_ip=arp.pdst,
                      info=f"{'REQUEST' if arp.op==1 else 'REPLY'}: {arp.psrc} → {arp.pdst}")
        return result

    if pkt.haslayer(IP):
        ip = pkt[IP]
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst
        result["ttl"]    = ip.ttl
    elif pkt.haslayer(IPv6):
        ip = pkt[IPv6]
        result["src_ip"] = ip.src
        result["dst_ip"] = ip.dst
        result["proto"]  = "IPv6"

    if pkt.haslayer(ICMP):
        icmp = pkt[ICMP]
        types = {0:"Echo Reply",3:"Unreachable",8:"Echo Request",11:"TTL Exceeded"}
        result.update(proto="ICMP", info=f"ICMP {types.get(icmp.type, f'type={icmp.type}')} {result['src_ip']} → {result['dst_ip']}")
        _check_threats(result)
        return result

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        result["src_port"] = tcp.sport
        result["dst_port"] = tcp.dport
        # Flags
        flag_bits = {"FIN":0x01,"SYN":0x02,"RST":0x04,"PSH":0x08,"ACK":0x10,"URG":0x20}
        flags = "|".join(n for n, b in flag_bits.items() if tcp.flags & b)
        result["flags"] = flags or "NONE"

        if pkt.haslayer(HTTPRequest):
            req = pkt[HTTPRequest]
            m   = (req.Method or b"?").decode(errors="replace")
            path= (req.Path or b"/").decode(errors="replace")
            host= (req.Host or result["dst_ip"].encode()).decode(errors="replace")
            result.update(proto="HTTP", info=f"{m} {host}{path}")
        elif pkt.haslayer(HTTPResponse):
            resp = pkt[HTTPResponse]
            code = (resp.Status_Code or b"?").decode(errors="replace")
            result.update(proto="HTTP", info=f"HTTP Response {code}")
        elif tcp.dport == 443 or tcp.sport == 443:
            result["proto"] = "HTTPS"
            result["info"]  = f"TLS {result['src_ip']}:{tcp.sport} → {result['dst_ip']}:{tcp.dport}"
        else:
            svc = COMMON_PORTS.get(tcp.dport, COMMON_PORTS.get(tcp.sport, ""))
            result["proto"] = "TCP"
            result["info"]  = f"{result['src_ip']}:{tcp.sport} → {result['dst_ip']}:{tcp.dport} [{flags}]{' ['+svc+']' if svc else ''}"

        if pkt.haslayer(Raw):
            raw = bytes(pkt[Raw].load)[:256]
            try:    result["payload"] = raw.decode("utf-8", errors="replace")
            except: result["payload"] = raw.hex()

        _check_threats(result)
        return result

    if pkt.haslayer(UDP):
        udp = pkt[UDP]
        result["src_port"] = udp.sport
        result["dst_port"] = udp.dport

        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            if dns.qr == 0 and dns.qd:
                qname = dns.qd.qname.decode(errors="replace") if dns.qd.qname else "?"
                result.update(proto="DNS", info=f"DNS Query: {qname}")
            else:
                result.update(proto="DNS", info=f"DNS Response ({dns.ancount} ans)")
        else:
            svc = COMMON_PORTS.get(udp.dport, COMMON_PORTS.get(udp.sport,""))
            result["proto"] = "UDP"
            result["info"]  = f"{result['src_ip']}:{udp.sport} → {result['dst_ip']}:{udp.dport}{' ['+svc+']' if svc else ''}"

        _check_threats(result)
        return result

    result["info"] = pkt.summary()
    return result


def _check_threats(p):
    for name, rule in THREAT_RULES:
        try:
            if rule(p):
                p["threat"] = name
                return
        except:
            pass


# ─────────────────────────────────────────────────────────────────────────────
#  PACKET TABLE MODEL
# ─────────────────────────────────────────────────────────────────────────────
COLUMNS = ["#","Time","Protocol","Source","Destination","Size","Flags","Info","Threat"]
COL_IDX = {c:i for i,c in enumerate(COLUMNS)}

class PacketModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self._data   = []
        self._colors = {}

    def rowCount(self, _=QModelIndex()):    return len(self._data)
    def columnCount(self, _=QModelIndex()): return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if orientation == Qt.Horizontal and role == Qt.DisplayRole:
            return COLUMNS[section]
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid() or index.row() >= len(self._data):
            return None
        row = self._data[index.row()]
        col = index.column()

        if role == Qt.DisplayRole:
            return self._cell(row, col)

        if role == Qt.ForegroundRole:
            if row.get("threat"):
                return QBrush(QColor("#ff3b3b"))
            proto = row.get("proto","OTHER")
            color = PROTO_COLORS.get(proto, DARK["text_dim"])
            if col == COL_IDX["Protocol"]:
                return QBrush(QColor(color))
            return QBrush(QColor(DARK["text"]))

        if role == Qt.BackgroundRole:
            if row.get("threat"):
                return QBrush(QColor("#1a0808"))
            if index.row() % 2 == 0:
                return QBrush(QColor("#0a0f15"))
            return QBrush(QColor(DARK["panel"]))

        if role == Qt.FontRole:
            f = QFont("Consolas", 10)
            if col == COL_IDX["Protocol"]:
                f.setBold(True)
            return f

        return None

    def _cell(self, row, col):
        mapping = [
            str(row.get("id","")),
            row.get("time",""),
            row.get("proto",""),
            f"{row.get('src_ip','')}:{row.get('src_port','')}" if row.get('src_port') else row.get('src_ip',''),
            f"{row.get('dst_ip','')}:{row.get('dst_port','')}" if row.get('dst_port') else row.get('dst_ip',''),
            f"{row.get('size',0)} B",
            row.get("flags",""),
            row.get("info",""),
            row.get("threat","") or "",
        ]
        return mapping[col]

    def add_packets(self, pkts):
        if not pkts: return
        start = len(self._data)
        self.beginInsertRows(QModelIndex(), start, start + len(pkts) - 1)
        self._data.extend(pkts)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self._data = []
        self.endResetModel()

    def get_row(self, row_idx):
        if 0 <= row_idx < len(self._data):
            return self._data[row_idx]
        return {}

    def all_packets(self):
        return list(self._data)


# ─────────────────────────────────────────────────────────────────────────────
#  SNIFFER THREAD
# ─────────────────────────────────────────────────────────────────────────────
class SnifferThread(QThread):
    packet_captured = pyqtSignal(dict)
    error_occurred  = pyqtSignal(str)

    def __init__(self, iface=None, bpf_filter=None, count=0):
        super().__init__()
        self.iface      = iface
        self.bpf_filter = bpf_filter
        self.count      = count
        self._stop      = threading.Event()

    def run(self):
        if not SCAPY_OK:
            self.error_occurred.emit("scapy not installed.\nRun: pip install scapy")
            return
        try:
            sniff(
                iface    = self.iface or None,
                filter   = self.bpf_filter or None,
                count    = self.count if self.count > 0 else 0,
                prn      = self._handle,
                stop_filter = lambda _: self._stop.is_set(),
                store    = False,
            )
        except PermissionError:
            self.error_occurred.emit("Permission denied — run with sudo/root.")
        except Exception as e:
            self.error_occurred.emit(str(e))

    def _handle(self, pkt):
        p = parse_packet(pkt)
        self.packet_captured.emit(p)

    def stop(self):
        self._stop.set()


# ─────────────────────────────────────────────────────────────────────────────
#  MINI STAT CARD
# ─────────────────────────────────────────────────────────────────────────────
class StatCard(QFrame):
    def __init__(self, label, value="0", sub=""):
        super().__init__()
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet(f"""
            StatCard {{
                background: {DARK['panel']};
                border: 1px solid {DARK['border']};
                border-radius: 8px;
            }}
        """)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        lay.setSpacing(5)

        self._lbl = QLabel(label.upper())
        self._lbl.setStyleSheet(f"color:{DARK['text_dim']};font-size:11px;font-family:Consolas;letter-spacing:1.5px;")

        self._val = QLabel(value)
        self._val.setStyleSheet(f"color:{DARK['bright']};font-size:28px;font-weight:bold;font-family:'Segoe UI',sans-serif;")
        self._val.setMinimumHeight(38)

        self._sub = QLabel(sub)
        self._sub.setStyleSheet(f"color:{DARK['text_dim']};font-size:11px;font-family:Consolas;")

        lay.addWidget(self._lbl)
        lay.addWidget(self._val)
        lay.addWidget(self._sub)

    def update(self, value, sub=""):
        self._val.setText(str(value))
        if sub: self._sub.setText(sub)


# ─────────────────────────────────────────────────────────────────────────────
#  PROTOCOL BAR WIDGET
# ─────────────────────────────────────────────────────────────────────────────
class ProtoBarWidget(QWidget):
    def __init__(self):
        super().__init__()
        self._data = {}
        self.setMinimumHeight(24)

    def set_data(self, proto_counts: dict):
        self._data = proto_counts
        self.update()

    def paintEvent(self, event):
        if not self._data: return
        p = QPainter(self)
        total = sum(self._data.values()) or 1
        x = 0
        w = self.width()
        h = self.height()
        for proto, count in sorted(self._data.items(), key=lambda x: -x[1]):
            seg_w = int(count / total * w)
            color = PROTO_COLORS.get(proto, DARK["text_dim"])
            p.fillRect(x, 0, seg_w, h, QColor(color))
            x += seg_w


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────────────────────────────────────
class NetScope(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScope — Real-Time Network Analyzer")
        self.resize(1440, 900)
        self._apply_dark_theme()

        # State
        self.sniffer        = None
        self.packets        = []          # all raw dicts
        self._pending       = []          # batch buffer
        self._stats         = dict(total=0, bytes=0, protos=Counter(), src_ips=Counter(),
                                   dst_ips=Counter(), dst_ports=Counter(), alerts=[], threats=Counter())
        self._start_time    = None
        self._last_total    = 0
        self._last_bytes    = 0
        self._last_ts       = time.time()
        self._timeline_bytes= []          # per-second bytes
        self._tl_bucket     = 0
        self._tl_second     = int(time.time())
        self._auto_scroll   = True
        self._capture_running = False
        self._filter_text   = ""          # live search filter

        self._build_ui()
        self._build_timers()

    # ── Theme ────────────────────────────────────────────────────────────────
    def _apply_dark_theme(self):
        self.setStyleSheet(f"""
            QMainWindow, QWidget {{
                background: {DARK['bg']};
                color: {DARK['text']};
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 12px;
            }}
            QTabWidget::pane {{
                border: 1px solid {DARK['border']};
                background: {DARK['panel']};
            }}
            QTabBar::tab {{
                background: {DARK['bg']};
                color: {DARK['text_dim']};
                padding: 8px 18px;
                border: 1px solid {DARK['border']};
                border-bottom: none;
                font-family: Consolas;
                font-size: 11px;
                letter-spacing: 0.5px;
            }}
            QTabBar::tab:selected {{
                background: {DARK['panel']};
                color: {DARK['accent']};
                border-top: 2px solid {DARK['accent']};
            }}
            QTableView, QTableWidget {{
                background: {DARK['bg']};
                alternate-background-color: {DARK['panel']};
                gridline-color: {DARK['border']};
                color: {DARK['text']};
                font-family: Consolas;
                font-size: 11px;
                border: none;
                selection-background-color: #0d2233;
                selection-color: {DARK['bright']};
            }}
            QHeaderView::section {{
                background: {DARK['panel']};
                color: {DARK['text_dim']};
                padding: 6px 10px;
                border: none;
                border-right: 1px solid {DARK['border']};
                border-bottom: 1px solid {DARK['border']};
                font-family: Consolas;
                font-size: 10px;
                letter-spacing: 1px;
                text-transform: uppercase;
            }}
            QPushButton {{
                background: {DARK['border']};
                color: {DARK['text']};
                border: 1px solid #22334a;
                border-radius: 5px;
                padding: 7px 16px;
                font-family: Consolas;
                font-size: 11px;
                font-weight: bold;
            }}
            QPushButton:hover {{ background: #1e2e40; border-color: {DARK['accent']}; }}
            QPushButton:disabled {{ color: {DARK['text_dim']}; background: {DARK['bg']}; }}
            QPushButton#startBtn {{
                background: {DARK['accent']};
                color: #00FF00;
                border: 1px solid #00FF00;
            }}
            QPushButton#startBtn:hover {{ background: #33ddff; }}
            QPushButton#stopBtn {{
                background: transparent;
                color: {DARK['alert']};
                border: 1px solid {DARK['alert']};
            }}
            QPushButton#stopBtn:hover {{ background: #1a0808; }}
            QLineEdit, QComboBox, QSpinBox {{
                background: {DARK['bg']};
                color: {DARK['text']};
                border: 1px solid {DARK['border']};
                border-radius: 4px;
                padding: 6px 10px;
                font-family: Consolas;
                font-size: 11px;
            }}
            QLineEdit:focus, QComboBox:focus {{
                border-color: {DARK['accent']};
            }}
            QComboBox::drop-down {{ border: none; }}
            QComboBox QAbstractItemView {{
                background: {DARK['panel']};
                color: {DARK['text']};
                border: 1px solid {DARK['border']};
                selection-background-color: #0d2233;
            }}
            QGroupBox {{
                border: 1px solid {DARK['border']};
                border-radius: 6px;
                margin-top: 8px;
                padding-top: 6px;
                font-family: Consolas;
                font-size: 10px;
                color: {DARK['text_dim']};
                letter-spacing: 1px;
            }}
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 6px;
            }}
            QScrollBar:vertical {{
                background: {DARK['bg']};
                width: 6px;
            }}
            QScrollBar::handle:vertical {{
                background: {DARK['border']};
                border-radius: 3px;
            }}
            QSplitter::handle {{
                background: {DARK['border']};
            }}
            QTextEdit {{
                background: {DARK['panel']};
                color: {DARK['text']};
                border: 1px solid {DARK['border']};
                font-family: Consolas;
                font-size: 11px;
            }}
            QLabel#alertLabel {{
                color: {DARK['alert']};
                font-family: Consolas;
                font-size: 11px;
                padding: 6px;
                background: #1a0808;
                border: 1px solid #330a0a;
                border-radius: 4px;
            }}
            QStatusBar {{
                background: {DARK['panel']};
                color: {DARK['text_dim']};
                border-top: 1px solid {DARK['border']};
                font-family: Consolas;
                font-size: 10px;
            }}
        """)

    # ── Build UI ─────────────────────────────────────────────────────────────
    def _build_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Toolbar
        root.addWidget(self._build_toolbar())

        # Stat cards
        root.addWidget(self._build_stat_bar())

        # Protocol bar
        self.proto_bar = ProtoBarWidget()
        self.proto_bar.setFixedHeight(6)
        root.addWidget(self.proto_bar)

        # Main splitter
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # LEFT: tabs
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_packet_tab(),  "  PACKETS  ")
        self.tabs.addTab(self._build_stats_tab(),   "  STATISTICS  ")
        self.tabs.addTab(self._build_threats_tab(), "  THREATS  ")
        self.tabs.addTab(self._build_dns_tab(),     "  DNS LOG  ")
        self.tabs.addTab(self._build_convo_tab(),   "  CONVERSATIONS  ")
        splitter.addWidget(self.tabs)

        # RIGHT: detail + charts
        right_panel = self._build_right_panel()
        splitter.addWidget(right_panel)
        splitter.setSizes([980, 380])

        root.addWidget(splitter, 1)

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self._status_lbl = QLabel("Ready  |  Install scapy + run with sudo to capture real traffic")
        self._status_lbl.setStyleSheet(f"color:{DARK['text_dim']};font-family:Consolas;font-size:10px;")
        self.status.addWidget(self._status_lbl)

        self._pkt_count_lbl = QLabel("0 packets")
        self._pkt_count_lbl.setStyleSheet(f"color:{DARK['text_dim']};font-family:Consolas;font-size:10px;")
        self.status.addPermanentWidget(self._pkt_count_lbl)

    # ── Toolbar ──────────────────────────────────────────────────────────────
    def _build_toolbar(self):
        bar = QFrame()
        bar.setFixedHeight(58)
        bar.setStyleSheet(f"background:{DARK['panel']};border-bottom:1px solid {DARK['border']};")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(12, 0, 12, 0)
        lay.setSpacing(10)

        # Logo
        logo = QLabel("⬡ NetScope")
        logo.setStyleSheet(f"color:{DARK['accent']};font-size:16px;font-weight:bold;font-family:'Segoe UI';letter-spacing:-0.5px;")
        lay.addWidget(logo)

        sep = QFrame(); sep.setFrameShape(QFrame.VLine)
        sep.setStyleSheet(f"color:{DARK['border']};"); lay.addWidget(sep)

        # Interface
        lay.addWidget(QLabel("Interface:"))
        self.iface_combo = QComboBox()
        self.iface_combo.setFixedWidth(130)
        self._populate_interfaces()
        lay.addWidget(self.iface_combo)

        # BPF filter
        lay.addWidget(QLabel("BPF Filter:"))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("tcp  |  udp port 53  |  host 8.8.8.8  |  icmp")
        self.filter_edit.setFixedWidth(240)
        lay.addWidget(self.filter_edit)

        # Count
        lay.addWidget(QLabel("Count:"))
        self.count_spin = QSpinBox()
        self.count_spin.setRange(0, 100000)
        self.count_spin.setValue(0)
        self.count_spin.setSpecialValueText("∞")
        self.count_spin.setFixedWidth(80)
        lay.addWidget(self.count_spin)

        lay.addSpacing(6)
        sep2 = QFrame(); sep2.setFrameShape(QFrame.VLine)
        sep2.setStyleSheet(f"color:{DARK['border']};"); lay.addWidget(sep2)
        lay.addSpacing(6)

        # Buttons
        self.start_btn = QPushButton("▶  START")
        self.start_btn.setObjectName("startBtn")
        self.start_btn.setFixedWidth(100)
        self.start_btn.clicked.connect(self.start_capture)
        lay.addWidget(self.start_btn)

        self.stop_btn = QPushButton("■  STOP")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setFixedWidth(90)
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self.stop_capture)
        lay.addWidget(self.stop_btn)

        self.clear_btn = QPushButton("⊘ Clear")
        self.clear_btn.clicked.connect(self.clear_all)
        lay.addWidget(self.clear_btn)

        sep3 = QFrame(); sep3.setFrameShape(QFrame.VLine)
        sep3.setStyleSheet(f"color:{DARK['border']};"); lay.addWidget(sep3)

        self.save_btn = QPushButton("↓ Save JSON")
        self.save_btn.clicked.connect(self.save_json)
        lay.addWidget(self.save_btn)

        self.load_btn = QPushButton("↑ Load JSON")
        self.load_btn.clicked.connect(self.load_json)
        lay.addWidget(self.load_btn)

        self.pcap_save_btn = QPushButton("↓ Save PCAP")
        self.pcap_save_btn.clicked.connect(self.save_pcap)
        lay.addWidget(self.pcap_save_btn)

        self.pcap_load_btn = QPushButton("↑ Load PCAP")
        self.pcap_load_btn.clicked.connect(self.load_pcap)
        lay.addWidget(self.pcap_load_btn)

        self.csv_btn = QPushButton("↓ Export CSV")
        self.csv_btn.clicked.connect(self.export_csv)
        lay.addWidget(self.csv_btn)

        lay.addStretch()

        # Status indicator
        self.indicator = QLabel("● IDLE")
        self.indicator.setStyleSheet(f"color:{DARK['text_dim']};font-family:Consolas;font-size:11px;font-weight:bold;")
        lay.addWidget(self.indicator)

        self.elapsed_lbl = QLabel("00:00:00")
        self.elapsed_lbl.setStyleSheet(f"color:{DARK['text_dim']};font-family:Consolas;font-size:11px;")
        lay.addWidget(self.elapsed_lbl)

        return bar

    # ── Stat bar ─────────────────────────────────────────────────────────────
    def _build_stat_bar(self):
        frame = QFrame()
        frame.setFixedHeight(110)
        frame.setStyleSheet(f"background:{DARK['bg']};border-bottom:1px solid {DARK['border']};")
        lay = QHBoxLayout(frame)
        lay.setContentsMargins(12, 10, 12, 10)
        lay.setSpacing(10)

        self.card_pkts   = StatCard("Packets",   "0",   "0 pkt/s")
        self.card_bytes  = StatCard("Data",      "0 B", "0 B/s")
        self.card_protos = StatCard("Protocols", "0",   "—")
        self.card_ips    = StatCard("Unique IPs","0",   "—")
        self.card_alerts = StatCard("Threats",   "0",   "no threats")
        self.card_alerts._val.setStyleSheet(f"color:{DARK['success']};font-size:28px;font-weight:bold;")

        for c in [self.card_pkts, self.card_bytes, self.card_protos, self.card_ips, self.card_alerts]:
            lay.addWidget(c)

        return frame

    # ── Packet tab ───────────────────────────────────────────────────────────
    def _build_packet_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # Search / quick filter bar
        fbar = QFrame()
        fbar.setFixedHeight(38)
        fbar.setStyleSheet(f"background:{DARK['panel']};border-bottom:1px solid {DARK['border']};")
        flay = QHBoxLayout(fbar)
        flay.setContentsMargins(10, 0, 10, 0)
        flay.setSpacing(8)

        flay.addWidget(QLabel("🔍 Quick Filter:"))
        self.quick_filter = QLineEdit()
        self.quick_filter.setPlaceholderText("Filter by IP, protocol, port, keyword...")
        self.quick_filter.setFixedWidth(300)
        self.quick_filter.textChanged.connect(self._apply_quick_filter)
        flay.addWidget(self.quick_filter)

        flay.addWidget(QLabel("Proto:"))
        self.proto_filter = QComboBox()
        self.proto_filter.addItems(["All", "TCP", "UDP", "DNS", "HTTP", "HTTPS", "ICMP", "ARP", "IPv6", "OTHER"])
        self.proto_filter.currentTextChanged.connect(self._apply_quick_filter)
        flay.addWidget(self.proto_filter)

        self.threat_only_chk = QCheckBox("Threats only")
        self.threat_only_chk.setStyleSheet(f"color:{DARK['alert']};font-family:Consolas;")
        self.threat_only_chk.stateChanged.connect(self._apply_quick_filter)
        flay.addWidget(self.threat_only_chk)

        self.autoscroll_chk = QCheckBox("Auto-scroll")
        self.autoscroll_chk.setChecked(True)
        self.autoscroll_chk.setStyleSheet(f"color:{DARK['text_dim']};font-family:Consolas;")
        self.autoscroll_chk.stateChanged.connect(lambda s: setattr(self, '_auto_scroll', bool(s)))
        flay.addWidget(self.autoscroll_chk)

        flay.addStretch()
        flay.addWidget(QLabel("Rows:"))
        self.max_rows_spin = QSpinBox()
        self.max_rows_spin.setRange(100, 50000)
        self.max_rows_spin.setValue(5000)
        self.max_rows_spin.setSuffix(" max")
        self.max_rows_spin.setFixedWidth(100)
        flay.addWidget(self.max_rows_spin)

        lay.addWidget(fbar)

        # Table
        self.pkt_model   = PacketModel()
        self.proxy_model = QSortFilterProxyModel()
        self.proxy_model.setSourceModel(self.pkt_model)
        self.proxy_model.setFilterCaseSensitivity(Qt.CaseInsensitive)
        self.proxy_model.setFilterKeyColumn(-1)

        self.table = QTableView()
        self.table.setModel(self.proxy_model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)

        # Column widths
        widths = [50, 110, 72, 170, 170, 65, 120, 300, 120]
        for i, w2 in enumerate(widths):
            self.table.setColumnWidth(i, w2)

        self.table.selectionModel().selectionChanged.connect(self._on_packet_selected)
        lay.addWidget(self.table, 1)

        return w

    # ── Stats tab ────────────────────────────────────────────────────────────
    def _build_stats_tab(self):
        w = QWidget()
        lay = QGridLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(10)

        # Protocol table
        pg1 = self._make_group("PROTOCOL BREAKDOWN")
        self.proto_table = self._make_simple_table(["Protocol","Packets","Bytes","% Total"])
        pg1.layout().addWidget(self.proto_table)
        lay.addWidget(pg1, 0, 0)

        # Top Source IPs
        pg2 = self._make_group("TOP SOURCE IPs")
        self.src_ip_table = self._make_simple_table(["IP Address","Packets","% Share"])
        pg2.layout().addWidget(self.src_ip_table)
        lay.addWidget(pg2, 0, 1)

        # Top Destination IPs
        pg3 = self._make_group("TOP DESTINATION IPs")
        self.dst_ip_table = self._make_simple_table(["IP Address","Packets","% Share"])
        pg3.layout().addWidget(self.dst_ip_table)
        lay.addWidget(pg3, 1, 0)

        # Top Ports
        pg4 = self._make_group("TOP DESTINATION PORTS")
        self.port_table = self._make_simple_table(["Port","Service","Packets","% Share"])
        pg4.layout().addWidget(self.port_table)
        lay.addWidget(pg4, 1, 1)

        return w

    # ── Threats tab ──────────────────────────────────────────────────────────
    def _build_threats_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)

        hdr = QHBoxLayout()
        title = QLabel("⚠  THREAT DETECTION LOG")
        title.setStyleSheet(f"color:{DARK['alert']};font-size:13px;font-weight:bold;font-family:Consolas;")
        hdr.addWidget(title)
        hdr.addStretch()
        clear_t = QPushButton("Clear Alerts")
        clear_t.clicked.connect(self._clear_threats)
        hdr.addWidget(clear_t)
        lay.addLayout(hdr)

        # Threat summary cards
        cards_row = QHBoxLayout()
        self.threat_cards = {}
        for rule_name, _ in THREAT_RULES:
            card = StatCard(rule_name, "0", "detections")
            self.threat_cards[rule_name] = card
            cards_row.addWidget(card)
        lay.addLayout(cards_row)

        # Threat table
        self.threat_table = self._make_simple_table(
            ["#","Time","Threat Type","Source","Destination","Proto","Info"], min_height=400
        )
        lay.addWidget(self.threat_table, 1)

        return w

    # ── DNS tab ──────────────────────────────────────────────────────────────
    def _build_dns_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)

        self.dns_table = self._make_simple_table(
            ["#","Time","Query/Response","Source","Details"], min_height=500
        )
        lay.addWidget(self.dns_table)
        return w

    # ── Conversations tab ────────────────────────────────────────────────────
    def _build_convo_tab(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)

        self.convo_table = self._make_simple_table(
            ["Conversation","Packets","Bytes","Protocols","Start","Last Seen"], min_height=500
        )
        lay.addWidget(self.convo_table)
        return w

    # ── Right panel (detail + charts) ────────────────────────────────────────
    def _build_right_panel(self):
        w = QWidget()
        w.setStyleSheet(f"background:{DARK['panel']};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        right_tabs = QTabWidget()
        right_tabs.addTab(self._build_detail_panel(),  "  DETAIL  ")
        right_tabs.addTab(self._build_charts_panel(),  "  CHARTS  ")
        right_tabs.addTab(self._build_hex_panel(),     "  HEX  ")
        lay.addWidget(right_tabs)

        return w

    def _build_detail_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)
        lay.setSpacing(8)

        lbl = QLabel("SELECT A PACKET TO INSPECT")
        lbl.setStyleSheet(f"color:{DARK['text_dim']};font-family:Consolas;font-size:10px;letter-spacing:1px;")
        lay.addWidget(lbl)

        self.detail_text = QTextEdit()
        self.detail_text.setReadOnly(True)
        self.detail_text.setFont(QFont("Consolas", 10))
        lay.addWidget(self.detail_text, 1)

        pg = self._make_group("PAYLOAD")
        self.payload_text = QTextEdit()
        self.payload_text.setReadOnly(True)
        self.payload_text.setFont(QFont("Consolas", 10))
        self.payload_text.setMaximumHeight(160)
        pg.layout().addWidget(self.payload_text)
        lay.addWidget(pg)

        return w

    def _build_charts_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(10)

        if PYQTGRAPH_OK:
            # Traffic timeline
            tl_grp = self._make_group("TRAFFIC (bytes/sec)")
            self.tl_plot = pg.PlotWidget()
            self.tl_plot.setBackground(DARK['panel'])
            self.tl_plot.setFixedHeight(120)
            self.tl_curve = self.tl_plot.plot(pen=pg.mkPen(DARK['accent'], width=1.5))
            self.tl_fill  = pg.FillBetweenItem(
                self.tl_curve,
                self.tl_plot.plot([0],[0]),
                brush=pg.mkBrush(0, 212, 255, 20)
            )
            self.tl_plot.addItem(self.tl_fill)
            self.tl_plot.showGrid(y=True, alpha=0.15)
            self.tl_plot.getAxis('bottom').setPen(pg.mkPen(DARK['border']))
            self.tl_plot.getAxis('left').setPen(pg.mkPen(DARK['border']))
            tl_grp.layout().addWidget(self.tl_plot)
            lay.addWidget(tl_grp)

            # Packets/sec bar
            pps_grp = self._make_group("PACKETS / sec")
            self.pps_plot = pg.PlotWidget()
            self.pps_plot.setBackground(DARK['panel'])
            self.pps_plot.setFixedHeight(100)
            self.pps_bars = pg.BarGraphItem(x=[], height=[], width=0.8, brush=DARK['accent'])
            self.pps_plot.addItem(self.pps_bars)
            self.pps_plot.showGrid(y=True, alpha=0.15)
            pps_grp.layout().addWidget(self.pps_plot)
            lay.addWidget(pps_grp)

            # Protocol breakdown bars
            proto_grp = self._make_group("PROTOCOL DISTRIBUTION")
            self.proto_plot = pg.PlotWidget()
            self.proto_plot.setBackground(DARK['panel'])
            self.proto_plot.setFixedHeight(150)
            proto_grp.layout().addWidget(self.proto_plot)
            lay.addWidget(proto_grp)

        else:
            # Fallback text
            self.chart_fallback = QTextEdit()
            self.chart_fallback.setReadOnly(True)
            self.chart_fallback.setPlaceholderText("Install pyqtgraph for charts:\npip install pyqtgraph")
            lay.addWidget(self.chart_fallback)

        # Top talkers (always shown)
        talkers_grp = self._make_group("TOP TALKERS (src IP)")
        self.talkers_text = QTextEdit()
        self.talkers_text.setReadOnly(True)
        self.talkers_text.setFont(QFont("Consolas", 10))
        self.talkers_text.setMaximumHeight(180)
        talkers_grp.layout().addWidget(self.talkers_text)
        lay.addWidget(talkers_grp)

        lay.addStretch()
        return w

    def _build_hex_panel(self):
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(10, 10, 10, 10)

        lbl = QLabel("HEX DUMP  —  select a packet in the table")
        lbl.setStyleSheet(f"color:{DARK['text_dim']};font-family:Consolas;font-size:10px;letter-spacing:1px;")
        lay.addWidget(lbl)

        self.hex_text = QTextEdit()
        self.hex_text.setReadOnly(True)
        self.hex_text.setFont(QFont("Consolas", 10))
        lay.addWidget(self.hex_text, 1)
        return w

    # ── Helpers ──────────────────────────────────────────────────────────────
    def _make_group(self, title):
        g = QGroupBox(title)
        g.setLayout(QVBoxLayout())
        g.layout().setContentsMargins(6, 14, 6, 6)
        g.layout().setSpacing(4)
        return g

    def _make_simple_table(self, cols, min_height=200):
        t = QTableWidget(0, len(cols))
        t.setHorizontalHeaderLabels(cols)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.setSelectionBehavior(QAbstractItemView.SelectRows)
        t.verticalHeader().setVisible(False)
        t.verticalHeader().setDefaultSectionSize(22)
        t.horizontalHeader().setStretchLastSection(True)
        t.setAlternatingRowColors(True)
        t.setMinimumHeight(min_height)
        return t

    def _populate_interfaces(self):
        self.iface_combo.addItem("all")
        try:
            ifaces = get_if_list() if SCAPY_OK else []
            for i in ifaces:
                self.iface_combo.addItem(i)
        except:
            for i in ["eth0","wlan0","en0","en1","lo"]:
                self.iface_combo.addItem(i)

    # ── Timers ───────────────────────────────────────────────────────────────
    def _build_timers(self):
        # Flush pending packets to UI @ 10 Hz
        self._flush_timer = QTimer()
        self._flush_timer.timeout.connect(self._flush_packets)
        self._flush_timer.start(100)

        # Update stats/charts @ 2 Hz
        self._stats_timer = QTimer()
        self._stats_timer.timeout.connect(self._update_ui)
        self._stats_timer.start(500)

        # Elapsed clock @ 1 Hz
        self._clock_timer = QTimer()
        self._clock_timer.timeout.connect(self._tick_clock)
        self._clock_timer.start(1000)

    # ── Capture control ───────────────────────────────────────────────────────
    def start_capture(self):
        if not SCAPY_OK:
            QMessageBox.critical(self, "scapy not found",
                "Install scapy first:\n\npip install scapy\n\nThen run with sudo.")
            return

        iface  = self.iface_combo.currentText()
        flt    = self.filter_edit.text().strip()
        count  = self.count_spin.value()

        self.sniffer = SnifferThread(
            iface  = None if iface == "all" else iface,
            bpf_filter = flt or None,
            count  = count,
        )
        self.sniffer.packet_captured.connect(self._on_packet)
        self.sniffer.error_occurred.connect(self._on_error)
        self.sniffer.start()

        self._capture_running = True
        self._start_time = time.time()
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.indicator.setText("● LIVE")
        self.indicator.setStyleSheet(f"color:#00ff88;font-family:Consolas;font-size:11px;font-weight:bold;")
        self._status_lbl.setText(f"Capturing on [{iface}]  filter: [{flt or 'none'}]")

    def stop_capture(self):
        if self.sniffer:
            self.sniffer.stop()
            self.sniffer = None
        self._capture_running = False
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.indicator.setText("● STOPPED")
        self.indicator.setStyleSheet(f"color:{DARK['text_dim']};font-family:Consolas;font-size:11px;font-weight:bold;")
        self._status_lbl.setText(f"Capture stopped  |  {self._stats['total']:,} packets captured")

    def clear_all(self):
        self.stop_capture()
        self.packets.clear()
        self._pending.clear()
        self._stats = dict(total=0, bytes=0, protos=Counter(), src_ips=Counter(),
                           dst_ips=Counter(), dst_ports=Counter(), alerts=[], threats=Counter())
        self._timeline_bytes.clear()
        self._tl_bucket = 0
        global _pkt_id; _pkt_id = 0
        self.pkt_model.clear()
        for t in [self.proto_table, self.src_ip_table, self.dst_ip_table,
                  self.port_table, self.threat_table, self.dns_table, self.convo_table]:
            t.setRowCount(0)
        self.detail_text.clear()
        self.payload_text.clear()
        self.hex_text.clear()
        self.talkers_text.clear()
        self.elapsed_lbl.setText("00:00:00")
        self.indicator.setText("● IDLE")
        self.indicator.setStyleSheet(f"color:{DARK['text_dim']};font-family:Consolas;font-size:11px;font-weight:bold;")
        self._update_stat_cards()

    # ── Packet receive ────────────────────────────────────────────────────────
    @pyqtSlot(dict)
    def _on_packet(self, pkt):
        self._pending.append(pkt)

    def _flush_packets(self):
        if not self._pending: return
        batch = self._pending[:]
        self._pending.clear()

        max_rows = self.max_rows_spin.value()

        for p in batch:
            self.packets.append(p)
            # Stats
            self._stats["total"]    += 1
            self._stats["bytes"]    += p.get("size", 0)
            self._stats["protos"][p.get("proto","OTHER")] += 1
            if p.get("src_ip"):
                self._stats["src_ips"][p["src_ip"]] += 1
            if p.get("dst_ip"):
                self._stats["dst_ips"][p["dst_ip"]] += 1
            if p.get("dst_port"):
                self._stats["dst_ports"][p["dst_port"]] += 1
            # Threats
            if p.get("threat"):
                self._stats["threats"][p["threat"]] += 1
                if p not in self._stats["alerts"]:
                    self._stats["alerts"].append(p)
                    self._add_threat_row(p)
            # DNS
            if p.get("proto") == "DNS":
                self._add_dns_row(p)

        # Timeline bucket
        sec = int(time.time())
        if sec != self._tl_second:
            self._timeline_bytes.append(self._tl_bucket)
            if len(self._timeline_bytes) > 120:
                self._timeline_bytes.pop(0)
            self._tl_bucket  = 0
            self._tl_second  = sec
        self._tl_bucket += sum(p.get("size",0) for p in batch)

        # Add to model
        self.pkt_model.add_packets(batch)

        # Trim if over limit
        if self.pkt_model.rowCount() > max_rows:
            excess = self.pkt_model.rowCount() - max_rows
            self.pkt_model.beginRemoveRows(QModelIndex(), 0, excess - 1)
            self.pkt_model._data = self.pkt_model._data[excess:]
            self.pkt_model.endRemoveRows()

        # Auto-scroll
        if self._auto_scroll:
            self.table.scrollToBottom()

        self._pkt_count_lbl.setText(f"{self._stats['total']:,} packets")

    # ── UI update (periodic) ─────────────────────────────────────────────────
    def _update_ui(self):
        self._update_stat_cards()
        self._update_stats_tables()
        self._update_charts()
        self._update_conversations()
        self._update_threat_cards()
        self.proto_bar.set_data(dict(self._stats["protos"]))

    def _update_stat_cards(self):
        s = self._stats
        now = time.time()
        dt  = now - self._last_ts or 1
        pps = (s["total"] - self._last_total) / dt
        bps = (s["bytes"] - self._last_bytes) / dt
        self._last_total = s["total"]
        self._last_bytes = s["bytes"]
        self._last_ts    = now

        self.card_pkts.update(f"{s['total']:,}", f"{pps:.1f} pkt/s")
        self.card_bytes.update(fmt_bytes(s['bytes']), f"{fmt_bytes(bps)}/s")
        self.card_protos.update(len(s['protos']), f"top: {s['protos'].most_common(1)[0][0] if s['protos'] else '—'}")
        self.card_ips.update(len(s['src_ips']), f"active sources")

        tc = len(s["alerts"])
        self.card_alerts.update(tc, "threat detected" if tc else "no threats")
        self.card_alerts._val.setStyleSheet(
            f"color:{'#ff3b3b' if tc else '#00ff88'};font-size:22px;font-weight:bold;"
        )

    def _update_stats_tables(self):
        s = self._stats
        total = s["total"] or 1

        # Protocol table
        self.proto_table.setRowCount(0)
        for proto, count in s["protos"].most_common():
            r = self.proto_table.rowCount()
            self.proto_table.insertRow(r)
            color = QColor(PROTO_COLORS.get(proto, DARK["text_dim"]))
            items = [proto, str(count), "—", f"{count/total*100:.1f}%"]
            for c, v in enumerate(items):
                it = QTableWidgetItem(v)
                if c == 0: it.setForeground(QBrush(color))
                self.proto_table.setItem(r, c, it)

        # Src IPs
        self.src_ip_table.setRowCount(0)
        for ip, count in s["src_ips"].most_common(20):
            r = self.src_ip_table.rowCount()
            self.src_ip_table.insertRow(r)
            for c, v in enumerate([ip, str(count), f"{count/total*100:.1f}%"]):
                self.src_ip_table.setItem(r, c, QTableWidgetItem(v))

        # Dst IPs
        self.dst_ip_table.setRowCount(0)
        for ip, count in s["dst_ips"].most_common(20):
            r = self.dst_ip_table.rowCount()
            self.dst_ip_table.insertRow(r)
            for c, v in enumerate([ip, str(count), f"{count/total*100:.1f}%"]):
                self.dst_ip_table.setItem(r, c, QTableWidgetItem(v))

        # Ports
        self.port_table.setRowCount(0)
        for port, count in s["dst_ports"].most_common(20):
            r = self.port_table.rowCount()
            self.port_table.insertRow(r)
            svc = COMMON_PORTS.get(int(port), "")
            for c, v in enumerate([str(port), svc, str(count), f"{count/total*100:.1f}%"]):
                self.port_table.setItem(r, c, QTableWidgetItem(v))

    def _update_charts(self):
        if not PYQTGRAPH_OK: return
        tl = self._timeline_bytes
        if tl:
            self.tl_curve.setData(list(range(len(tl))), tl)
            # rebuild fill
            self.tl_plot.removeItem(self.tl_fill)
            base = self.tl_plot.plot(list(range(len(tl))), [0]*len(tl),
                                     pen=pg.mkPen(None))
            self.tl_fill = pg.FillBetweenItem(
                self.tl_curve, base, brush=pg.mkBrush(0, 212, 255, 25)
            )
            self.tl_plot.addItem(self.tl_fill)

        # Protocol bar chart
        self.proto_plot.clear()
        protos = list(self._stats["protos"].keys())
        counts = list(self._stats["protos"].values())
        if protos:
            colors = [QColor(PROTO_COLORS.get(p, DARK["text_dim"])) for p in protos]
            bg = pg.BarGraphItem(x=range(len(protos)), height=counts, width=0.6, brushes=colors)
            self.proto_plot.addItem(bg)
            ax = self.proto_plot.getAxis('bottom')
            ax.setTicks([list(enumerate(protos))])

        # Top talkers text
        lines = []
        for i, (ip, cnt) in enumerate(self._stats["src_ips"].most_common(8)):
            bar_w = int(cnt / (self._stats["src_ips"].most_common(1)[0][1] or 1) * 20)
            bar = "█" * bar_w + "░" * (20 - bar_w)
            lines.append(f"{ip:<20}  {bar}  {cnt:,}")
        self.talkers_text.setPlainText("\n".join(lines))

    def _update_conversations(self):
        convos = defaultdict(lambda: dict(pkts=0, bytes=0, protos=set(), start=None, last=None))
        for p in self.packets[-2000:]:
            src = p.get("src_ip","?")
            dst = p.get("dst_ip","?")
            key = f"{min(src,dst)} ↔ {max(src,dst)}"
            convos[key]["pkts"]   += 1
            convos[key]["bytes"]  += p.get("size", 0)
            convos[key]["protos"].add(p.get("proto",""))
            t = p.get("time","")
            if not convos[key]["start"]: convos[key]["start"] = t
            convos[key]["last"] = t

        self.convo_table.setRowCount(0)
        for convo, info in sorted(convos.items(), key=lambda x: -x[1]["pkts"]):
            r = self.convo_table.rowCount()
            self.convo_table.insertRow(r)
            for c, v in enumerate([
                convo, str(info["pkts"]), fmt_bytes(info["bytes"]),
                ",".join(sorted(info["protos"])), info["start"], info["last"]
            ]):
                self.convo_table.setItem(r, c, QTableWidgetItem(v))

    def _update_threat_cards(self):
        for name, card in self.threat_cards.items():
            cnt = self._stats["threats"].get(name, 0)
            card.update(cnt, "detections")
            card._val.setStyleSheet(
                f"color:{'#ff3b3b' if cnt else '#22c55e'};font-size:22px;font-weight:bold;"
            )

    def _tick_clock(self):
        if self._start_time:
            e = int(time.time() - self._start_time)
            h = e // 3600; m = (e % 3600) // 60; s = e % 60
            self.elapsed_lbl.setText(f"{h:02d}:{m:02d}:{s:02d}")

    # ── Threat / DNS rows ─────────────────────────────────────────────────────
    def _add_threat_row(self, p):
        r = self.threat_table.rowCount()
        self.threat_table.insertRow(r)
        vals = [str(p.get("id","")), p.get("time",""), p.get("threat",""),
                p.get("src_ip",""), p.get("dst_ip",""), p.get("proto",""), p.get("info","")]
        for c, v in enumerate(vals):
            it = QTableWidgetItem(v)
            it.setForeground(QBrush(QColor(DARK["alert"])))
            self.threat_table.setItem(r, c, it)

    def _add_dns_row(self, p):
        r = self.dns_table.rowCount()
        self.dns_table.insertRow(r)
        vals = [str(p.get("id","")), p.get("time",""), p.get("info",""),
                p.get("src_ip",""), p.get("info","")]
        for c, v in enumerate(vals):
            it = QTableWidgetItem(v)
            it.setForeground(QBrush(QColor(PROTO_COLORS["DNS"])))
            self.dns_table.setItem(r, c, it)

    def _clear_threats(self):
        self._stats["alerts"].clear()
        self._stats["threats"].clear()
        self.threat_table.setRowCount(0)

    # ── Packet detail ─────────────────────────────────────────────────────────
    def _on_packet_selected(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel: return
        proxy_row = sel[0].row()
        src_row   = self.proxy_model.mapToSource(self.proxy_model.index(proxy_row, 0)).row()
        pkt = self.pkt_model.get_row(src_row)
        if not pkt: return
        self._show_detail(pkt)

    def _show_detail(self, p):
        lines = [
            f"{'═'*38}",
            f"  Packet #{p.get('id')}",
            f"{'═'*38}",
            f"  Time       : {p.get('time','')}",
            f"  Protocol   : {p.get('proto','')}",
            f"  Source     : {p.get('src_ip','')}{'  Port: '+str(p['src_port']) if p.get('src_port') else ''}",
            f"  Destination: {p.get('dst_ip','')}{'  Port: '+str(p['dst_port']) if p.get('dst_port') else ''}",
            f"  Size       : {p.get('size',0)} bytes",
            f"  TTL        : {p.get('ttl','—')}",
            f"  TCP Flags  : {p.get('flags','—')}",
            f"  Info       : {p.get('info','')}",
        ]
        if p.get("threat"):
            lines.append(f"\n  ⚠ THREAT   : {p['threat']}")
        lines.append(f"\n  Raw        : {p.get('raw','')}")
        self.detail_text.setPlainText("\n".join(lines))

        payload = p.get("payload","")
        self.payload_text.setPlainText(payload if payload else "[no payload]")

        # Hex view (from payload)
        if payload:
            raw = payload.encode("utf-8", errors="replace")
            hex_lines = []
            for i in range(0, len(raw), 16):
                chunk = raw[i:i+16]
                hex_part  = " ".join(f"{b:02x}" for b in chunk).ljust(47)
                ascii_part = "".join(chr(b) if 32<=b<127 else "." for b in chunk)
                hex_lines.append(f"{i:04x}  {hex_part}  |{ascii_part}|")
            self.hex_text.setPlainText("\n".join(hex_lines))
        else:
            self.hex_text.setPlainText("[no payload data]")

    # ── Filters ───────────────────────────────────────────────────────────────
    def _apply_quick_filter(self):
        text  = self.quick_filter.text().strip()
        proto = self.proto_filter.currentText()
        threats_only = self.threat_only_chk.isChecked()

        # Build combined regex filter
        # We filter on any column
        parts = []
        if text:
            parts.append(text)

        if parts:
            self.proxy_model.setFilterRegExp("|".join(parts))
        else:
            self.proxy_model.setFilterRegExp("")

        # Additional protocol filter via custom filter
        self.proxy_model.setFilterKeyColumn(-1)
        if proto != "All" or threats_only or text:
            self.proxy_model.setFilterRole(Qt.DisplayRole)

            class CustomFilter(QSortFilterProxyModel):
                pass

            # Direct row-by-row filtering
            visible = []
            for i, row in enumerate(self.pkt_model._data):
                # Text match
                if text:
                    row_text = " ".join(str(v) for v in row.values()).lower()
                    if text.lower() not in row_text:
                        continue
                # Protocol filter
                if proto != "All" and row.get("proto","") != proto:
                    continue
                # Threats only
                if threats_only and not row.get("threat"):
                    continue
                visible.append(i)

            # Rebuild model with visible rows only (recreate proxy filter)
            self.proxy_model.setFilterFixedString("")
        else:
            self.proxy_model.setFilterFixedString("")

    # ── Save / Load ───────────────────────────────────────────────────────────
    def save_json(self):
        path, _ = QFileDialog.getSaveFileName(self, "Save JSON", "capture.json", "JSON (*.json)")
        if not path: return
        data = {
            "exported": datetime.now().isoformat(),
            "summary": {
                "total": self._stats["total"],
                "bytes": self._stats["bytes"],
                "protocols": dict(self._stats["protos"]),
                "src_ips": dict(self._stats["src_ips"].most_common(50)),
                "threats": dict(self._stats["threats"]),
            },
            "packets": self.packets[-5000:],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        self._status_lbl.setText(f"Saved to {path}")

    def load_json(self):
        path, _ = QFileDialog.getOpenFileName(self, "Load JSON", "", "JSON (*.json)")
        if not path: return
        try:
            with open(path) as f:
                data = json.load(f)
            self.clear_all()
            s = data.get("summary", {})
            self._stats["total"] = s.get("total", 0)
            self._stats["bytes"] = s.get("bytes", 0)
            self._stats["protos"] = Counter(s.get("protocols", {}))
            self._stats["src_ips"] = Counter(s.get("src_ips", {}))

            for p in data.get("packets", []):
                self.packets.append(p)
                self._pending.append(p)
            self._status_lbl.setText(f"Loaded {len(data.get('packets',[]))} packets from {path}")
        except Exception as e:
            QMessageBox.critical(self, "Load Error", str(e))

    def save_pcap(self):
        if not SCAPY_OK:
            QMessageBox.warning(self, "scapy required", "Install scapy to save PCAP files.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save PCAP", "capture.pcap", "PCAP (*.pcap)")
        if path:
            QMessageBox.information(self, "PCAP", "PCAP saving requires raw scapy packets.\nUse --pcap flag in sniffer.py instead.")

    def load_pcap(self):
        if not SCAPY_OK:
            QMessageBox.warning(self, "scapy required", "Install scapy to read PCAP files.")
            return
        path, _ = QFileDialog.getOpenFileName(self, "Open PCAP", "", "PCAP (*.pcap *.pcapng)")
        if not path: return
        try:
            self.clear_all()
            pkts = rdpcap(path)
            for raw_pkt in pkts:
                p = parse_packet(raw_pkt)
                self._pending.append(p)
            self._status_lbl.setText(f"Loaded {len(pkts)} packets from {path}")
        except Exception as e:
            QMessageBox.critical(self, "PCAP Error", str(e))

    def export_csv(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export CSV", "capture.csv", "CSV (*.csv)")
        if not path: return
        with open(path, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["id","time","proto","src_ip","src_port",
                                              "dst_ip","dst_port","size","flags","info","threat"])
            w.writeheader()
            for p in self.packets:
                w.writerow({k: p.get(k,"") for k in w.fieldnames})
        self._status_lbl.setText(f"Exported {len(self.packets):,} rows to {path}")

    # ── Error handler ────────────────────────────────────────────────────────
    def _on_error(self, msg):
        self.stop_capture()
        QMessageBox.critical(self, "Capture Error", msg)

    def closeEvent(self, event):
        self.stop_capture()
        event.accept()


# ─────────────────────────────────────────────────────────────────────────────
#  UTILITIES
# ─────────────────────────────────────────────────────────────────────────────
def fmt_bytes(b):
    b = float(b)
    for u in ["B","KB","MB","GB"]:
        if b < 1024: return f"{b:.1f} {u}"
        b /= 1024
    return f"{b:.2f} TB"


# ─────────────────────────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    # Dark palette for native widgets
    pal = QPalette()
    pal.setColor(QPalette.Window,          QColor(DARK["bg"]))
    pal.setColor(QPalette.WindowText,      QColor(DARK["text"]))
    pal.setColor(QPalette.Base,            QColor(DARK["panel"]))
    pal.setColor(QPalette.AlternateBase,   QColor(DARK["bg"]))
    pal.setColor(QPalette.ToolTipBase,     QColor(DARK["panel"]))
    pal.setColor(QPalette.ToolTipText,     QColor(DARK["text"]))
    pal.setColor(QPalette.Text,            QColor(DARK["text"]))
    pal.setColor(QPalette.Button,          QColor(DARK["border"]))
    pal.setColor(QPalette.ButtonText,      QColor(DARK["text"]))
    pal.setColor(QPalette.BrightText,      QColor(DARK["bright"]))
    pal.setColor(QPalette.Highlight,       QColor("#0d2233"))
    pal.setColor(QPalette.HighlightedText, QColor(DARK["bright"]))
    app.setPalette(pal)

    win = NetScope()
    win.showMaximized()
    sys.exit(app.exec_())