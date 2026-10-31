#!/usr/bin/env python3
"""
CyberTracker 2026 - Modern Network Host Tracker & Security Scanner
-------------------------------------------------------------------
- Generative Live Host Discovery (Real-time Treeview & Metric Updates)
- Multithreaded TCP Ping Sweep + Banner Service Probing
- pfSense Compatible DHCP Discovery & SSDP UPnP Broadcast Engine
- Real-Time Thread Monitoring & Live Console Stream
- Normalized Service Port Keys (Prevents duplicate port/service listings)
"""

import socket
import subprocess
import json
import csv
import time
import os
import sys
import re
import threading
import queue
import webbrowser
from datetime import datetime
from ipaddress import ip_address, ip_network
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure System Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('network_tracker.log')
    ]
)
logger = logging.getLogger("CyberTracker")

# GUI imports check
GUI_AVAILABLE = False
try:
    import tkinter as tk
    from tkinter import ttk, scrolledtext, messagebox, filedialog
    GUI_AVAILABLE = True
except ImportError:
    logger.warning("Tkinter unavailable. Running in CLI mode.")

# Color Theme Palette
COLOR_BG = "#181825"          # Base background
COLOR_SURFACE = "#1E1E2E"     # Card surface
COLOR_SURFACE_LIGHT = "#313244"# Hover/Highlight surface
COLOR_BORDER = "#45475A"      # Borders
COLOR_TEXT = "#CDD6F4"        # Main text
COLOR_MUTED = "#A6ADC8"       # Secondary text
COLOR_ACCENT = "#89B4FA"      # Primary Blue Accent
COLOR_SUCCESS = "#A6E3A1"     # Green Accent
COLOR_WARNING = "#F9E2AF"     # Yellow Accent
COLOR_DANGER = "#F38BA8"      # Red Accent


# ----------------------------------------------------------------------
# Network Helper Functions
# ----------------------------------------------------------------------

def normalize_subnet(input_str):
    """Normalize user input to valid CIDR subnet string (e.g., 192.168.1.0/24)."""
    input_str = input_str.strip()
    if not input_str:
        return "192.168.1.0/24"
    if "/" not in input_str:
        parts = input_str.split(".")
        if len(parts) >= 3:
            return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "192.168.1.0/24"
    return input_str


def get_default_gateway():
    """Detect local default gateway IP (e.g. pfSense router IP)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1", local_ip
    except Exception:
        return "192.168.1.1", "192.168.1.100"


def discover_upnp_ssdp(timeout=2.5):
    """Broadcasting SSDP UPnP query over UDP multicast."""
    devices = []
    ssdp_request = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n\r\n"
    ).encode('utf-8')

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.settimeout(timeout)

    try:
        sock.sendto(ssdp_request, ("239.255.255.250", 1900))
        start_time = time.time()
        while time.time() - start_time < timeout:
            try:
                data, addr = sock.recvfrom(2048)
                response = data.decode('utf-8', errors='ignore')
                location = "UPnP Device"
                for line in response.splitlines():
                    if line.lower().startswith("location:"):
                        location = line.split(":", 1)[1].strip()
                        break
                info = f"{addr[0]} -> {location}"
                if info not in devices:
                    devices.append(info)
            except socket.timeout:
                break
            except Exception:
                pass
    except Exception as e:
        logger.error(f"SSDP Discovery error: {e}")
    finally:
        sock.close()
    return devices


def discover_dhcp_servers(timeout=2.5):
    """Sends DHCP DISCOVER packet with support for pfSense and Windows .exe environments."""
    found_servers = []
    gateway_ip, local_ip = get_default_gateway()

    parts = local_ip.split(".")
    subnet_broadcast = f"{parts[0]}.{parts[1]}.{parts[2]}.255"
    targets = list(dict.fromkeys(["255.255.255.255", subnet_broadcast, gateway_ip, f"{parts[0]}.{parts[1]}.{parts[2]}.254"]))

    dhcp_discover = bytes([
        0x01, 0x01, 0x06, 0x00,
        0x39, 0x03, 0xF3, 0x26,
        0x00, 0x00, 0x80, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
        0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
        0x63, 0x82, 0x53, 0x63,
        0x35, 0x01, 0x01,
        0x3D, 0x07, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xFF
    ])

    for target in targets:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.settimeout(0.8)

            try:
                sock.bind(("0.0.0.0", 68))
            except Exception:
                pass

            sock.sendto(dhcp_discover, (target, 67))
            start_t = time.time()
            while time.time() - start_t < 0.8:
                try:
                    data, server = sock.recvfrom(1024)
                    if len(data) > 2 and data[0] == 0x02:
                        s_str = f"DHCP Server at {server[0]}:{server[1]}"
                        if s_str not in found_servers:
                            found_servers.append(s_str)
                except socket.timeout:
                    break
                except Exception:
                    pass
            sock.close()
        except Exception:
            pass

    return found_servers


# ----------------------------------------------------------------------
# Core Tracker Engine
# ----------------------------------------------------------------------

class NetworkHostTracker:
    def __init__(self, subnet="192.168.1.0/24", cache_file="network_hosts.json"):
        self.subnet = normalize_subnet(subnet)
        try:
            self.network = ip_network(self.subnet, strict=False)
        except ValueError:
            self.network = ip_network("192.168.1.0/24")
            self.subnet = "192.168.1.0/24"

        self.cache_file = cache_file
        self.hosts = {}
        self.lock = threading.Lock()
        self.load_state()

    def is_valid_ip_in_subnet(self, ip_str):
        try:
            addr = ip_address(ip_str)
            return addr in self.network and not addr.is_multicast and not addr.is_loopback and not ip_str.endswith(".255")
        except ValueError:
            return False

    def get_arp_map(self):
        """Read system ARP table into IP -> MAC dictionary."""
        arp_map = {}
        ip_regex = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        mac_regex = re.compile(r'([0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2}[:-][0-9A-Fa-f]{2})')

        try:
            if sys.platform == "win32":
                flags = subprocess.CREATE_NO_WINDOW if hasattr(subprocess, 'CREATE_NO_WINDOW') else 0
                out = subprocess.check_output(['arp', '-a'], text=True, creationflags=flags)
                for line in out.splitlines():
                    ip_m = ip_regex.search(line)
                    mac_m = mac_regex.search(line)
                    if ip_m and mac_m:
                        ip = ip_m.group(1)
                        mac = mac_m.group(1).upper().replace('-', ':')
                        if mac != "FF:FF:FF:FF:FF:FF":
                            arp_map[ip] = mac
            else:
                if os.path.exists("/proc/net/arp"):
                    with open("/proc/net/arp", "r") as f:
                        next(f)
                        for line in f:
                            parts = line.strip().split()
                            if len(parts) >= 4:
                                ip, mac = parts[0], parts[3].upper()
                                if mac != "00:00:00:00:00:00":
                                    arp_map[ip] = mac
                try:
                    cmd = ['arp', '-a'] if sys.platform == 'darwin' else ['ip', 'neigh']
                    out = subprocess.check_output(cmd, text=True)
                    for line in out.splitlines():
                        ip_m = ip_regex.search(line)
                        mac_m = mac_regex.search(line)
                        if ip_m and mac_m:
                            arp_map[ip_m.group(1)] = mac_m.group(1).upper()
                except Exception:
                    pass
        except Exception as e:
            logger.error(f"ARP Map parsing error: {e}")
        return arp_map

    def quick_service_scan(self, ip):
        services = {}
        ports = {21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 80: 'HTTP',
                 139: 'NetBIOS', 443: 'HTTPS', 445: 'SMB', 3306: 'MySQL', 3389: 'RDP',
                 5432: 'PostgreSQL', 8080: 'HTTP-Alt'}
        for port, name in ports.items():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                if s.connect_ex((ip, port)) == 0:
                    services[int(port)] = name
                s.close()
            except Exception:
                pass
        return services

    def resolve_hostname(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except Exception:
            return None

    def process_discovered_host(self, ip, mac=None):
        """Processes a single discovered host and returns structured host dict."""
        if not mac:
            arp_map = self.get_arp_map()
            mac = arp_map.get(ip, f"DYNAMIC-{ip.replace('.', '')[-6:]}")

        hostname = self.resolve_hostname(ip)
        raw_services = self.quick_service_scan(ip)
        
        # Ensure all service port keys are clean integers
        clean_services = {int(p): n for p, n in raw_services.items()}
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self.lock:
            if mac in self.hosts:
                self.hosts[mac]['last_seen'] = now_str
                self.hosts[mac]['ip'] = ip
                if hostname:
                    self.hosts[mac]['hostname'] = hostname
                
                # Normalize existing dictionary keys to int before updating
                existing_services = {int(p): n for p, n in self.hosts[mac]['services'].items()}
                existing_services.update(clean_services)
                self.hosts[mac]['services'] = existing_services
                self.hosts[mac]['scan_count'] += 1
            else:
                self.hosts[mac] = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname or "Unknown Host",
                    'first_seen': now_str,
                    'last_seen': now_str,
                    'services': clean_services,
                    'scan_count': 1
                }
            self.save_state()
            return self.hosts[mac]

    def save_state(self):
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(self.hosts, f, indent=2)
        except Exception as e:
            logger.error(f"Error saving JSON cache: {e}")

    def load_state(self):
        if os.path.exists(self.cache_file):
            try:
                with open(self.cache_file, 'r') as f:
                    data = json.load(f)
                    # Convert all JSON string keys ("80") to integer keys (80)
                    for mac, host in data.items():
                        if 'services' in host and isinstance(host['services'], dict):
                            host['services'] = {int(p): n for p, n in host['services'].items()}
                    self.hosts = data
            except Exception as e:
                logger.error(f"Error loading JSON cache: {e}")


# ----------------------------------------------------------------------
# GUI Application Engine
# ----------------------------------------------------------------------

class ModernNetworkApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberTracker 2026 - Network Intelligence & Scanner")
        self.root.geometry("1180x780")
        self.root.minsize(950, 650)
        self.root.configure(bg=COLOR_BG)

        self.port_scan_cancel = False
        self.gui_queue = queue.Queue()

        _, local_ip = get_default_gateway()
        ip_parts = local_ip.split(".")
        default_subnet = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

        self.tracker = NetworkHostTracker(subnet=default_subnet)

        self.setup_styles()
        self.build_ui()
        self.start_queue_consumer()

        # Load existing host cache into tree
        self.refresh_inventory_tree()
        self.gui_queue.put(('METRIC_HOSTS', len(self.tracker.hosts)))
        self.log_msg("CyberTracker initialized. Ready for scan.")

    def setup_styles(self):
        self.style = ttk.Style()
        self.style.theme_use('clam')

        self.style.configure(".", background=COLOR_BG, foreground=COLOR_TEXT, font=("Segoe UI", 9))
        self.style.configure("TFrame", background=COLOR_BG)
        self.style.configure("Card.TFrame", background=COLOR_SURFACE, relief="flat")
        self.style.configure("TLabel", background=COLOR_BG, foreground=COLOR_TEXT)
        self.style.configure("Card.TLabel", background=COLOR_SURFACE, foreground=COLOR_TEXT)
        self.style.configure("Muted.TLabel", background=COLOR_SURFACE, foreground=COLOR_MUTED, font=("Segoe UI", 8))

        self.style.configure("Accent.TButton", background=COLOR_ACCENT, foreground="#11111B",
                             font=("Segoe UI", 9, "bold"), borderwidth=0, padding=6)
        self.style.map("Accent.TButton", background=[("active", "#74C7EC")])

        self.style.configure("Danger.TButton", background=COLOR_DANGER, foreground="#11111B",
                             font=("Segoe UI", 9, "bold"), borderwidth=0, padding=6)
        self.style.map("Danger.TButton", background=[("active", "#F5C2E7")])

        self.style.configure("Dark.TButton", background=COLOR_SURFACE_LIGHT, foreground=COLOR_TEXT,
                             font=("Segoe UI", 9), borderwidth=0, padding=6)
        self.style.map("Dark.TButton", background=[("active", COLOR_BORDER)])

        self.style.configure("TEntry", fieldbackground=COLOR_SURFACE_LIGHT, foreground=COLOR_TEXT,
                             insertcolor=COLOR_TEXT, borderwidth=1, relief="solid")

        self.style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        self.style.configure("TNotebook.Tab", background=COLOR_SURFACE, foreground=COLOR_MUTED,
                             padding=[14, 8], font=("Segoe UI", 9, "bold"), borderwidth=0)
        self.style.map("TNotebook.Tab",
                       background=[("selected", COLOR_SURFACE_LIGHT)],
                       foreground=[("selected", COLOR_ACCENT)])

        self.style.configure("Treeview", background=COLOR_SURFACE, foreground=COLOR_TEXT,
                             fieldbackground=COLOR_SURFACE, rowheight=28, borderwidth=0)
        self.style.configure("Treeview.Heading", background=COLOR_SURFACE_LIGHT, foreground=COLOR_TEXT,
                             font=("Segoe UI", 9, "bold"), borderwidth=0)
        self.style.map("Treeview", background=[("selected", COLOR_ACCENT)], foreground=[("selected", "#11111B")])

    def build_ui(self):
        header = ttk.Frame(self.root, padding=(15, 12))
        header.pack(fill=tk.X)

        title_lbl = ttk.Label(header, text="CYBERTRACKER 2026", font=("Segoe UI", 16, "bold"), foreground=COLOR_ACCENT)
        title_lbl.pack(side=tk.LEFT)

        subtitle_lbl = ttk.Label(header, text=" Network Host Discovery & Security Scanner", font=("Segoe UI", 10), foreground=COLOR_MUTED)
        subtitle_lbl.pack(side=tk.LEFT, padx=(5, 0), pady=(4, 0))

        subnet_frame = ttk.Frame(header)
        subnet_frame.pack(side=tk.RIGHT)

        ttk.Label(subnet_frame, text="Target Subnet:", font=("Segoe UI", 9, "bold")).pack(side=tk.LEFT, padx=(0, 6))
        self.subnet_entry = ttk.Entry(subnet_frame, width=18)
        self.subnet_entry.pack(side=tk.LEFT, padx=(0, 8))
        self.subnet_entry.insert(0, self.tracker.subnet)

        self.scan_btn = ttk.Button(subnet_frame, text="▶ Start Subnet Scan", style="Accent.TButton", command=self.run_subnet_scan)
        self.scan_btn.pack(side=tk.LEFT)

        metrics_frame = ttk.Frame(self.root, padding=(15, 0, 15, 10))
        metrics_frame.pack(fill=tk.X)

        self.card_hosts = self.create_metric_card(metrics_frame, "TRACKED HOSTS", "0", COLOR_ACCENT)
        self.card_hosts.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        self.card_changes = self.create_metric_card(metrics_frame, "DISCOVERED TODAY", "0", COLOR_WARNING)
        self.card_changes.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))

        self.card_status = self.create_metric_card(metrics_frame, "SCANNER ENGINE", "IDLE", COLOR_SUCCESS)
        self.card_status.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=(5, 10))

        tab_inventory = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_inventory, text=" Host Inventory")
        self.build_inventory_tab(tab_inventory)

        tab_portscanner = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_portscanner, text=" Port & Service Scanner")
        self.build_portscanner_tab(tab_portscanner)

        tab_tools = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_tools, text=" Network Tools & Discovery")
        self.build_tools_tab(tab_tools)

        tab_logs = ttk.Frame(self.notebook, padding=10)
        self.notebook.add(tab_logs, text=" Live Console Log")
        self.build_logs_tab(tab_logs)

        self.status_bar = ttk.Frame(self.root, padding=(15, 4), style="Card.TFrame")
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        self.status_lbl = ttk.Label(self.status_bar, text="Ready", style="Card.TLabel", font=("Segoe UI", 8))
        self.status_lbl.pack(side=tk.LEFT)

        self.thread_lbl = ttk.Label(self.status_bar, text="Threads: Idle (1)", style="Muted.TLabel")
        self.thread_lbl.pack(side=tk.RIGHT)

    def create_metric_card(self, parent, title, value, accent_color):
        card = ttk.Frame(parent, style="Card.TFrame", padding=10)
        lbl_title = ttk.Label(card, text=title, style="Muted.TLabel")
        lbl_title.pack(anchor="w")
        lbl_val = ttk.Label(card, text=value, font=("Segoe UI", 16, "bold"), foreground=accent_color, style="Card.TLabel")
        lbl_val.pack(anchor="w", pady=(2, 0))
        card.value_label = lbl_val
        return card

    def build_inventory_tab(self, parent):
        filter_bar = ttk.Frame(parent)
        filter_bar.pack(fill=tk.X, pady=(0, 8))

        ttk.Label(filter_bar, text="Search Filter:").pack(side=tk.LEFT, padx=(0, 6))
        self.search_entry = ttk.Entry(filter_bar, width=30)
        self.search_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.search_entry.bind("<KeyRelease>", self.filter_tree_results)

        btn_export_json = ttk.Button(filter_bar, text="Export JSON", style="Dark.TButton", command=self.export_json)
        btn_export_json.pack(side=tk.RIGHT, padx=(4, 0))

        btn_export_csv = ttk.Button(filter_bar, text="Export CSV", style="Dark.TButton", command=self.export_csv)
        btn_export_csv.pack(side=tk.RIGHT)

        cols = ("IP Address", "MAC Address", "Hostname", "Open Services", "Last Seen", "Scan Count")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings", selectmode="browse")

        widths = [130, 150, 180, 220, 150, 90]
        for col, width in zip(cols, widths):
            self.tree.heading(col, text=col, command=lambda _c=col: self.sort_tree_column(_c, False))
            self.tree.column(col, width=width, anchor="w")

        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.context_menu = tk.Menu(self.root, tearoff=0, bg=COLOR_SURFACE, fg=COLOR_TEXT, activebackground=COLOR_ACCENT)
        self.context_menu.add_command(label="Send Target to Port Scanner", command=self.context_send_to_scanner)
        self.context_menu.add_command(label="Open HTTP (Port 80) in Browser", command=lambda: self.context_open_browser("http"))
        self.context_menu.add_command(label="Open HTTPS (Port 443) in Browser", command=lambda: self.context_open_browser("https"))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Copy IP Address", command=lambda: self.context_copy(0))
        self.context_menu.add_command(label="Copy MAC Address", command=lambda: self.context_copy(1))

        self.tree.bind("<Button-3>", self.show_context_menu)
        self.tree.bind("<Double-Button-1>", lambda e: self.context_send_to_scanner())

    def build_portscanner_tab(self, parent):
        top_bar = ttk.Frame(parent)
        top_bar.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(top_bar, text="Target Host IP:").pack(side=tk.LEFT, padx=(0, 6))
        self.port_target_entry = ttk.Entry(top_bar, width=20)
        self.port_target_entry.pack(side=tk.LEFT, padx=(0, 10))

        gateway_ip, _ = get_default_gateway()
        self.port_target_entry.insert(0, gateway_ip)

        ttk.Label(top_bar, text="Port Range:").pack(side=tk.LEFT, padx=(10, 6))
        self.port_range_entry = ttk.Entry(top_bar, width=15)
        self.port_range_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.port_range_entry.insert(0, "1-1024")

        self.start_port_btn = ttk.Button(top_bar, text="▶ Start Port Scan", style="Accent.TButton", command=self.run_full_port_scan)
        self.start_port_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.stop_port_btn = ttk.Button(top_bar, text="⏹ Stop", style="Danger.TButton", command=self.cancel_port_scan, state=tk.DISABLED)
        self.stop_port_btn.pack(side=tk.LEFT)

        self.port_progress = ttk.Progressbar(parent, orient=tk.HORIZONTAL, mode='determinate')
        self.port_progress.pack(fill=tk.X, pady=(0, 10))

        port_cols = ("Port", "Protocol", "State", "Service Banner / Response")
        self.port_tree = ttk.Treeview(parent, columns=port_cols, show="headings")
        self.port_tree.heading("Port", text="PORT")
        self.port_tree.column("Port", width=90)
        self.port_tree.heading("Protocol", text="PROTOCOL")
        self.port_tree.column("Protocol", width=100)
        self.port_tree.heading("State", text="STATE")
        self.port_tree.column("State", width=100)
        self.port_tree.heading("Service Banner / Response", text="SERVICE BANNER / RESPONSE")
        self.port_tree.column("Service Banner / Response", width=500)

        self.port_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        p_scroll = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.port_tree.yview)
        self.port_tree.configure(yscrollcommand=p_scroll.set)
        p_scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def build_tools_tab(self, parent):
        grid_frame = ttk.Frame(parent)
        grid_frame.pack(fill=tk.BOTH, expand=True)

        card_upnp = ttk.Labelframe(grid_frame, text=" SSDP / UPnP Multicast Discovery ")
        card_upnp.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        btn_upnp = ttk.Button(card_upnp, text="Run UPnP SSDP Broadcast", style="Dark.TButton", command=self.run_upnp_discovery)
        btn_upnp.pack(anchor="w", padx=10, pady=8)

        self.upnp_listbox = tk.Listbox(card_upnp, bg=COLOR_SURFACE, fg=COLOR_TEXT, borderwidth=0, highlightthickness=0)
        self.upnp_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

        card_dhcp = ttk.Labelframe(grid_frame, text=" DHCP Server Audit (pfSense & Hardware Routers) ")
        card_dhcp.pack(fill=tk.BOTH, expand=True)

        btn_dhcp = ttk.Button(card_dhcp, text="Audit DHCP Servers", style="Dark.TButton", command=self.run_dhcp_discovery)
        btn_dhcp.pack(anchor="w", padx=10, pady=8)

        self.dhcp_listbox = tk.Listbox(card_dhcp, bg=COLOR_SURFACE, fg=COLOR_TEXT, borderwidth=0, highlightthickness=0)
        self.dhcp_listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))

    def build_logs_tab(self, parent):
        self.log_text = scrolledtext.ScrolledText(parent, wrap=tk.WORD, bg=COLOR_SURFACE, fg=COLOR_TEXT,
                                                   insertbackground=COLOR_TEXT, borderwidth=0)
        self.log_text.pack(fill=tk.BOTH, expand=True)

    def log_msg(self, msg):
        timestamp = datetime.now().strftime("%H:%M:%S")
        formatted = f"[{timestamp}] {msg}"
        self.gui_queue.put(('LOG', formatted))

    # ------------------------------------------------------------------
    # Queue Consumer (GUI Event Stream Handler)
    # ------------------------------------------------------------------

    def start_queue_consumer(self):
        try:
            while True:
                task = self.gui_queue.get_nowait()
                kind = task[0]
                data = task[1]

                if kind == 'LOG':
                    self.log_text.insert(tk.END, f"{data}\n")
                    self.log_text.see(tk.END)
                elif kind == 'STATUS':
                    self.status_lbl.config(text=data)
                elif kind == 'METRIC_HOSTS':
                    self.card_hosts.value_label.config(text=str(data))
                elif kind == 'METRIC_DISCOVERED':
                    self.card_changes.value_label.config(text=str(data))
                elif kind == 'METRIC_ENGINE':
                    self.card_status.value_label.config(text=data[0], foreground=data[1])
                elif kind == 'PORT_PROGRESS':
                    self.port_progress['value'] = data
                elif kind == 'PORT_FOUND':
                    self.port_tree.insert('', tk.END, values=data)
                elif kind == 'LIVE_HOST_UPSERT':
                    self.upsert_host_tree_row(data)

                self.gui_queue.task_done()
        except queue.Empty:
            pass

        act_threads = threading.active_count()
        if act_threads > 1:
            self.thread_lbl.config(text=f"Threads: {act_threads} Active")
        else:
            self.thread_lbl.config(text="Threads: Idle (1)")

        self.root.after(80, self.start_queue_consumer)

    def upsert_host_tree_row(self, host):
        """Generatively inserts or updates a row in the host inventory table."""
        ip = host['ip']
        mac = host['mac']
        hostname = host['hostname']
        
        # Sort ports numerically for display
        sorted_ports = sorted(host['services'].keys())
        services_str = ', '.join([f"{p}:{host['services'][p]}" for p in sorted_ports]) if sorted_ports else 'None'
        
        last_seen = host['last_seen']
        scan_count = host['scan_count']

        existing_item = None
        for item in self.tree.get_children():
            row_vals = self.tree.item(item, 'values')
            if row_vals and (row_vals[1] == mac or row_vals[0] == ip):
                existing_item = item
                break

        if existing_item:
            self.tree.item(existing_item, values=(ip, mac, hostname, services_str, last_seen, scan_count))
        else:
            self.tree.insert('', tk.END, values=(ip, mac, hostname, services_str, last_seen, scan_count))

    # ------------------------------------------------------------------
    # Generative Sweep Workflows
    # ------------------------------------------------------------------

    def run_subnet_scan(self):
        raw_subnet = self.subnet_entry.get()
        subnet = normalize_subnet(raw_subnet)
        self.subnet_entry.delete(0, tk.END)
        self.subnet_entry.insert(0, subnet)

        self.tracker = NetworkHostTracker(subnet=subnet)

        def worker():
            self.gui_queue.put(('METRIC_ENGINE', ("SCANNING", COLOR_WARNING)))
            self.log_msg(f"Initiating Generative Sweep on {subnet}...")

            discovered_count = 0
            host_list = list(self.tracker.network.hosts())[:254]

            def probe_host(ip_obj):
                nonlocal discovered_count
                ip_str = str(ip_obj)

                is_alive = False
                for port in [80, 443, 445, 22, 139, 53, 3389, 8080]:
                    try:
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.settimeout(0.12)
                        res = s.connect_ex((ip_str, port))
                        s.close()
                        if res == 0:
                            is_alive = True
                            break
                    except Exception:
                        pass

                if is_alive:
                    host_info = self.tracker.process_discovered_host(ip_str)
                    discovered_count += 1
                    self.gui_queue.put(('LIVE_HOST_UPSERT', host_info))
                    self.gui_queue.put(('METRIC_HOSTS', len(self.tracker.hosts)))
                    self.gui_queue.put(('METRIC_DISCOVERED', discovered_count))
                    
                    sorted_p = sorted(host_info['services'].keys())
                    ports_found = ', '.join([f"{p}:{host_info['services'][p]}" for p in sorted_p]) or "None"
                    self.log_msg(f"DISCOVERED: {ip_str} [{host_info['mac']}] - {host_info['hostname']} (Ports: {ports_found})")

            self.gui_queue.put(('STATUS', f"Probing {len(host_list)} hosts in parallel..."))
            
            with ThreadPoolExecutor(max_workers=100) as executor:
                executor.map(probe_host, host_list)

            self.gui_queue.put(('STATUS', "Harvesting passive ARP table entries..."))
            arp_map = self.tracker.get_arp_map()

            for ip_str, mac in arp_map.items():
                if self.tracker.is_valid_ip_in_subnet(ip_str) and mac != "FF:FF:FF:FF:FF:FF":
                    host_info = self.tracker.process_discovered_host(ip_str, mac=mac)
                    discovered_count += 1
                    self.gui_queue.put(('LIVE_HOST_UPSERT', host_info))
                    self.gui_queue.put(('METRIC_HOSTS', len(self.tracker.hosts)))

            self.gui_queue.put(('METRIC_ENGINE', ("IDLE", COLOR_SUCCESS)))
            self.gui_queue.put(('STATUS', f"Scan Complete. {len(self.tracker.hosts)} active hosts cataloged."))
            self.log_msg(f"Sweep Finished. Total Active Hosts: {len(self.tracker.hosts)}")

        threading.Thread(target=worker, daemon=True).start()

    def refresh_inventory_tree(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        if not self.tracker or not self.tracker.hosts:
            return

        for mac, info in self.tracker.hosts.items():
            self.upsert_host_tree_row(info)

    def filter_tree_results(self, event=None):
        query = self.search_entry.get().lower().strip()
        for item in self.tree.get_children():
            values = [str(v).lower() for v in self.tree.item(item, 'values')]
            if any(query in v for v in values):
                self.tree.reattach(item, '', tk.END)
            else:
                self.tree.detach(item)

    def run_full_port_scan(self):
        target = self.port_target_entry.get().strip()
        port_range_str = self.port_range_entry.get().strip()

        try:
            if "-" in port_range_str:
                start_p, end_p = map(int, port_range_str.split("-"))
            else:
                start_p, end_p = 1, int(port_range_str)
        except ValueError:
            messagebox.showerror("Invalid Range", "Please enter a valid range format (e.g. 1-1024 or 80)")
            return

        for item in self.port_tree.get_children():
            self.port_tree.delete(item)

        self.port_scan_cancel = False
        self.start_port_btn.config(state=tk.DISABLED)
        self.stop_port_btn.config(state=tk.NORMAL)

        def worker():
            self.log_msg(f"Starting Multi-Threaded Port Scan on {target} ({start_p}-{end_p})")
            total_ports = end_p - start_p + 1

            def grab_banner(ip, port):
                banner = "Open"
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(0.35)
                    if s.connect_ex((ip, port)) == 0:
                        if port in [80, 8080]:
                            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
                        else:
                            s.send(b"\r\n")
                        try:
                            res = s.recv(128).decode('utf-8', errors='ignore').strip()
                            if res:
                                banner = res.splitlines()[0][:60]
                        except Exception:
                            pass
                        s.close()
                        return port, banner
                    s.close()
                except Exception:
                    pass
                return None

            completed = 0
            with ThreadPoolExecutor(max_workers=150) as executor:
                futures = [executor.submit(grab_banner, target, p) for p in range(start_p, end_p + 1)]
                for future in futures:
                    if self.port_scan_cancel:
                        break
                    res = future.result()
                    completed += 1
                    if completed % 10 == 0 or completed == total_ports:
                        pct = int((completed / total_ports) * 100)
                        self.gui_queue.put(('PORT_PROGRESS', pct))

                    if res:
                        port, banner = res
                        self.gui_queue.put(('PORT_FOUND', (port, "TCP", "OPEN", banner)))
                        self.log_msg(f"PORT OPEN: {target}:{port} ({banner})")

            self.gui_queue.put(('PORT_PROGRESS', 100))
            self.log_msg(f"Port scan on {target} finished.")
            self.root.after(0, lambda: self.start_port_btn.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.stop_port_btn.config(state=tk.DISABLED))

        threading.Thread(target=worker, daemon=True).start()

    def cancel_port_scan(self):
        self.port_scan_cancel = True
        self.log_msg("Cancelling port scan engine...")

    def run_upnp_discovery(self):
        self.upnp_listbox.delete(0, tk.END)
        def worker():
            self.log_msg("Sending SSDP UPnP Multicast Query...")
            devs = discover_upnp_ssdp()
            if devs:
                for d in devs:
                    self.root.after(0, lambda _d=d: self.upnp_listbox.insert(tk.END, _d))
                self.log_msg(f"UPnP Discovery found {len(devs)} device(s).")
            else:
                self.root.after(0, lambda: self.upnp_listbox.insert(tk.END, "No UPnP devices detected."))
                self.log_msg("UPnP Discovery finished: No devices responded.")
        threading.Thread(target=worker, daemon=True).start()

    def run_dhcp_discovery(self):
        self.dhcp_listbox.delete(0, tk.END)
        def worker():
            self.log_msg("Auditing network for DHCP servers (Broadcast & Gateway Unicast)...")
            servers = discover_dhcp_servers()
            if servers:
                for s in servers:
                    self.root.after(0, lambda _s=s: self.dhcp_listbox.insert(tk.END, _s))
                self.log_msg(f"DHCP Audit: Discovered {len(servers)} DHCP server(s).")
            else:
                self.root.after(0, lambda: self.dhcp_listbox.insert(tk.END, "No DHCP servers detected."))
                self.log_msg("DHCP Audit finished: No response.")
        threading.Thread(target=worker, daemon=True).start()

    def show_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def context_send_to_scanner(self):
        item = self.tree.selection()
        if item:
            ip = self.tree.item(item[0], 'values')[0]
            self.port_target_entry.delete(0, tk.END)
            self.port_target_entry.insert(0, ip)
            self.notebook.select(1)

    def context_open_browser(self, proto):
        item = self.tree.selection()
        if item:
            ip = self.tree.item(item[0], 'values')[0]
            webbrowser.open(f"{proto}://{ip}")

    def context_copy(self, col_index):
        item = self.tree.selection()
        if item:
            val = self.tree.item(item[0], 'values')[col_index]
            self.root.clipboard_clear()
            self.root.clipboard_append(val)

    def sort_tree_column(self, col, reverse):
        l = [(self.tree.set(k, col), k) for k in self.tree.get_children('')]
        l.sort(reverse=reverse)
        for index, (val, k) in enumerate(l):
            self.tree.move(k, '', index)
        self.tree.heading(col, command=lambda: self.sort_tree_column(col, not reverse))

    def export_json(self):
        if not self.tracker:
            return
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON Files", "*.json")])
        if path:
            with open(path, 'w') as f:
                json.dump(self.tracker.hosts, f, indent=2)
            messagebox.showinfo("Export Complete", f"Data exported to {path}")

    def export_csv(self):
        if not self.tracker:
            return
        path = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV Files", "*.csv")])
        if path:
            with open(path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP Address", "MAC Address", "Hostname", "Services", "First Seen", "Last Seen"])
                for mac, info in self.tracker.hosts.items():
                    sorted_p = sorted(info['services'].keys())
                    services_str = ', '.join([f"{p}:{info['services'][p]}" for p in sorted_p])
                    writer.writerow([info['ip'], mac, info['hostname'], services_str, info['first_seen'], info['last_seen']])
            messagebox.showinfo("Export Complete", f"Data exported to {path}")


# ----------------------------------------------------------------------
# Execution Entry Point
# ----------------------------------------------------------------------

if __name__ == '__main__':
    if GUI_AVAILABLE:
        root = tk.Tk()
        app = ModernNetworkApp(root)
        root.mainloop()
    else:
        print("GUI libraries unavailable. Executing CLI sweep...")
        tracker = NetworkHostTracker("192.168.1.0/24")
        found = tracker.get_arp_map()
        print(f"Scan complete. Found {len(found)} hosts.")
        for ip, mac in found.items():
            print(f"IP: {ip:<15} MAC: {mac:<18}")