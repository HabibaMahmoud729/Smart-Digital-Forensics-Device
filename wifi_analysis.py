import scapy.all as scapy
from scapy.layers.inet import TCP, UDP, ICMP, IP
from scapy.layers.l2 import ARP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP
from scapy.layers.dhcp import DHCP
from scapy.layers.ntp import NTP
from scapy.layers.snmp import SNMP
from scapy.layers.tls.all import TLS
from scapy.layers.dhcp import DHCP
from scapy.layers.ntp import NTP
from scapy.layers.snmp import SNMP
from scapy.packet import Raw
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11ProbeReq
from netaddr import EUI
from netaddr import NotRegisteredError
import geoip2.database
import threading
import time
import socket
import datetime
import netifaces
import struct
import subprocess
import os
import platform
import logging
import atexit
import sys
from fpdf import FPDF
import traceback
sys.setrecursionlimit(10000)
import real_ip
from ip_tracking import update_ip_timeline, mark_as_attacker, append_timeline_to_report, generate_full_pcap_report, _make_table, ip_timeline
#from wpa2_decrypt import process_eapol, decrypt_and_convert, WPA2_PSK, WPA2_SSID
#import wpa2_decrypt
_geoip_reader = None
def _get_geoip():
    global _geoip_reader
    if _geoip_reader is None:
        try:
            _geoip_reader = geoip2.database.Reader('/home/kali/python/GeoLite2-City.mmdb')
        except:
            pass
    return _geoip_reader
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
analysis_output = [] # append the packets in analysis 
alerts_output = [] # append the alerts of attacks
scan_output = set() # append the ports after scanning ports
arp_table = {} # the mac addresses table 
arp_spoof_reported = {}
ARP_REPORT_COOLDOWN = 10 # the wait time to get new report
spoof_counter= 0 # the sum of packets has arp spoof 
#ip_mac_table = {} # 
MAX_ENTRIES = 100 # to output this num of packets only
MAX_LIST_SIZE = 10000 # max limited in list
#scan_done = False # 
ENABLE_ACTIVE_SCAN = False # to control scan in live mode not pcap file
print_lock = threading.Lock() # to smart output
REPORT = "REPORTS" # file name for reports
Analysis='ANALYSIS' #file name for analysis
os.makedirs(REPORT, exist_ok=True) # to make the reports file
os.makedirs(Analysis, exist_ok=True)
port_scan_tracker = {} # store data
PORT_SCAN_THRESHOLD = 5 # max ports
PORT_SCAN_TIME = 5 # min time any device can open new port
port_scan_reported = {}
port_scan_sessions = {}  # ip -> set of dst_ports + details
REPORT_COOLDOWN = 10
last_printed_index = 0 # to print last packets only without repeet
ip_mac_map = {}          # mac -> set of src IPs
ip_spoof_reported = {}   # ip -> last report time
IP_SPOOF_COOLDOWN = 10
IP_SPOOF_IP_THRESHOLD = 2
gateway_mac = None
ip_mac_first = {}
DNS_WHITELIST = {
    "google.com.":   {"142.250.185.46", "216.58.215.46"},
    "facebook.com.": {"157.240.241.35", "31.13.92.36"},
}
DNS_SPOOF_COOLDOWN = 10
dns_spoof_reported = {}   # domain -> last report time
DOS_EXCLUDED_PORTS = {
    443, 80, 8080, 53,      # Web & DNS
    5228, 5229, 5230,       # Google services
    3478, 3479,             # STUN / WebRTC
    8801, 8802,             # Zoom
    5004,                   # RTP / VoIP
    123,                    # NTP
    1900,                   # SSDP
    5353,                   # mDNS
}
dns_txid_tracker = {}    
DNS_TXID_TIMEOUT = 5      
DOS_PACKET_THRESHOLD = 50     
DOS_TIME = 5                 
DOS_COOLDOWN = 10           
udp_dos_tracker  = {}   # ip_src -> [timestamps]
icmp_dos_tracker = {}   # ip_src -> [timestamps]
syn_dos_tracker  = {}   # ip_src:dst_port -> [timestamps]
udp_dos_reported  = {}  # ip_src -> last report time
icmp_dos_reported = {}  # ip_src -> last report time
syn_dos_reported  = {}  # key    -> last report time
time_now = datetime.datetime.now().strftime("%H:%M:%S")
udp_ddos_tracker = {}   # ip_dst -> {ip_src: count}
udp_ddos_reported = {}  # ip_dst -> last report time
DDOS_PACKET_THRESHOLD = 5   # num of packets from ip
DDOS_SOURCE_THRESHOLD = 3    #num of ips
DDOS_TIME = 10                # attack refresh time
DDOS_COOLDOWN = 10
external_spoof_reported = {}  # ip_src -> last report time
EXTERNAL_SPOOF_COOLDOWN = 10
icmp_ddos_tracker = {}   # ip_dst -> {ip_src: [timestamps]}
icmp_ddos_reported = {}  # ip_dst -> last report time
ICMP_DDOS_PACKET_THRESHOLD = 5   # num of packets from ip
ICMP_DDOS_SOURCE_THRESHOLD = 3    # num of ips
ICMP_DDOS_TIME = 10                # attack refresh time
ICMP_DDOS_COOLDOWN = 10
syn_flood_tracker = {}   # ip_dst:port -> {ip_src: [timestamps]}
syn_flood_reported = {}  # ip_dst:port -> last report time
SYN_FLOOD_PACKET_THRESHOLD = 5   # num of packets from ip
SYN_FLOOD_SOURCE_THRESHOLD = 3    # num of ips
SYN_FLOOD_TIME = 10                # attack refresh time
SYN_FLOOD_COOLDOWN = 10
botnet_tracker = {}    # ip_src -> [timestamps]  للـ heartbeat
botnet_dns_tracker = {}  # ip_src -> set of domains
botnet_reported = {}   # ip_src -> last report time
BOTNET_HEARTBEAT_THRESHOLD = 30  # connection to ip in short time
BOTNET_HEARTBEAT_TIME = 60      
BOTNET_DNS_THRESHOLD = 20       
BOTNET_DNS_TIME = 10           
BOTNET_COOLDOWN = 15
icmp_meta = {}
syn_meta = {}
KNOWN_APS = {
    "aa:bb:cc:dd:ee:ff": "HomeNetwork",
    "11:22:33:44:55:66": "Company_WiFi", 
}
block_prompt_tracker = {}      # mac -> last time a prompt was shown
BLOCK_PROMPT_COOLDOWN = 30      # seconds before asking again about the same MAC
block_prompt_lock = threading.Lock()
block_requests = []            # pending block requests
block_current = None           # {"mac", "ip", "device"} being asked
rogue_ap_tracker = {}
rogue_ap_reported = {}
ROGUE_AP_COOLDOWN = 30
deauth_tracker = {}
deauth_sessions = {}
DEAUTH_THRESHOLD = 10
DEAUTH_TIME_WINDOW = 10
DEAUTH_COOLDOWN = 30
deauth_reported = {}
ap_tracker = {}        # ssid -> {bssid: set of seen_bssids}
evil_twin_reported = {}
EVIL_TWIN_COOLDOWN = 30
num=0
import queue
stdin_queue = queue.Queue()
block_queue = queue.Queue()
MONITOR_IFACE = None
MONITOR_CHANNEL = None
MY_BSSID = ""
##############################block mac address##############################
def block_mac(mac_address, ip_address):
    system = platform.system()
    while True:
        would_block = input("you want to block this mac? y/n:").strip().lower()
        if would_block == 'y':
            if system == "Linux":
                cmd = f"sudo ebtables -A INPUT -s {mac_address} -j DROP"
                subprocess.call(cmd, shell=True)
                print(f"[REAL BLOCK] MAC {mac_address} blocked.")
            elif system == "Windows":
                cmd = f"netsh advfirewall firewall add rule name='BlockIP' dir=in action=block remoteip={ip_address}"
                subprocess.call(cmd, shell=True)
            else:
                print(f"[SIMULATION] Would block MAC: {mac_address}")
            break
        elif would_block == 'n':
            print(f"Ignored MAC {mac_address}")
            break
        else:
            print("Invalid input, try again.")
def block_mac_threaded(mac_address, ip_address, device_type="Unknown"):
    with block_prompt_lock:
        last_asked = block_prompt_tracker.get(mac_address, 0)
        if time.time() - last_asked < BLOCK_PROMPT_COOLDOWN:
            return 
        block_prompt_tracker[mac_address] = time.time()
    block_requests.append({"mac": mac_address, "ip": ip_address, "device": device_type})
def stdin_listener():
    while True:
        line = sys.stdin.readline().strip().lower()
        if line in ("y", "n"):
            stdin_queue.put(line)
def execute_block(mac, ip):
    system = platform.system()
    if system == "Linux":
        cmd = f"sudo ebtables -A INPUT -s {mac} -j DROP"
        subprocess.call(cmd, shell=True)
        print(f"[REAL BLOCK] MAC {mac} blocked.")
    elif system == "Windows":
        cmd = f"netsh advfirewall firewall add rule name='BlockIP' dir=in action=block remoteip={ip}"
        subprocess.call(cmd, shell=True)
    else:
        print(f"[SIMULATION] Would block MAC: {mac}")
##############################attacker activity##############################
def get_attacker_activity(packet):
    if packet.haslayer(ARP):
        if packet[ARP].op == 1:  # ARP Request
            return "ARP Request - Network scanning"
        elif packet[ARP].op == 2:  # ARP Reply
            return "ARP Reply - Possible spoofing attempt"
    elif packet.haslayer(TCP):
        sport = packet[TCP].sport
        dport = packet[TCP].dport
        return f"TCP traffic using source port {sport} and destination port {dport}"
    elif packet.haslayer(UDP):
        sport = packet[UDP].sport
        dport = packet[UDP].dport
        return f"UDP traffic using source port {sport} and destination port {dport}"
    elif packet.haslayer(ICMP):
        return "ICMP traffic (ping or network discovery)"
    else:
        return "Other network activity"
##############################save report##############################
def save_report(filename, content):
    pdf_path = os.path.join(REPORT, filename.replace(".txt", ".pdf"))
    try:
        from fpdf import FPDF
        class DarkPDF(FPDF):
            def header(self):
                self.set_fill_color(0, 0, 0)
                self.rect(0, 0, 216, 280, "F")
            def footer(self):
                pass
        pdf = DarkPDF(orientation="P", unit="mm", format="Letter")
        pdf.add_page()
        pdf.set_auto_page_break(auto=True, margin=10)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Courier", "", 7)
        for line in content.split("\n"):
            s = line
            for a, b in [("═","="), ("─","-"), ("┌","+"), ("└","+"), ("┐","+"), ("┘","+"), ("│","|"), ("├","+"), ("┤","+"), ("●","*")]:
                s = s.replace(a, b)
            s = s.encode("latin-1", "replace").decode("latin-1")
            pdf.cell(0, 3.2, s, new_x="LMARGIN", new_y="NEXT")
        pdf.output(pdf_path)
    except:
        try:
            import subprocess, tempfile
            with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as _tf:
                _tf.write(content)
                _tf_path = _tf.name
            subprocess.run(
                ["/usr/sbin/cupsfilter", "-o", "media=Letter", _tf_path],
                stdout=open(pdf_path, "wb"), stderr=subprocess.DEVNULL, timeout=30
            )
            os.unlink(_tf_path)
        except:
            pass
try:
    ##############################to know Device name##############################
    def Device_type(ttl, window):
        if ttl is None or window is None:
            return "Unknown"
        elif ttl >= 128:
            if 64240 <= window <= 65535:
                return "Windows"
            elif 8192 <= window < 64240:
                return "Windows Variant"
            else:
                return "Windows-like"
        elif 64 <= ttl < 128:
            if window in [5840, 29200, 14600]:
                return "Linux"
            elif window == 65535:
                return "macOS / iOS"
            elif window == 32120:
                return "FreeBSD"
            elif window == 8760:
                return "Android"
            else:
                return "Unix-like"
        elif 32 <= ttl < 64:
            return "Embedded Device or Network Device"
        else:
            return "Unknown"
    known_fingerprints = {
        (('MSS', 1460), ('WScale', 7), ('SAckOK', b''), ('Timestamp', None)): "Linux",
        (('MSS', 1460), ('WScale', 8), ('SAckOK', b'')): "Windows",
        (('MSS', 1460), ('WScale', 2), ('SAckOK', b''), ('Timestamp', None)): "MacOS",
        (('MSS', 1460), ('WScale', 4), ('SAckOK', b''), ('Timestamp', None)): "Android",
        (('MSS', 1460), ('WScale', 6), ('SAckOK', b''), ('Timestamp', None)): "iOS (iPhone)",
        (('MSS', 1460), ('WScale', 3), ('SAckOK', b''), ('Timestamp', None)): "FreeBSD",
        (('MSS', 1460), ('WScale', 5), ('SAckOK', b''), ('Timestamp', None)): "Router (Cisco/Juniper)",
        (('MSS', 1380), ('WScale', 8), ('SAckOK', b''), ('Timestamp', None)): "Embedded Device (IoT)",
    }
    def Device_fingerprint(packet):
        if not packet.haslayer(TCP):
            return None
        options = packet[TCP].options
        fingerprint = []
        for opt in options:
            if isinstance(opt, tuple) and len(opt) == 2:
                key, value = opt
                if key in ['MSS', 'WScale', 'SAckOK', 'Timestamp']:
                    fingerprint.append((key, value))
        fingerprint = tuple(sorted(fingerprint))
        return fingerprint
    def get_mac_vendor(mac):
        try:
            if not mac or mac == 'N/A' or len(mac) < 17: 
                return "Unknown Vendor"
            mac_addr = EUI(mac)
            return mac_addr.oui.registration().org
        except NotRegisteredError:
            return "Unknown Vendor"
        except:
            return "Unknown Vendor"
    ##############################to know location##############################
    def locate(ip):
        try:
            socket.inet_aton(ip)
        except:
            return "Invalid IP"
        if (ip.startswith('192.168.') or
            ip.startswith('10.') or
            ip.startswith('172.16.') or
            ip.startswith('127.')):
            return "Local Network"
        try:
            reader = _get_geoip()
            if reader:
                response = reader.city(ip)
                city = response.city.name or ""
                country = response.country.name or ""
                return f"{city}, {country}".strip(", ")
        except:
            pass
        return ip
    ##############################to know flags##############################
    def Flags(flag):
        if flag == 'P':
            return 'PSH (Push)'
        elif flag == 'S':
            return 'SYN (Synchronize)'
        elif flag == 'A':
            return 'ACK (Acknowledgment)'
        elif flag == 'F':
            return 'FIN (Finish)'
        elif flag == 'R':
            return 'RST (Reset)'
        elif flag == 'U':
            return 'URG (Urgent)'
        elif flag == 'E':
            return 'ECE (ECN Echo)'
        elif flag == 'C':
            return 'CWR (Congestion Window Reduced)'
        else: return 'NOT FOUND'
##############################to print with threading##############################
    def output_thread():
        while True:
            time.sleep(5)
            render_output()
    def run_scan():
        global scan_output
        if not ENABLE_ACTIVE_SCAN:
            return
        try:
            gws = netifaces.gateways()
            default = gws.get('default', {})
            ip = default.get(netifaces.AF_INET, [None])[0]
            if not ip:
                return
        except:
            print("Error getting gateway IP")
            return
        print(f"Scanning gateway: {ip}")
        scan_output = scan_all_ports(ip)
    ##############################Output##############################
    def render_output():
        global last_printed_index
        with print_lock:
            new_entries = analysis_output[last_printed_index:]
            if new_entries:
                if mode=='1':
                    header = "=" * 30 + "\n LIVE TRAFFIC ANALYSIS \n" + "=" * 30
                else:
                    header = "=" * 30 + "\n File TRAFFIC ANALYSIS \n" + "=" * 30
                print(header)
                with open(os.path.join(Analysis, "live_output.txt"), "a") as f:
                    f.write(header + "\n")
                    for entry in new_entries:
                        print(entry)
                        f.write(entry + "\n")
                last_printed_index = len(analysis_output)
            if len(analysis_output) > MAX_LIST_SIZE:
                del analysis_output[:len(analysis_output) - MAX_LIST_SIZE]
                last_printed_index = len(analysis_output)
            if alerts_output:
                print("\n" + "="*30)
                print(" ALERTS ")
                print("="*30)
                for alert in alerts_output: 
                    print(alert)
                alerts_output.clear()
            global block_requests, block_current
            if block_requests or block_current is not None:
                print("\n" + "="*30)
                print(" BLOCK REQUESTS ")
                print("="*30)
                if block_current is None:
                    block_current = block_requests.pop(0)
                req = block_current
                print(f"Block {req['mac']} ({req['ip']}) [{req['device']}]? y/n:")
                try:
                    resp = stdin_queue.get_nowait()
                    if resp == 'y':
                        execute_block(req['mac'], req['ip'])
                        analysis_output.append(f"[+] MAC {req['mac']} ({req['ip']}) BLOCKED")
                    else:
                        analysis_output.append(f"[-] MAC {req['mac']} ({req['ip']}) IGNORED")
                    block_current = None
                except queue.Empty:
                    pass
            if not ENABLE_ACTIVE_SCAN:
                return
            else:
                if scan_output:
                    print("\n" + "="*30)
                    print(" OPEN PORTS SCANNING ")
                    print("="*30)
                    for port in sorted(scan_output):
                        print(port)
    ##############################Port scan##############################
    def scan_port(ip, port):
        try:
            pkt = IP(dst=ip)/TCP(dport=port, flags='S')
            resp = scapy.sr1(pkt, timeout=1, verbose=0)
        except Exception:
            return False
        if resp is None:
            return False
        elif resp.haslayer(TCP):
            if resp.getlayer(TCP).flags == 0x12:  ## 0x02. syn 0x10. ack 
                scapy.send(IP(dst=ip)/TCP(dport=port, flags='R'), verbose=0)
                return True
            elif resp.getlayer(TCP).flags == 0x14: ## 0x04. rest 0x10. ack 
                return False
        return False
    def scan_all_ports(ip):
        open_ports = set()
        for port in range(20, 1025):
            if scan_port(ip, port): ## if not scan_port(ip, port):
                try:
                    service = socket.getservbyport(port)
                except:
                    service = "Unknown"
                insecure_protocols = [20, 21, 23, 80]
                if port in insecure_protocols:
                    open_ports.add(f"Alert!! Insecure Protocol (Port {port} OPEN ({service}))") 
                else:
                    open_ports.add(f"Port {port} OPEN ({service})")
        return open_ports
    ##############################Monitor Mode LLC/SNAP Decoder##############################
    def decode_monitor_data(packet):
        if not packet.haslayer(scapy.RadioTap):
            return packet
        if packet.haslayer(IP):
            return packet
        if not packet.haslayer(scapy.Dot11):
            return packet
        raw = bytes(packet)
        rt_len = packet[scapy.RadioTap].len
        dot11 = packet[scapy.Dot11]
        fc = dot11.type
        if fc != 2:
            return packet
        dot11_len = 24
        if dot11.FCfield & 0x80:
            dot11_len += 4
        off = rt_len + dot11_len
        if off + 8 > len(raw):
            return packet
        llc = raw[off:off+3]
        if llc != b'\xaa\xaa\x03':
            return packet
        oui = raw[off+3:off+6]
        if oui == b'\x00\x00\x00':
            etype = (raw[off+6] << 8) | raw[off+7]
        else:
            return packet
        payload = raw[off+8:]
        from scapy.layers.l2 import Ether
        dec = Ether(src=dot11.addr2, dst=dot11.addr1, type=etype) / payload
        return dec
    ##############################Analysis##############################
    def process_packet(packet):# tcp udp icmp arp dns http https 
        global num
        wifi_bssid = ""
        wifi_signal = ""
        wifi_frame = ""
        if packet.haslayer(scapy.RadioTap) and packet.haslayer(scapy.Dot11):
            if MY_BSSID:
                pkt_bssid = (packet[scapy.Dot11].addr3 or "").lower()
                if pkt_bssid and pkt_bssid != MY_BSSID:
                    return
            wifi_bssid = packet[scapy.Dot11].addr3 or "N/A"
            try:
                wifi_signal = f"{packet[scapy.RadioTap].dBm_AntSignal} dBm"
            except:
                pass
            wifi_frame = {0: "Management", 1: "Control", 2: "Data"}.get(packet.type, "Unknown")
        packet = decode_monitor_data(packet)
        try:
            flags_info = "N/A"
            time_now = datetime.datetime.now().strftime("%H:%M:%S")
            ###############to know device name###############
            window = None
            ttl = None
            try:
                mac_src = packet.src
                mac_dst = packet.dst
            except:
                mac_src = "N/A"
                mac_dst = "N/A"
            device_type_guess = "Unknown"
            device_type_guess2 = "Unknown"
            fingerprint = None 
            if packet.haslayer(IP):
                ttl = packet[IP].ttl
            if packet.haslayer(TCP): 
                window = packet[TCP].window
            if packet.haslayer(TCP) and packet[TCP].flags == 0x02:
                fingerprint = Device_fingerprint(packet)
            if fingerprint and fingerprint in known_fingerprints:
                device_type_guess = known_fingerprints[fingerprint]
                device_type_guess2 = known_fingerprints[fingerprint]
            elif mac_src:
                mac_vendor = get_mac_vendor(mac_src)
                device_type_guess = f"{mac_vendor}"
                mac_vendor2 = get_mac_vendor(mac_dst)
                device_type_guess2 = f"{mac_vendor2}"
            else:
                device_type_guess = Device_type(ttl, window)
                device_type_guess2 = Device_type(ttl, window)
            ###############to know ip###############
            if packet.haslayer(IP):
                ip_src = packet[IP].src
                ip_dst = packet[IP].dst
            else:
                ip_src = "N/A"
                ip_dst = "N/A"
            ###############to know service###############
            def get_service(src_port,dst_port):
                try:
                    ## local ip: dst
                    serv_src = socket.getservbyport(src_port)
                    serv_dst ="Not Found"
                except:
                    try:
                        ##m local ip: src
                        serv_dst = socket.getservbyport(dst_port)
                        serv_src ="Not Found"
                    except:
                        serv_src ="Not Found"
                        serv_dst ="Not Found"
                return serv_src,serv_dst
            ###############to get port###############
            try:
                dst_port = packet.dport#not icmp and ARP
                src_port = packet.sport#not icmp and ARP
            except:
                pass
            detect_ip_spoofing(packet, device_type_guess, time_now)
            detect_botnet(packet, device_type_guess, time_now)
            ##############################to know protocol and print analysis##############################
            if packet.haslayer(scapy.RadioTap):
                if packet.haslayer(scapy.Dot11):
                # BSSID filter: skip packets not from our network
                    if MY_BSSID:
                        pkt_bssid = (packet[scapy.Dot11].addr3 or "").lower()
                        if pkt_bssid and pkt_bssid != MY_BSSID:
                            return
                    detect_rogue_ap(packet, time_now)
                    detect_deauthentication(packet, time_now)
                    detect_evil_twin(packet, time_now)
                    mac_src = packet[scapy.Dot11].addr2 or "N/A"
                    mac_dst = packet[scapy.Dot11].addr1 or "N/A"
                    mac_bssid = packet[scapy.Dot11].addr3 or "N/A"

                    frame_type = packet[scapy.Dot11].type
                    frame_subtype = packet[scapy.Dot11].subtype

                    frame_name = "Unknown"
                    if frame_type == 0:  # Management
                        subtypes = {
                            0: "Association Request",
                            1: "Association Response",
                            2: "Reassociation Request",
                            4: "Probe Request",
                            5: "Probe Response",
                            8: "Beacon",
                            10: "Disassociation",
                            11: "Authentication",
                            12: "Deauthentication",
                        }
                        frame_name = f"Management - {subtypes.get(frame_subtype, f'Subtype {frame_subtype}')}"
                    elif frame_type == 1:
                        frame_name = "Control"
                    elif frame_type == 2:
                        frame_name = "Data"

                    ssid = "N/A"
                    if packet.haslayer(Dot11Elt):
                        try:
                            ssid = packet[Dot11Elt].info.decode(errors='ignore') or "Hidden"
                        except:
                            ssid = "N/A"

                    signal = "N/A"
                    try:
                        signal = f"{packet[scapy.RadioTap].dBm_AntSignal} dBm"
                    except:
                        pass

                    wifi_bssid = mac_bssid
                    wifi_signal = signal
                    wifi_frame = frame_name
                    if frame_type != 2:  # Management & Control
                        analysis_output.append(
                        f'''Packet No. {num}    Time: {time_now}
                        Source MAC:      {mac_src}  ({get_mac_vendor(mac_src)})
                        Destination MAC: {mac_dst}  ({get_mac_vendor(mac_dst)})
                        BSSID:           {mac_bssid}
                        Frame Type:      {frame_name}
                        SSID:            {ssid}
                        Signal:          {signal}
                        Length:          {len(packet)}
                        Source IP:       {ip_src if ip_src != "N/A" else "N/A"}
                        Destination IP:  {ip_dst if ip_dst != "N/A" else "N/A"}
                        INFO:            ({locate(ip_src) if ip_src != "N/A" else "N/A"} -> {locate(ip_dst) if ip_dst != "N/A" else "N/A"})
                        Device Type:     Source({device_type_guess}) Destination({device_type_guess2})
                        Flags:           ({flags_info})
                        {("-" * 80)}
                        '''
                        )
            # For Dot11: handle ARP and Data frames
            if packet.haslayer(scapy.IPv6) and not packet.haslayer(IP):
                return
            if packet.haslayer(ARP):
                proto='ARP'
                Arp_Spoofing(packet, device_type_guess, device_type_guess2, time_now)
                if packet.haslayer(TCP):
                    flag = packet[TCP].sprintf("%TCP.flags%")
                    flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                f'''Packet No. {num}    Time: {time_now}
                Source IP: {packet[ARP].psrc}  Source MAC: {packet[ARP].hwsrc}
                Destination IP: {packet[ARP].pdst} Destination MAC: {packet[ARP].hwdst}
                Protocol: {proto} Length: {len(packet)}
                Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                Flags: ({flags_info})
                {("-" * 100)}
                '''
                )
                update_ip_timeline(packet[ARP].psrc, packet[ARP].hwsrc, packet[ARP].pdst, packet[ARP].hwdst, "N/A", proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(ICMP):
                proto='ICMP'
                detect_icmp_dos(packet, device_type_guess, time_now)
                detect_icmp_ddos(packet, device_type_guess, time_now)
                if packet.haslayer(TCP):
                    flag = packet[TCP].sprintf("%TCP.flags%")
                    flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                f'''Packet No. {num}    Time: {time_now}
                Source IP: {ip_src}  Source MAC: {mac_src}
                Destination IP: {ip_dst} Destination MAC: {mac_dst}
                Protocol: {proto} Length: {len(packet)}
                INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                Flags: ({flags_info})
                {("-" * 80)}
                '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, "N/A", proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(DNS):
                serv_src, serv_dst = get_service(src_port, dst_port)
                proto='DNS'
                detect_dns_spoof(packet, device_type_guess, time_now)
                if packet.haslayer(TCP):
                    flag = packet[TCP].sprintf("%TCP.flags%")
                    flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                f'''Packet No. {num}    Time: {time_now}
                Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                Protocol: {proto} Length: {len(packet)}
                INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                Flags: ({flags_info})
                {("-" * 80)}
                '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(HTTP):
                proto='HTTP'
                if packet.haslayer(TCP):
                    flag = packet[TCP].sprintf("%TCP.flags%")
                    flags_info = ", ".join([Flags(i) for i in flag])
                serv_src, serv_dst = get_service(src_port, dst_port)
                analysis_output.append(
                f'''Packet No. {num}    Time: {time_now}
                Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                Protocol: {proto} Length: {len(packet)}
                INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                Flags: ({flags_info})
                {("-" * 80)}
                '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TLS):
                serv_src, serv_dst = get_service(src_port, dst_port)
                if packet.haslayer(TCP) and (packet.dport == 443 or packet.sport == 443):
                    proto="HTTPS"
                    if packet.haslayer(TCP):
                        flag = packet[TCP].sprintf("%TCP.flags%")
                        flags_info = ", ".join([Flags(i) for i in flag])
                    analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                {("-" * 80)}
                    '''
                    )
                    update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
                else:
                    proto="TLS"
                    if packet.haslayer(TCP):
                        flag = packet[TCP].sprintf("%TCP.flags%")
                        flags_info = ", ".join([Flags(i) for i in flag])
                    analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                {("-" * 80)}
                    '''
                    )
                    update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP) and (src_port == 21 or dst_port == 21):
                proto = 'FTP'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flag = packet[TCP].sprintf("%TCP.flags%")
                flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP) and (src_port == 22 or dst_port == 22):
                # SSH or SFTP - distinguish by payload or just label as SSH/SFTP
                serv_src, serv_dst = get_service(src_port, dst_port)
                flag = packet[TCP].sprintf("%TCP.flags%")
                flags_info = ", ".join([Flags(i) for i in flag])
                # SFTP runs over SSH, so we check payload hint
                proto = 'SFTP' if packet.haslayer(Raw) and b'sftp' in bytes(packet[Raw]).lower() else 'SSH'
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP) and (src_port == 25 or dst_port == 25):
                proto = 'SMTP'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flag = packet[TCP].sprintf("%TCP.flags%")
                flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP) and (src_port == 110 or dst_port == 110):
                proto = 'POP3'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flag = packet[TCP].sprintf("%TCP.flags%")
                flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP) and (src_port == 143 or dst_port == 143):
                proto = 'IMAP'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flag = packet[TCP].sprintf("%TCP.flags%")
                flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP) and (src_port == 389 or dst_port == 389):
                proto = 'LDAP'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flag = packet[TCP].sprintf("%TCP.flags%")
                flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP) and (src_port == 445 or dst_port == 445):
                proto = 'SMB'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flag = packet[TCP].sprintf("%TCP.flags%")
                flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP) and (src_port == 636 or dst_port == 636):
                proto = 'LDAPS'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flag = packet[TCP].sprintf("%TCP.flags%")
                flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP) and (src_port == 3389 or dst_port == 3389):
                proto = 'RDP'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flag = packet[TCP].sprintf("%TCP.flags%")
                flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP) and (src_port == 23 or dst_port == 23):
                proto = 'TELNET'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flag = packet[TCP].sprintf("%TCP.flags%")
                flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(TCP):
                detect_syn_flood(packet, device_type_guess, time_now)
                detect_syn_dos(packet, device_type_guess, time_now)
                serv_src, serv_dst = get_service(src_port, dst_port)
                if src_port == 80 or dst_port == 80 or src_port == 8080 or dst_port == 8080:
                    proto = 'HTTP'
                else:
                    proto = 'TCP'
                if packet.haslayer(TCP):
                    flag = packet[TCP].sprintf("%TCP.flags%")
                    flags_info = ", ".join([Flags(i) for i in flag])
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                {("-" * 80)}
                    '''
                    )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
                port_scanning(packet, time_now, device_type_guess)
            elif packet.haslayer(UDP) and (src_port == 67 or dst_port == 67 or src_port == 68 or dst_port == 68):
                proto = 'DHCP'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flags_info = "N/A"
                dhcp_msg_type = "Unknown"
                if packet.haslayer(DHCP):
                    for opt in packet[DHCP].options:
                        if opt[0] == 'message-type':
                            dhcp_types = {1:'Discover', 2:'Offer', 3:'Request', 4:'Decline', 5:'ACK', 6:'NAK', 7:'Release', 8:'Inform'}
                            dhcp_msg_type = dhcp_types.get(opt[1], "Unknown")
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto}  DHCP Message: {dhcp_msg_type}  Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(UDP) and (src_port == 69 or dst_port == 69):
                proto = 'TFTP'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flags_info = "N/A"
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto} Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(UDP) and (src_port == 123 or dst_port == 123):
                proto = 'NTP'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flags_info = "N/A"
                ntp_mode = "Unknown"
                if packet.haslayer(NTP):
                    ntp_modes = {1:'Symmetric Active', 2:'Symmetric Passive', 3:'Client', 4:'Server', 5:'Broadcast', 6:'Control', 7:'Private'}
                    ntp_mode = ntp_modes.get(packet[NTP].mode, "Unknown")
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto}  NTP Mode: {ntp_mode}  Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(UDP) and (src_port == 161 or dst_port == 161 or src_port == 162 or dst_port == 162):
                proto = 'SNMP'
                serv_src, serv_dst = get_service(src_port, dst_port)
                flags_info = "N/A"
                snmp_community = "N/A"
                snmp_version = "N/A"
                if packet.haslayer(SNMP):
                    try:
                        snmp_community = packet[SNMP].community.decode() if isinstance(packet[SNMP].community, bytes) else str(packet[SNMP].community)
                        snmp_version = packet[SNMP].version
                    except:
                        pass
                analysis_output.append(
                    f'''Packet No. {num}    Time: {time_now}
                    Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                    Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                    Protocol: {proto}  SNMP Version: {snmp_version}  Community: {snmp_community}  Length: {len(packet)}
                    INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                    Flags: ({flags_info})
                    {("-" * 80)}
                    '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            elif packet.haslayer(UDP):
                serv_src, serv_dst = get_service(src_port, dst_port)
                proto='UDP'
                detect_udp_dos(packet, device_type_guess, time_now)
                detect_udp_ddos(packet, device_type_guess, time_now)
                flags_info = "N/A"
                analysis_output.append(
                f'''Packet No. {num}    Time: {time_now}
                Source IP: {ip_src}  Source MAC: {mac_src}  Source Port: {src_port}({serv_src})
                Destination IP: {ip_dst} Destination MAC: {mac_dst}  Destination Port(Service): {dst_port}({serv_dst})
                Protocol: {proto} Length: {len(packet)}
                INFO. ({locate(ip_src)} -> {locate(ip_dst)})   Device Type: Source({device_type_guess}) Destination({device_type_guess2})
                Flags: ({flags_info})
                {("-" * 80)} 
                '''
                )
                update_ip_timeline(ip_src, mac_src, ip_dst, mac_dst, dst_port, proto, flags_info, device_type_guess, time_now)
            else:
                proto= "Unknown Protocol"
                analysis_output.append(proto)
            if wifi_bssid and proto not in ("Unknown Protocol",):
                wifi_line = f"        WiFi >> BSSID: {wifi_bssid}  Signal: {wifi_signal}  Frame: {wifi_frame}"
                last_entry = analysis_output[-1]
                lines = last_entry.split('\n')
                for i, line in enumerate(lines):
                    if line.strip().startswith('---'):
                        lines.insert(i, wifi_line)
                        analysis_output[-1] = '\n'.join(lines)
                        break
        except RecursionError:
            pass
        except Exception as e:
            print(f"[PACKET ERROR] {e}")
            traceback.print_exc()
except RecursionError:
    pass
except Exception as e:
    print(f"[PACKET ERROR] {e}")
    traceback.print_exc()

#######################################################'Attacks'#######################################################
     ##############################port scanning##############################
def port_scanning(packet, time_now, device_type_guess):
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return
    if packet[TCP].flags != 0x02:
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    src_port= packet[TCP].sport
    dst_port = packet[TCP].dport
    if gateway_mac and packet.src == gateway_mac:
        return
    current_time = time.time()
    attacker_activity= get_attacker_activity(packet)
    EXCLUDED_DST_PORTS = {443, 80, 8080, 53}
    if dst_port in EXCLUDED_DST_PORTS:
        return
    if ip_src not in port_scan_tracker:
        port_scan_tracker[ip_src] = []
    port_scan_tracker[ip_src].append((src_port, dst_port, ip_dst, current_time, num))
    port_scan_tracker[ip_src]= [
        (sp, dp, idst, t, pkt_num)
        for (sp, dp, idst, t, pkt_num) in port_scan_tracker[ip_src]
        if current_time - t <= PORT_SCAN_TIME
        ]
    unique_dst_ports={dp for _, dp, _, _, _ in port_scan_tracker[ip_src]}
    unique_src_ports={sp for sp, _, _, _, _ in port_scan_tracker[ip_src]}
    EXCLUDED_FIXED_PORTS = {20, 21}
    if unique_src_ports.issubset(EXCLUDED_FIXED_PORTS) and len(unique_dst_ports) < PORT_SCAN_THRESHOLD * 3:
        return
    if len(unique_dst_ports) >= PORT_SCAN_THRESHOLD:
        last_reported = port_scan_reported.get(ip_src, 0)
        if current_time - last_reported < REPORT_COOLDOWN:
            if ip_src in port_scan_sessions:
                port_scan_sessions[ip_src]['dst_ports'].update(unique_dst_ports)
                port_scan_sessions[ip_src]['src_ports'].update(unique_src_ports)
                port_scan_sessions[ip_src]['details'] = port_scan_tracker[ip_src].copy()
                port_scan_sessions[ip_src]['device'] = device_type_guess
                port_scan_sessions[ip_src]['mac'] = packet.src
                port_scan_sessions[ip_src]['attacker_activity']= attacker_activity
            return
        port_scan_reported[ip_src] = current_time
        port_scan_sessions[ip_src] = {
            'dst_ports': set(unique_dst_ports),
            'src_ports': set(unique_src_ports),
            'details': port_scan_tracker[ip_src].copy(),
            'device': device_type_guess,
            'mac': packet.src,
            'time': time_now
        }
        port_scan_tracker[ip_src] = []
        #################################### to print unique report #########################################
def flush_port_scan_reports():
    for ip_src, session in port_scan_sessions.items():
        unique_src_ports = session['src_ports']
        unique_dst_ports = session['dst_ports']
        attcker_acktivity = session['attacker_activity']
        ports_count = len(unique_dst_ports)
        if ports_count >= 100:
            score = 10
        elif ports_count >= 50:
            score = 8
        elif ports_count >= 20:
            score = 5
        else:
            score = 2
        if score >= 9:
            level = "CRITICAL"
        elif score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"
        if len(unique_src_ports) == 1:
            scan_type = "Fixed Source Port Scan"
        else:
            scan_type = "Random Source Port Scan"
        attack_headers = ["Field", "Value"]
        attack_rows = [
            ["Attack Level", f"{level} (Score {score})"],
            ["Attack Time", session['time']],
            ["Scan Type", scan_type],
            ["Attacker IP", ip_src],
            ["Attacker MAC", session['mac']],
            ["Attacker Location", str(locate(ip_src))],
            ["Attacker Device", session['device']],
            ["Scanned Source Ports", ", ".join(str(p) for p in sorted(unique_src_ports))],
            ["Scanned Destination Ports", ", ".join(str(p) for p in sorted(unique_dst_ports))],
            ["Total Attempts", str(len(session['details']))],
            ["Attacker Activity", attcker_acktivity],
        ]
        steps_headers = ["Time", "Packet#", "SrcPort", "DstPort", "DstIP"]
        steps_rows = [
            [time.strftime('%H:%M:%S', time.localtime(t)), str(pkt_num), str(sp), str(dp), idst]
            for sp, dp, idst, t, pkt_num in port_scan_tracker[ip_src]
        ]
        report = ("=" * 80) + "\n"
        report += "PORT SCANNING ATTACK DETECTED!\n"
        report += ("=" * 80) + "\n\n"
        report += _make_table(attack_headers, attack_rows)
        report += "\n\n        Attack Steps:\n"
        report += _make_table(steps_headers, steps_rows)
        mark_as_attacker(ip_src, "Port Scanning")
        report += append_timeline_to_report(ip_src)
        add_alert(report)
        save_report(f"PortScan_{session['time']}.txt", report)
        if mode == '1':
            threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
            block_mac_threaded(session['mac'], ip_src)
    port_scan_sessions.clear()
##############################Simple scanning to the attacker##############################
def scan_and_print_ports(ip):
    if not ip or not is_private_ip(ip):
        return
    open_ports = scan_all_ports(ip)
    with print_lock:
        print(f"\n{'='*30}\nOpen ports on {ip}:\n{'='*30}")
        if open_ports:
            for port in sorted(open_ports):
                print(port)
        else:
            print("No open ports found.")
        print("="*30 + "\n")
##############################ARP Spoofing##############################
def Arp_Spoofing(packet, device_type_guess, device_type_guess2, time_now):
    global num
    global spoof_counter
    attacker_activity = get_attacker_activity(packet)
    src_port="N/A"
    dst_port="N/A"
    proto="ARP"
    ip = packet[ARP].psrc
    mac = packet[scapy.ARP].hwsrc
    old_mac = arp_table.get(ip, "Unknown")
    src_service = socket.getservbyport(src_port) if src_port != "N/A" else "N/A"
    dst_service = socket.getservbyport(dst_port) if dst_port != "N/A" else "N/A"
    if gateway_mac and mac == gateway_mac:
        return
    if packet[scapy.ARP].op == 1:
        if ip not in arp_table:
            arp_table[ip] = mac
    elif packet[scapy.ARP].op == 2:
        if ip in arp_table:
            if arp_table[ip] != mac:
                spoof_counter +=1
                with print_lock:
                    arp_table[ip] = mac
                    if spoof_counter >= 2:
                        last_reported = arp_spoof_reported.get(ip, 0)
                        if time.time() - last_reported < ARP_REPORT_COOLDOWN:
                            return
                        arp_spoof_reported[ip] = time.time()
                        changes = spoof_counter
                        if changes >= 10:
                            score = 10
                        elif changes >= 5:
                            score = 8
                        elif changes >= 2:
                            score = 5
                        else:
                            score = 2
                        if score >= 9:
                            level = "CRITICAL"
                        elif score >= 7:
                            level = "HIGH"
                        elif score >= 4:
                            level = "MEDIUM"
                        else:
                            level = "LOW"
                        attack_headers = ["Field", "Value"]
                        attack_rows = [
                            ["Attack Level", f"{level} (Score {score})"],
                            ["Attack Time", time_now],
                            ["Attacker IP", packet[ARP].psrc],
                            ["Target IP", packet[ARP].pdst],
                            ["Attacker MAC", packet[ARP].hwsrc],
                            ["Target MAC", packet[ARP].hwdst],
                            ["Attacker Port (Service)", f"{src_port}({src_service})"],
                            ["Target Port (Service)", f"{dst_port}({dst_service})"],
                            ["Attacker Location", str(locate(packet[ARP].psrc))],
                            ["Target Location", str(locate(packet[ARP].pdst))],
                            ["Attacker Device", device_type_guess],
                            ["Target Device", device_type_guess2],
                            ["Attacker Activity", attacker_activity],
                            ["Protocol Used", proto],
                            ["MAC Changed", f"{old_mac} -> {mac}"],
                        ]
                        report = ("=" * 80) + "\n"
                        report += "ARP SPOOFING ATTACK DETECTED!\n"
                        report += ("=" * 80) + "\n\n"
                        report += _make_table(attack_headers, attack_rows)
                        mark_as_attacker(packet[ARP].psrc, "ARP Spoofing")
                        report += append_timeline_to_report(packet[ARP].psrc)
                        add_alert(report)
                        filename = f"ARP_Spoofing_{time_now}.txt"
                        save_report(filename, report)
                        if mode == '1':
                            threading.Thread(target=lambda: scan_and_print_ports(packet[ARP].psrc), daemon=True).start()
                            block_mac_threaded(packet[ARP].hwsrc, packet[ARP].psrc)
    else:
        arp_table[ip] = mac
##########################################'ARP Request to getway'##########################################
def build_arp_table():
    global gateway_mac
    try:
        gws = netifaces.gateways()
        default = gws.get('default', {})
        gateway_ip = default.get(netifaces.AF_INET, [None])[0]
        if not gateway_ip:
            return
        arp_req = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=gateway_ip)
        answered, _ = scapy.srp(arp_req, timeout=2, verbose=False)
        for sent, received in answered:
            arp_table[received[scapy.ARP].psrc] = received[scapy.ARP].hwsrc
            gateway_mac = received[scapy.ARP].hwsrc
    except Exception as e:
        print(f"[ARP] Error: {e}")
##########################################'to get getway from pcap'##########################################
def detect_gateway_from_pcap(packets):
    global gateway_mac
    mac_count = {}
    for pkt in packets:
        if pkt.haslayer(IP):
            dst_mac = pkt.dst
            if dst_mac not in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00") and not dst_mac.startswith("01:"):
                mac_count[dst_mac] = mac_count.get(dst_mac, 0) + 1
    if mac_count:
        gateway_mac = max(mac_count, key=mac_count.get) # max
        print(f"[PCAP] Detected gateway MAC: {gateway_mac}")
##############################IP Spoofing Detection##############################
PRIVATE_RANGES = [
    ("10.0.0.0",     "10.255.255.255"),
    ("172.16.0.0",   "172.31.255.255"),
    ("192.168.0.0",  "192.168.255.255"),
    ("127.0.0.0",    "127.255.255.255"), #loopback
    ("169.254.0.0",  "169.254.255.255"), #apipa
]
def ip_to_int(ip):
    if ':' in ip:
        return # ipv6
    return struct.unpack("!I", socket.inet_aton(ip))[0]
def is_private_ip(ip):
    try:
        if ':' in ip:
            return False # ipv6
        ip_int = ip_to_int(ip)
        for start, end in PRIVATE_RANGES:
            if ip_to_int(start) <= ip_int <= ip_to_int(end):
                return True
        return False
    except:
        return False
def is_multicast_ip(ip):
    try:
        first_octet = int(ip.split('.')[0])
        return 224 <= first_octet <= 239
    except:
        return False
def detect_ip_spoofing(packet, device_type_guess, time_now):
    if not packet.haslayer(IP):
        return
    if packet.haslayer(scapy.RadioTap) and packet.haslayer(scapy.Dot11):
        mac_src = packet[scapy.Dot11].addr2 or "N/A"
    else:
        mac_src = packet.src
    attacker_activity= get_attacker_activity(packet)
    if gateway_mac and mac_src == gateway_mac:
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    ttl = packet[IP].ttl
    reason = None
    if ip_src == "0.0.0.0" and ip_dst == "255.255.255.255":
        return
    if ':' in ip_src:
        return # ipv6
    if is_private_ip(ip_src):
        known_mac = arp_table.get(ip_src)
        if known_mac and known_mac != mac_src: # first condition
            reason = f"Private IP ({ip_src}) arriving with unexpected MAC (expected {known_mac}, got {mac_src})"
    if mac_src not in ip_mac_map:
        ip_mac_map[mac_src] = set()
        if ip_src != "0.0.0.0":
            ip_mac_first[mac_src] = ip_src
    if ip_src != "0.0.0.0":
        ip_mac_map[mac_src].add(ip_src)
    if mac_src not in ip_mac_first and ip_src != "0.0.0.0":
        ip_mac_first[mac_src] = ip_src
    if len(ip_mac_map[mac_src]) >= IP_SPOOF_IP_THRESHOLD: # second condition
        all_ips = ip_mac_map[mac_src]
        first_ip = ip_mac_first[mac_src]
        spoofed_ips = all_ips - {first_ip}
        reason = (reason or "") + f" | MAC {mac_src} is sending from {len(all_ips)} different IPs | Real IP: {first_ip} | Spoofed IPs: {spoofed_ips}"
    else:
        first_ip = ip_src    
        spoofed_ips = set()  
    spoofed_count = len(spoofed_ips)
    if spoofed_count >= 10:
        score = 10
    elif spoofed_count >= 5:
        score = 8
    elif spoofed_count >= 2:
        score = 5
    else:
        score = 2 
    if score >= 9:
        level = "CRITICAL"
    elif score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"
    if not is_private_ip(ip_src) and not is_multicast_ip(ip_src) and not is_multicast_ip(ip_dst):
        current_time = time.time()
        score = 9
        level = "CRITICAL"
        last_ext = external_spoof_reported.get(ip_src, 0)
        if current_time - last_ext >= EXTERNAL_SPOOF_COOLDOWN:
            external_spoof_reported[ip_src] = current_time

            attack_headers = ["Field", "Value"]
            attack_rows = [
                ["Attack Level", f"{level} (Score {score})"],
                ["Attack Time", time_now],
                ["Attacker MAC", mac_src],
                ["Spoofed IP", ip_src],
                ["Destination IP", ip_dst],
                ["Attacker Port", str(packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else 'N/A')],
                ["Destination Port", str(packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else 'N/A')],
                ["Attacker Location", str(locate(ip_src))],
                ["Attacker Device", device_type_guess],
                ["Attacker Activity", attacker_activity],
                ["TTL Value", str(ttl)],
                ["Detection Reason", "External IP seen inside local network — possible spoofing"],
            ]

            ext_report = ("=" * 80) + "\n"
            ext_report += "IP SPOOFING ATTACK DETECTED!\n"
            ext_report += ("=" * 80) + "\n\n"
            ext_report += _make_table(attack_headers, attack_rows)

            mark_as_attacker(ip_src, "IP Spoofing (External)")
            ext_report += append_timeline_to_report(ip_src)
            add_alert(ext_report, ip_src)
            save_report(f"IPSpoofing_{time_now}.txt", ext_report)
            if mode == '1':
                threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
                block_mac_threaded(mac_src, ip_src)
        return
    if ip_src == ip_dst: # third condition
        reason = (reason or "") + f" | Land Attack: src IP == dst IP ({ip_src})"
    if ttl < 10 and not is_multicast_ip(ip_dst): # fourth condition
        reason = (reason or "") + f" | Suspiciously low TTL ({ttl})..."
    if not reason:
        return
    current_time = time.time()
    last_reported = ip_spoof_reported.get(mac_src, 0)
    if current_time - last_reported < IP_SPOOF_COOLDOWN:
        return
    ip_spoof_reported[mac_src] = current_time
    attack_headers = ["Field", "Value"]
    attack_rows = [
        ["Attack Level", f"{level} (Score {score})"],
        ["Attack Time", time_now],
        ["Real IP", first_ip],
        ["Spoofed IP(s)", ", ".join(spoofed_ips) if spoofed_ips else "None"],
        ["Attacker MAC", mac_src],
        ["Attacker Port", str(packet.sport if packet.haslayer(TCP) or packet.haslayer(UDP) else 'N/A')],
        ["Destination IP", ip_dst],
        ["Destination MAC", packet.dst],
        ["Destination Port", str(packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else 'N/A')],
        ["Attacker Location", str(locate(first_ip))],
        ["Attacker Device", device_type_guess],
        ["Attacker Activity", attacker_activity],
        ["TTL Value", str(ttl)],
        ["Detection Reason", reason],
    ]
    report = ("=" * 80) + "\n"
    report += "IP SPOOFING ATTACK DETECTED!\n"
    report += ("=" * 80) + "\n\n"
    report += _make_table(attack_headers, attack_rows)
    mark_as_attacker(first_ip, "IP Spoofing")
    report += append_timeline_to_report(first_ip)
    add_alert(report)
    save_report(f"IPSpoofing_{time_now}.txt", report)
    if mode == '1':
        threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
        block_mac_threaded(mac_src, ip_src)
##############################DNS Spoofing##############################
def detect_dns_spoof(packet, device_type_guess, time_now):
    if not packet.haslayer(DNS) or not packet.haslayer(IP):
        return
    dns = packet[DNS]
    if dns.qr != 1:
        return
    try:
        qname = dns.qd.qname
        if isinstance(qname, bytes):
            domain = qname.decode(errors='ignore') if isinstance(qname, bytes) else str(qname)
        else:
            domain = str(qname)
    except:
        domain = None
    if not domain:
        return
    ip_src = packet[IP].src  
    ip_dst = packet[IP].dst  
    mac_src = packet.src
    txid = dns.id
    current_time = time.time()
    answered_ips = set()
    try:
        for i in range(dns.ancount):
            ans = dns.an
            while ans and i > 0:
                ans = ans.payload
                i -= 1
            if ans and hasattr(ans, 'rdata'):
                answered_ips.add(str(ans.rdata))
    except:
        pass
    reason = None
    clean_domain = domain.rstrip('.').lower() + '.'
    if clean_domain in DNS_WHITELIST:
        trusted_ips = DNS_WHITELIST[clean_domain]
        spoofed = answered_ips - trusted_ips
        if spoofed:
            reason = (reason or "") + \
                f" | Domain '{domain}' resolved to untrusted IP(s): {spoofed} (expected: {trusted_ips})"
    spoofed_ips_count = len(answered_ips)
    if spoofed_ips_count >= 5:
        score = 10
    elif spoofed_ips_count >= 3:
        score = 8
    else:
        score = 6
    if score >= 9:
        level = "CRITICAL"
    elif score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"
    if txid in dns_txid_tracker:
        prev = dns_txid_tracker[txid]
        if current_time - prev['time'] <= DNS_TXID_TIMEOUT:
            if prev['ips'] != answered_ips and prev['domain'] == domain:
                score = 9
                level = "CRITICAL"
                reason = (reason or "") + \
                    f" | Same TXID ({txid}) got 2 different responses: {prev['ips']} vs {answered_ips} — possible Race Condition"
    else:
        dns_txid_tracker[txid] = {
            'ips': answered_ips,
            'domain': domain,
            'time': current_time
        }
    expired = [k for k, v in dns_txid_tracker.items()
               if current_time - v['time'] > DNS_TXID_TIMEOUT]
    for k in expired:
        del dns_txid_tracker[k]
    if not reason:
        return
    last_reported = dns_spoof_reported.get(domain, 0)
    if current_time - last_reported < DNS_SPOOF_COOLDOWN:
        return
    dns_spoof_reported[domain] = current_time
    attack_headers = ["Field", "Value"]
    attack_rows = [
        ["Attack Level", f"{level} (Score {score})"],
        ["Attack Time", time_now],
        ["Attacker IP", ip_src],
        ["Attacker MAC", mac_src],
        ["Victim IP", ip_dst],
        ["Domain Queried", domain],
        ["Spoofed IP(s)", ", ".join(answered_ips) if answered_ips else "None"],
        ["Transaction ID", str(txid)],
        ["Attacker Location", str(locate(ip_src))],
        ["Device Type", device_type_guess],
        ["Detection Reason", reason],
    ]

    report = ("=" * 80) + "\n"
    report += "DNS SPOOFING ATTACK DETECTED!\n"
    report += ("=" * 80) + "\n\n"
    report += _make_table(attack_headers, attack_rows)

    mark_as_attacker(ip_src, "DNS Spoofing")
    report += append_timeline_to_report(ip_src)
    add_alert(report)
    save_report(f"DNSSpoofing_{time_now}.txt", report)
    if mode == '1':
        threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
        block_mac_threaded(mac_src, ip_src)
##############################DoS Detection##############################
##############################UDP DoS Detection##############################
def detect_udp_dos(packet, device_type_guess, time_now):
    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return
    try:
        dst_port = packet[UDP].dport  
    except Exception as e:
        return
    if dst_port in DOS_EXCLUDED_PORTS:
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    mac_src = packet.src
    attacker_activity = get_attacker_activity(packet)
    try:
        current_time = float(packet.time)
    except:
        current_time = time.time()
    if gateway_mac and mac_src == gateway_mac:
        return
    if ip_src not in udp_dos_tracker:
        udp_dos_tracker[ip_src] = []
    udp_dos_tracker[ip_src].append(current_time)
    udp_dos_tracker[ip_src] = [
        t for t in udp_dos_tracker[ip_src]
        if current_time - t <= DOS_TIME
    ]
    if len(udp_dos_tracker[ip_src]) >= DOS_PACKET_THRESHOLD:
        last_reported = udp_dos_reported.get(ip_src, 0)
        if current_time - last_reported < DOS_COOLDOWN:
            return
        udp_dos_reported[ip_src] = current_time
        attack_headers = ["Field", "Value"]
        packets = len(udp_dos_tracker[ip_src])
        if packets >= 500:
            score = 10
        elif packets >= 200:
            score = 8
        elif packets >= 100:
            score = 6
        else:
            score = 4
        if score >= 9:
            level = "CRITICAL"
        elif score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"
        attack_rows = [
            ["Attack Level", f"{level} (Score {score})"],
            ["Attack Time", time_now],
            ["Attacker IP", ip_src],
            ["Attacker MAC", mac_src],
            ["Target IP", ip_dst],
            ["Target Port", str(packet[UDP].dport)],
            ["Target Location", str(locate(ip_dst))],
            ["Attacker Location", str(locate(ip_src))],
            ["Device Type", device_type_guess],
            ["Total Packets", f"{len(udp_dos_tracker[ip_src])} in {DOS_TIME}s"],
            ["Attacker Activity", attacker_activity],
            ["Detection Reason", f"Single IP sending {DOS_PACKET_THRESHOLD}+ UDP packets in {DOS_TIME}s"],
        ]

        report = ("=" * 80) + "\n"
        report += "UDP DoS ATTACK DETECTED! (Single Source)\n"
        report += ("=" * 80) + "\n\n"
        report += _make_table(attack_headers, attack_rows)

        mark_as_attacker(ip_src, "UDP DoS")
        report += append_timeline_to_report(ip_src)
        add_alert(report)
        save_report(f"UDPDoS_{time_now}.txt", report)
        if mode == '1':
            threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
            block_mac_threaded(mac_src, ip_src)
##############################ICMP DoS Detection##############################
def detect_icmp_dos(packet, device_type_guess, time_now):
    if not packet.haslayer(ICMP) or not packet.haslayer(IP):
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    mac_src = packet.src
    attacker_activity = get_attacker_activity(packet)
    try:
        current_time = float(packet.time)
    except:
        current_time = time.time()
    if gateway_mac and mac_src == gateway_mac:
        return
    if ip_src not in icmp_dos_tracker:
        icmp_dos_tracker[ip_src] = []
    icmp_dos_tracker[ip_src].append(current_time)
    icmp_dos_tracker[ip_src] = [
        t for t in icmp_dos_tracker[ip_src]
        if current_time - t <= DOS_TIME
    ]
    if len(icmp_dos_tracker[ip_src]) >= DOS_PACKET_THRESHOLD:
        last_reported = icmp_dos_reported.get(ip_src, 0)
        if current_time - last_reported < DOS_COOLDOWN:
            return
        icmp_dos_reported[ip_src] = current_time
        packets = len(icmp_dos_tracker[ip_src])
        if packets >= 500:
            score = 10
        elif packets >= 200:
            score = 8
        elif packets >= 100:
            score = 6
        else:
            score = 4
        if score >= 9:
            level = "CRITICAL"
        elif score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"
        attack_headers = ["Field", "Value"]
        attack_rows = [
            ["Attack Level", f"{level} (Score {score})"],
            ["Attack Time", time_now],
            ["Attacker IP", ip_src],
            ["Attacker MAC", mac_src],
            ["Target IP", ip_dst],
            ["Target Location", str(locate(ip_dst))],
            ["Attacker Location", str(locate(ip_src))],
            ["Device Type", device_type_guess],
            ["Total Packets", f"{len(icmp_dos_tracker[ip_src])} in {DOS_TIME}s"],
            ["Attacker Activity", attacker_activity],
            ["Detection Reason", f"Single IP sending {DOS_PACKET_THRESHOLD}+ ICMP packets in {DOS_TIME}s"],
        ]

        report = ("=" * 80) + "\n"
        report += "ICMP DoS ATTACK DETECTED! (Ping Flood - Single Source)\n"
        report += ("=" * 80) + "\n\n"
        report += _make_table(attack_headers, attack_rows)

        mark_as_attacker(ip_src, "ICMP DoS")
        report += append_timeline_to_report(ip_src)
        add_alert(report)
        save_report(f"ICMPDoS_{time_now}.txt", report)
        if mode == '1':
            threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
            block_mac_threaded(mac_src, ip_src)
##############################SYN DoS Detection##############################
def detect_syn_dos(packet, device_type_guess, time_now):
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return
    if packet[TCP].flags != 0x02:
        return
    dst_port = packet[TCP].dport
    if dst_port in DOS_EXCLUDED_PORTS:
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    dst_port = packet[TCP].dport
    mac_src = packet.src
    attacker_activity = get_attacker_activity(packet)
    try:
        current_time = float(packet.time)
    except:
        current_time = time.time()

    if gateway_mac and mac_src == gateway_mac:
        return
    key = f"{ip_src}:{dst_port}"
    if key not in syn_dos_tracker:
        syn_dos_tracker[key] = []
    syn_dos_tracker[key].append(current_time)
    syn_dos_tracker[key] = [
        t for t in syn_dos_tracker[key]
        if current_time - t <= DOS_TIME
    ]
    if len(syn_dos_tracker[key]) >= DOS_PACKET_THRESHOLD:
        last_reported = syn_dos_reported.get(key, 0)
        if current_time - last_reported < DOS_COOLDOWN:
            return
        syn_dos_reported[key] = current_time
        try:
            service_name = socket.getservbyport(dst_port)
        except:
            service_name = "Unknown"
        attack_headers = ["Field", "Value"]
        packets = len(syn_dos_tracker[key])
        if packets >= 500:
            score = 10
        elif packets >= 200:
            score = 8
        elif packets >= 100:
            score = 6
        else:
            score = 4
        if score >= 9:
            level = "CRITICAL"
        elif score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"
        attack_rows = [
            ["Attack Level", f"{level} (Score {score})"],
            ["Attack Time", time_now],
            ["Attacker IP", ip_src],
            ["Attacker MAC", mac_src],
            ["Target IP", ip_dst],
            ["Target Port", f"{dst_port} ({service_name})"],
            ["Target Location", str(locate(ip_dst))],
            ["Attacker Location", str(locate(ip_src))],
            ["Device Type", device_type_guess],
            ["Total SYN Packets", f"{len(syn_dos_tracker[key])} in {DOS_TIME}s"],
            ["Attacker Activity", attacker_activity],
            ["Detection Reason", f"Single IP sending {DOS_PACKET_THRESHOLD}+ SYN packets to port {dst_port} in {DOS_TIME}s"],
        ]
        report = ("=" * 80) + "\n"
        report += "SYN DoS ATTACK DETECTED! (Single Source)\n"
        report += ("=" * 80) + "\n\n"
        report += _make_table(attack_headers, attack_rows)
        mark_as_attacker(ip_src, "SYN DoS")
        report += append_timeline_to_report(ip_src)
        add_alert(report)
        save_report(f"SYNDoS_{time_now}.txt", report)
        if mode == '1':
            threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
            block_mac_threaded(mac_src, ip_src)
def flush_dos_reports():
    for ip_src, timestamps in udp_dos_tracker.items():
        if len(timestamps) >= DOS_PACKET_THRESHOLD:
            attack_headers = ["Field", "Value"]
            attack_rows = [
                ["Attacker IP", ip_src],
                ["Total Packets", f"{len(timestamps)} in {DOS_TIME}s"],
            ]
            report = ("=" * 80) + "\nUDP DoS ATTACK DETECTED!\n" + ("=" * 80) + "\n\n"
            report += _make_table(attack_headers, attack_rows)
            mark_as_attacker(ip_src, "UDP DoS")
            report += append_timeline_to_report(ip_src)
            add_alert(report)
            save_report(f"UDPDoS_{time_now}.txt", report)
    for ip_src, timestamps in icmp_dos_tracker.items():
        if len(timestamps) >= DOS_PACKET_THRESHOLD:
            attack_headers = ["Field", "Value"]
            attack_rows = [
                ["Attacker IP", ip_src],
                ["Total Packets", f"{len(timestamps)} in {DOS_TIME}s"],
            ]
            report = ("=" * 80) + "\nICMP DoS ATTACK DETECTED!\n" + ("=" * 80) + "\n\n"
            report += _make_table(attack_headers, attack_rows)
            mark_as_attacker(ip_src, "ICMP DoS")
            report += append_timeline_to_report(ip_src)
            add_alert(report)
            save_report(f"ICMPDoS_{time_now}.txt", report)
    for key, timestamps in syn_dos_tracker.items():
        if len(timestamps) >= DOS_PACKET_THRESHOLD:
            ip_src = key.split(":")[0]
            attack_headers = ["Field", "Value"]
            attack_rows = [
                ["Attacker (IP:Port)", key],
                ["Total SYN Packets", f"{len(timestamps)} in {DOS_TIME}s"],
            ]
            report = ("=" * 80) + "\nSYN DoS ATTACK DETECTED!\n" + ("=" * 80) + "\n\n"
            report += _make_table(attack_headers, attack_rows)
            mark_as_attacker(ip_src, "SYN DoS")
            report += append_timeline_to_report(ip_src)
            add_alert(report)
            save_report(f"SYNDoS_{time_now}.txt", report)
    udp_dos_tracker.clear()
    icmp_dos_tracker.clear()
    syn_dos_tracker.clear()
##############################DDoS Detection##############################
##############################UDP DDoS Detection##############################
def detect_udp_ddos(packet, device_type_guess, time_now):
    if not packet.haslayer(UDP) or not packet.haslayer(IP):
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    mac_src = packet.src
    attacker_activity = get_attacker_activity(packet)
    try:
        current_time = float(packet.time)
    except:
        current_time = time.time()
    if gateway_mac and mac_src == gateway_mac:
        return
    if ip_dst not in udp_ddos_tracker:
        udp_ddos_tracker[ip_dst] = {}
    if ip_dst not in udp_ddos_tracker.get('_meta', {}):
        if '_meta' not in udp_ddos_tracker:
            udp_ddos_tracker['_meta'] = {}
        udp_ddos_tracker['_meta'][ip_dst] = {
            'target_mac': packet.dst,
            'target_port': packet.dport if packet.haslayer(UDP) else 'N/A',
    }
    if ip_src not in udp_ddos_tracker[ip_dst]:
        udp_ddos_tracker[ip_dst][ip_src] = []
    udp_ddos_tracker[ip_dst][ip_src].append(current_time)
    udp_ddos_tracker[ip_dst][ip_src] = [
        t for t in udp_ddos_tracker[ip_dst][ip_src]
        if current_time - t <= DDOS_TIME
    ]
    if not udp_ddos_tracker[ip_dst][ip_src]:
        del udp_ddos_tracker[ip_dst][ip_src]
        return
    if mode == '2':
        return
    active_sources = {
        src: len(timestamps)
        for src, timestamps in udp_ddos_tracker[ip_dst].items()
        if len(timestamps) >= DDOS_PACKET_THRESHOLD
    }
    sources = len(active_sources)
    total_packets = sum(active_sources.values())
    if sources >= 20 or total_packets >= 5000:
        score = 10
    elif sources >= 10 or total_packets >= 2000:
        score = 8
    elif sources >= 5 or total_packets >= 1000:
        score = 6
    else:
        score = 4
    if score >= 9:
        level = "CRITICAL"
    elif score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"
    if len(active_sources) >= DDOS_SOURCE_THRESHOLD:
        last_reported = udp_ddos_reported.get(ip_dst, 0)
        if current_time - last_reported < DDOS_COOLDOWN:
            return
        udp_ddos_reported[ip_dst] = current_time
        total_packets = sum(active_sources.values())
        attack_headers = ["Field", "Value"]
        attack_rows = [ 
            ["Attack Level", f"{level} (Score {score})"],
            ["Attack Time", time_now],
            ["Target IP", ip_dst],
            ["Target MAC", packet.dst],
            ["Target Port", str(packet.dport if packet.haslayer(TCP) or packet.haslayer(UDP) else 'N/A')],
            ["Target Location", str(locate(ip_dst))],
            ["Total Sources", f"{len(active_sources)} different IPs"],
            ["Total Packets", f"{total_packets} in {DDOS_TIME}s"],
            ["Detection Reason", f"{len(active_sources)} IPs sending {DDOS_PACKET_THRESHOLD}+ UDP packets each in {DDOS_TIME}s"],
        ]

        sources_headers = ["Source IP", "Packets", "Location"]
        sources_rows = [[src_ip, str(count), str(locate(src_ip))] for src_ip, count in active_sources.items()]

        report = ("=" * 80) + "\n"
        report += "UDP DDoS ATTACK DETECTED!\n"
        report += ("=" * 80) + "\n\n"
        report += _make_table(attack_headers, attack_rows)
        report += "\n\n        Attack Sources:\n"
        report += _make_table(sources_headers, sources_rows)

        for src_ip in active_sources:
            mark_as_attacker(src_ip, "UDP DDoS")
        for src_ip in active_sources:
            report += append_timeline_to_report(src_ip)

        add_alert(report)
        save_report(f"UDPDDoS_{time_now}.txt", report)
        if mode == '1':
            threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
            block_mac_threaded(mac_src, ip_src)
def flush_udp_ddos_reports():
    for ip_dst, sources in udp_ddos_tracker.items():
        if ip_dst == '_meta':
            continue
        info = udp_ddos_tracker.get('_meta', {}).get(ip_dst, {})
        active_sources = {
            src: len(timestamps)
            for src, timestamps in sources.items()
            if len(timestamps) >= DDOS_PACKET_THRESHOLD
        }
        sources = len(active_sources)
        total_packets = sum(active_sources.values())
        if sources >= 20 or total_packets >= 5000:
            score = 10
        elif sources >= 10 or total_packets >= 2000:
            score = 8
        elif sources >= 5 or total_packets >= 1000:
            score = 6
        else:
            score = 4
        if score >= 9:
            level = "CRITICAL"
        elif score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"
        if len(active_sources) >= DDOS_SOURCE_THRESHOLD:
            total_packets = sum(active_sources.values())
            time_now = datetime.datetime.now().strftime("%H:%M:%S")
            attack_headers = ["Field", "Value"]
            attack_rows = [
                ["Attack Level", f"{level} (Score {score})"],
                ["Attack Time", time_now],
                ["Target IP", ip_dst],
                ["Target MAC", info.get('target_mac', 'N/A')],
                ["Target Port", str(info.get('target_port', 'N/A'))],
                ["Target Location", str(locate(ip_dst))],
                ["Total Sources", f"{len(active_sources)} different IPs"],
                ["Total Packets", f"{total_packets} in {DDOS_TIME}s"],
                ["Detection Reason", f"{len(active_sources)} IPs sending {DDOS_PACKET_THRESHOLD}+ UDP packets each in {DDOS_TIME}s"],
            ]
            sources_headers = ["Source IP", "Packets", "Location"]
            sources_rows = [[src_ip, str(count), str(locate(src_ip))] for src_ip, count in active_sources.items()]

            report = ("=" * 80) + "\nUDP DDoS ATTACK DETECTED!\n" + ("=" * 80) + "\n\n"
            report += _make_table(attack_headers, attack_rows)
            report += "\n\n        Attack Sources:\n"
            report += _make_table(sources_headers, sources_rows)

            for src_ip in active_sources:
                mark_as_attacker(src_ip, "UDP DDoS")
            for src_ip in active_sources:
                report += append_timeline_to_report(src_ip)

            add_alert(report)
            save_report(f"UDPDDoS_{time_now}.txt", report)
    udp_ddos_tracker.clear()
##############################ICMP DDoS Detection##############################
def detect_icmp_ddos(packet, device_type_guess, time_now):
    if not packet.haslayer(ICMP) or not packet.haslayer(IP):
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    mac_src = packet.src
    try:
        current_time = float(packet.time)
    except:
        current_time = time.time()
    if gateway_mac and mac_src == gateway_mac:
        return
    if ip_dst not in icmp_ddos_tracker:
        icmp_ddos_tracker[ip_dst] = {}
    if ip_src not in icmp_ddos_tracker[ip_dst]:
        icmp_ddos_tracker[ip_dst][ip_src] = []
    icmp_ddos_tracker[ip_dst][ip_src].append(current_time)
    icmp_ddos_tracker[ip_dst][ip_src] = [
        t for t in icmp_ddos_tracker[ip_dst][ip_src]
        if current_time - t <= ICMP_DDOS_TIME
    ]
    if not icmp_ddos_tracker[ip_dst][ip_src]:
        del icmp_ddos_tracker[ip_dst][ip_src]
        return
    if mode == '2':
        return
    active_sources = {
        src: len(timestamps)
        for src, timestamps in icmp_ddos_tracker[ip_dst].items()
        if len(timestamps) >= ICMP_DDOS_PACKET_THRESHOLD
    }
    if ip_dst not in icmp_meta:
        icmp_meta[ip_dst] = {
            'target_mac': packet.dst
        }
    if len(active_sources) >= ICMP_DDOS_SOURCE_THRESHOLD:
        last_reported = icmp_ddos_reported.get(ip_dst, 0)
        if current_time - last_reported < ICMP_DDOS_COOLDOWN:
            return
        icmp_ddos_reported[ip_dst] = current_time
        sources = len(active_sources)
        total_packets = sum(active_sources.values())
        if sources >= 20 or total_packets >= 5000:
            score = 10
        elif sources >= 10 or total_packets >= 2000:
            score = 8
        elif sources >= 5 or total_packets >= 1000:
            score = 6
        else:
            score = 4
        if score >= 9:
            level = "CRITICAL"
        elif score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"
        attack_headers = ["Field", "Value"]
        attack_rows = [
            ["Attack Level", f"{level} (Score {score})"],
            ["Attack Time", time_now],
            ["Target IP", ip_dst],
            ["Target MAC", packet.dst],
            ["Target Location", str(locate(ip_dst))],
            ["Total Sources", f"{len(active_sources)} different IPs"],
            ["Total Packets", f"{total_packets} in {ICMP_DDOS_TIME}s"],
            ["Detection Reason", f"{len(active_sources)} IPs sending {ICMP_DDOS_PACKET_THRESHOLD}+ ICMP packets each in {ICMP_DDOS_TIME}s"],
        ]
        sources_headers = ["Source IP", "Packets", "Location"]
        sources_rows = [[src_ip, str(count), str(locate(src_ip))] for src_ip, count in active_sources.items()]
        report = ("=" * 80) + "\nICMP DDoS ATTACK DETECTED! (Ping Flood)\n" + ("=" * 80) + "\n\n"
        report += _make_table(attack_headers, attack_rows)
        report += "\n\n        Attack Sources:\n"
        report += _make_table(sources_headers, sources_rows)
        for src_ip in active_sources:
            mark_as_attacker(src_ip, "ICMP DDoS")
        for src_ip in active_sources:
            report += append_timeline_to_report(src_ip)
        add_alert(report)
        save_report(f"ICMPDDoS_{time_now}.txt", report)
        if mode == '1':
            threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
            block_mac_threaded(mac_src, ip_src)
def flush_icmp_ddos_reports():
    for ip_dst, sources in icmp_ddos_tracker.items():
        active_sources = {
            src: len(timestamps)
            for src, timestamps in sources.items()
            if len(timestamps) >= ICMP_DDOS_PACKET_THRESHOLD
        }
        if len(active_sources) >= ICMP_DDOS_SOURCE_THRESHOLD:
            total_packets = sum(active_sources.values())
            time_now = datetime.datetime.now().strftime("%H:%M:%S")
            info = icmp_meta.get(ip_dst, {})
            sources = len(active_sources)
            if sources >= 20 or total_packets >= 5000:
                score = 10
            elif sources >= 10 or total_packets >= 2000:
                score = 8
            elif sources >= 5 or total_packets >= 1000:
                score = 6
            else:
                score = 4
            if score >= 9:
                level = "CRITICAL"
            elif score >= 7:
                level = "HIGH"
            elif score >= 4:
                level = "MEDIUM"
            else:
                level = "LOW"
            attack_headers = ["Field", "Value"]
            attack_rows = [
                ["Attack Level", f"{level} (Score {score})"],
                ["Attack Time", time_now],
                ["Target IP", ip_dst],
                ["Target MAC", info.get('target_mac', 'N/A')],
                ["Target Location", str(locate(ip_dst))],
                ["Total Sources", f"{len(active_sources)} different IPs"],
                ["Total Packets", f"{total_packets} in {ICMP_DDOS_TIME}s"],
                ["Detection Reason", f"{len(active_sources)} IPs sending {ICMP_DDOS_PACKET_THRESHOLD}+ ICMP packets each in {ICMP_DDOS_TIME}s"],
            ]
            sources_headers = ["Source IP", "Packets", "Location"]
            sources_rows = [[src_ip, str(count), str(locate(src_ip))] for src_ip, count in active_sources.items()]

            report = ("=" * 80) + "\nICMP DDoS ATTACK DETECTED! (Ping Flood)\n" + ("=" * 80) + "\n\n"
            report += _make_table(attack_headers, attack_rows)
            report += "\n\n        Attack Sources:\n"
            report += _make_table(sources_headers, sources_rows)

            for src_ip in active_sources:
                mark_as_attacker(src_ip, "ICMP DDoS")
            for src_ip in active_sources:
                report += append_timeline_to_report(src_ip)

            add_alert(report)
            save_report(f"ICMPDDoS_{time_now}.txt", report)
    icmp_ddos_tracker.clear()
##############################SYN Flood DDoS Detection##############################
def detect_syn_flood(packet, device_type_guess, time_now):
    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return
    if packet[TCP].flags != 0x02:
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    dst_port = packet[TCP].dport
    mac_src = packet.src
    try:
        current_time = float(packet.time)
    except:
        current_time = time.time()

    if gateway_mac and mac_src == gateway_mac:
        return
    target_key = f"{ip_dst}:{dst_port}"
    if target_key not in syn_flood_tracker:
        syn_flood_tracker[target_key] = {}
    if ip_src not in syn_flood_tracker[target_key]:
        syn_flood_tracker[target_key][ip_src] = []
    syn_flood_tracker[target_key][ip_src].append(current_time)
    syn_flood_tracker[target_key][ip_src] = [
        t for t in syn_flood_tracker[target_key][ip_src]
        if current_time - t <= SYN_FLOOD_TIME
    ]
    if not syn_flood_tracker[target_key][ip_src]:
        del syn_flood_tracker[target_key][ip_src]
        return
    if ip_dst not in syn_meta:
        syn_meta[ip_dst] = {
            'target_mac': packet.dst
        }
    if mode == '2':
        return
    active_sources = {
        src: len(timestamps)
        for src, timestamps in syn_flood_tracker[target_key].items()
        if len(timestamps) >= SYN_FLOOD_PACKET_THRESHOLD
    }
    if len(active_sources) >= SYN_FLOOD_SOURCE_THRESHOLD:
        last_reported = syn_flood_reported.get(target_key, 0)
        if current_time - last_reported < SYN_FLOOD_COOLDOWN:
            return
        syn_flood_reported[target_key] = current_time
        total_packets = sum(active_sources.values())
        try:
            service_name = socket.getservbyport(dst_port)
        except:
            service_name = "Unknown"
        sources = len(active_sources)
        if sources >= 20 or total_packets >= 5000:
            score = 10
        elif sources >= 10 or total_packets >= 2000:
            score = 8
        elif sources >= 5 or total_packets >= 1000:
            score = 6
        else:
            score = 4
        if score >= 9:
            level = "CRITICAL"
        elif score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"
        attack_headers = ["Field", "Value"]
        attack_rows = [
            ["Attack Level", f"{level} (Score {score})"],
            ["Attack Time", time_now],
            ["Target IP", ip_dst],
            ["Target MAC", packet.dst],
            ["Target Port", f"{dst_port} ({service_name})"],
            ["Target Location", str(locate(ip_dst))],
            ["Total Sources", f"{len(active_sources)} different IPs"],
            ["Total SYN Packets", f"{total_packets} in {SYN_FLOOD_TIME}s"],
            ["Detection Reason", f"{len(active_sources)} IPs sending {SYN_FLOOD_PACKET_THRESHOLD}+ SYN packets to port {dst_port} in {SYN_FLOOD_TIME}s"],
        ]
        sources_headers = ["Source IP", "SYN Packets", "Location"]
        sources_rows = [[src_ip, str(count), str(locate(src_ip))] for src_ip, count in active_sources.items()]
        report = ("=" * 80) + "\nSYN FLOOD DDoS ATTACK DETECTED!\n" + ("=" * 80) + "\n\n"
        report += _make_table(attack_headers, attack_rows)
        report += "\n\n        Attack Sources:\n"
        report += _make_table(sources_headers, sources_rows)

        for src_ip in active_sources:
            mark_as_attacker(src_ip, "SYN Flood DDoS")
        for src_ip in active_sources:
            report += append_timeline_to_report(src_ip)

        add_alert(report)
        save_report(f"SYNFlood_{time_now}.txt", report)
        if mode == '1':
            threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
            block_mac_threaded(mac_src, ip_src)
def flush_syn_ddos_reports():
    for target_key, sources in syn_flood_tracker.items():
        ip_dst, dst_port_str = target_key.rsplit(":", 1)
        dst_port = int(dst_port_str)
        try:
            service_name = socket.getservbyport(dst_port)
        except:
            service_name = "Unknown"
        info = syn_meta.get(ip_dst, {})
        active_sources = {
            src: len(timestamps)
            for src, timestamps in sources.items()
            if len(timestamps) >= SYN_FLOOD_PACKET_THRESHOLD
        }
        if len(active_sources) >= SYN_FLOOD_SOURCE_THRESHOLD:
            total_packets = sum(active_sources.values())
            time_now = datetime.datetime.now().strftime("%H:%M:%S")
            sources = len(active_sources)
            if sources >= 20 or total_packets >= 5000:
                score = 10
            elif sources >= 10 or total_packets >= 2000:
                score = 8
            elif sources >= 5 or total_packets >= 1000:
                score = 6
            else:
                score = 4
            if score >= 9:
                level = "CRITICAL"
            elif score >= 7:
                level = "HIGH"
            elif score >= 4:
                level = "MEDIUM"
            else:
                level = "LOW"
            attack_headers = ["Field", "Value"]
            attack_rows = [
                ["Attack Level", f"{level} (Score {score})"],
                ["Attack Time", time_now],
                ["Target IP", ip_dst],
                ["Target MAC", info.get('target_mac', 'N/A')],
                ["Target Port", f"{dst_port} ({service_name})"],
                ["Target Location", str(locate(ip_dst))],
                ["Total Sources", f"{len(active_sources)} different IPs"],
                ["Total Packets", f"{total_packets} in {SYN_FLOOD_TIME}s"],
                ["Detection Reason", f"{len(active_sources)} IPs sending {SYN_FLOOD_PACKET_THRESHOLD}+ SYN packets to port {dst_port} in {SYN_FLOOD_TIME}s"],
            ]
            sources_headers = ["Source IP", "Packets", "Location"]
            sources_rows = [[src_ip, str(count), str(locate(src_ip))] for src_ip, count in active_sources.items()]

            report = ("=" * 80) + "\nSYN FLOOD DDoS ATTACK DETECTED!\n" + ("=" * 80) + "\n\n"
            report += _make_table(attack_headers, attack_rows)
            report += "\n\n        Attack Sources:\n"
            report += _make_table(sources_headers, sources_rows)

            for src_ip in active_sources:
                mark_as_attacker(src_ip, "SYN Flood DDoS")
            for src_ip in active_sources:
                report += append_timeline_to_report(src_ip)

            add_alert(report)
            save_report(f"SYNFlood_{time_now}.txt", report)
    syn_flood_tracker.clear()
##############################Botnet / C&C Detection###############################
CC_PORTS = {6667, 6668, 6669,  # IRC
            1080, 4444, 5554,  # RATs
            9001, 9030}        # Tor
KNOWN_DNS_SERVERS = {
    "62.240.110.198",   # TE Data / Vodafone Egypt
    "62.240.110.197",
    "8.8.8.8",          # Google DNS
    "8.8.4.4",          # Google DNS
    "1.1.1.1",          # Cloudflare
    "1.0.0.1",          # Cloudflare
    "208.67.222.222",   # OpenDNS
}
NORMAL_PORTS = {80, 443, 8080, 8443, 5222, 5223, 5228, 5229, 5230}
KNOWN_CLOUD_RANGES = {
    "74.125.",    # Google
    "142.250.",   # Google
    "172.217.",   # Google
    "17.",        # Apple
    "54.",        # Amazon AWS
    "52.",        # Amazon AWS
    "13.",        # Amazon AWS
    "40.",        # Microsoft Azure
    "20.",        # Microsoft Azure
}
KNOWN_CLOUD_PREFIXES = {
    # Google
    "66.102.", "64.233.", "66.249.", "72.14.", "74.125.",
    "142.250.", "172.217.", "173.194.", "209.85.", "216.58.", "216.239.",
    # Apple
    "17.",
    # Amazon AWS
    "54.", "52.", "13.", "18.", "34.", "35.",
    # Microsoft
    "40.", "20.", "13.",
    # Cloudflare
    "104.16.", "104.17.", "104.18.", "104.19.", "104.20.", "104.21.",
    # Akamai
    "23.32.", "23.64.", "23.72.",
}
def is_known_cloud(ip):
    for prefix in KNOWN_CLOUD_RANGES:
        if ip.startswith(prefix):
            return True
    return False
def is_known_dns(ip):
    KNOWN_DNS_SERVERS = {
        "8.8.8.8", "8.8.4.4",
        "1.1.1.1", "1.0.0.1",
        "208.67.222.222",
    }
    if ip.startswith("62.240.110."):
        return True
    return ip in KNOWN_DNS_SERVERS
def detect_botnet(packet, device_type_guess, time_now):
    if not packet.haslayer(IP):
        return
    ip_src = packet[IP].src
    ip_dst = packet[IP].dst
    mac_src = packet.src
    current_time = time.time()
    reason = None
    if is_known_dns(ip_dst):
        return
    if ip_dst in KNOWN_DNS_SERVERS:
        return
    if gateway_mac and mac_src == gateway_mac:
        return
    if gateway_mac and ip_dst in arp_table and arp_table.get(ip_dst) == gateway_mac:
        return
    if is_known_cloud(ip_dst):
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            try:
                dst_port = packet.dport
                if dst_port in CC_PORTS:
                    score = 7
                    reason = f"Connection to known C&C port {dst_port}"
            except:
                pass
        if not reason:
            return
    if packet.haslayer(TCP):
        tcp_flags = packet[TCP].flags
        dst_port = packet[TCP].dport
        if tcp_flags != 0x02 and dst_port not in NORMAL_PORTS and is_private_ip(ip_dst):
            target_key = f"{ip_src}->{ip_dst}"
            if target_key not in botnet_tracker:
                botnet_tracker[target_key] = []
            botnet_tracker[target_key].append(current_time)
            botnet_tracker[target_key] = [
                t for t in botnet_tracker[target_key]
                if current_time - t <= BOTNET_HEARTBEAT_TIME
            ]
            if len(botnet_tracker[target_key]) >= BOTNET_HEARTBEAT_THRESHOLD:
                if len(botnet_tracker[target_key]) >= 20:
                    score = 10
                else:
                    score = 8
                reason = (reason or "") + f" | Heartbeat detected: {len(botnet_tracker[target_key])} connections to {ip_dst} in {BOTNET_HEARTBEAT_TIME}s"
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            try:
                qname = packet[DNS].qd.qname
                domain = qname.decode() if isinstance(qname, bytes) else str(qname)
            except:
                pass
            if ip_src not in botnet_dns_tracker:
                botnet_dns_tracker[ip_src] = {"domains": set(), "timestamps": []}
            botnet_dns_tracker[ip_src]["domains"].add(domain)
            botnet_dns_tracker[ip_src]["timestamps"].append(current_time)
            botnet_dns_tracker[ip_src]["timestamps"] = [
                t for t in botnet_dns_tracker[ip_src]["timestamps"]
                if current_time - t <= BOTNET_DNS_TIME
            ]
            if len(botnet_dns_tracker[ip_src]["domains"]) >= BOTNET_DNS_THRESHOLD:
                domains = len(botnet_dns_tracker[ip_src]["domains"])
                if domains >= 50:
                    score = 10
                elif domains >= 20:
                    score = 8
                else:
                    score = 6
                reason = (reason or "") + f" | DGA suspected: {len(botnet_dns_tracker[ip_src]['domains'])} different DNS queries in {BOTNET_DNS_TIME}s"
        except:
            pass
    if not reason:
        return
    if mode == '2':
        return
    current_time = time.time()
    last_reported = botnet_reported.get(ip_src, 0)
    if current_time - last_reported < BOTNET_COOLDOWN:
        return
    botnet_reported[ip_src] = current_time
    if score >= 9:
        level = "CRITICAL"
    elif score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"
    attack_headers = ["Field", "Value"]
    attack_rows = [
        ["Attack Level", f"{level} (Score {score})"],
        ["Attack Time", time_now],
        ["Infected Host IP", ip_src],
        ["Infected Host MAC", mac_src],
        ["C&C Server IP", ip_dst],
        ["Host Location", str(locate(ip_src))],
        ["C&C Location", str(locate(ip_dst))],
        ["Device Type", device_type_guess],
        ["Detection Reason", reason],
    ]

    report = ("=" * 80) + "\n"
    report += "BOTNET / C&C ACTIVITY DETECTED!\n"
    report += ("=" * 80) + "\n\n"
    report += _make_table(attack_headers, attack_rows)

    mark_as_attacker(ip_src, "Botnet/C&C")
    report += append_timeline_to_report(ip_src)
    add_alert(report)
    save_report(f"Botnet_{time_now}.txt", report)
    if mode == '1':
        threading.Thread(target=lambda: scan_and_print_ports(ip_src), daemon=True).start()
        block_mac_threaded(mac_src, ip_src)
def flush_botnet_reports():
    for target_key, timestamps in botnet_tracker.items():
        if len(timestamps) >= BOTNET_HEARTBEAT_THRESHOLD:
            time_now = datetime.datetime.now().strftime("%H:%M:%S")
            ip_src, ip_dst = target_key.split("->")
            heartbeat_count = len(timestamps)
            score = 0
            if heartbeat_count >= 50:
                score = 10
            elif heartbeat_count >= 20:
                score = 8
            else:
                score = 6
            if score >= 9:
                level = "CRITICAL"
            elif score >= 7:
                level = "HIGH"
            elif score >= 4:
                level = "MEDIUM"
            else:
                level = "LOW"
            attack_headers = ["Field", "Value"]
            attack_rows = [
                ["Attack Level", f"{level} (Score {score})"],
                ["Attack Time", time_now],
                ["Infected Host IP", ip_src],
                ["C&C Server IP", ip_dst],
                ["Host Location", str(locate(ip_src))],
                ["C&C Location", str(locate(ip_dst))],
                ["Detection Reason", f"Heartbeat: {len(timestamps)} connections in {BOTNET_HEARTBEAT_TIME}s"],
            ]

            report = ("=" * 80) + "\nBOTNET / C&C ACTIVITY DETECTED!\n" + ("=" * 80) + "\n\n"
            report += _make_table(attack_headers, attack_rows)

            mark_as_attacker(ip_src, "Botnet/C&C")
            report += append_timeline_to_report(ip_src)
            add_alert(report)
            save_report(f"Botnet_{time_now}.txt", report)
    botnet_tracker.clear()
##############################Rogue AP Detection##############################
def detect_rogue_ap(packet, time_now):
    if not packet.haslayer(Dot11Beacon):
        return
    if not packet.haslayer(Dot11Elt):
        return
    bssid = packet[Dot11].addr3 or packet[Dot11].addr2
    if not bssid:
        return
    if bssid in KNOWN_APS:
        return
    if MY_BSSID and bssid.lower() == MY_BSSID:
        return
    try:
        ssid = packet[Dot11Elt].info.decode(errors='ignore').strip()
    except:
        ssid = "Unknown"

    signal = "N/A"
    try:
        signal = packet[scapy.RadioTap].dBm_AntSignal
    except:
        pass
    current_time = time.time()
    if bssid not in rogue_ap_tracker:
        rogue_ap_tracker[bssid] = {
            'ssid': ssid,
            'signal': signal,
            'first_seen': time_now,
            'count': 0
        }
    beacons = rogue_ap_tracker[bssid]['count']
    if beacons >= 100:
        score = 9
    elif beacons >= 50:
        score = 7
    else:
        score = 5
    if score >= 9:
        level = "CRITICAL"
    elif score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"
    rogue_ap_tracker[bssid]['count'] += 1
    if rogue_ap_tracker[bssid]['count'] < 3:
        return
    last_reported = rogue_ap_reported.get(bssid, 0)
    if current_time - last_reported < ROGUE_AP_COOLDOWN:
        return
    rogue_ap_reported[bssid] = current_time
    report = f'''
{("=" * 80)}
                "ROGUE ACCESS POINT DETECTED!"
{("=" * 80)}
        Attack Level:   {level} (Score {score})
        Attack Time:    {time_now}
        Rogue AP BSSID: {bssid}
        Vendor:         {get_mac_vendor(bssid)}
        SSID:           {ssid}
        Signal:         {signal} dBm
        First Seen:     {rogue_ap_tracker[bssid]['first_seen']}
        Beacon Count:   {rogue_ap_tracker[bssid]['count']}
        Detection Reason: Unknown AP not in whitelist broadcasting in range
{("=" * 80)}
'''
    add_alert(report)
    save_report(f"RogueAP_{time_now}.txt", report)
    if mode == '1':
        # Rogue AP detection from Dot11 beacon — no IP available
        pass
##############################deauthentication##############################
def detect_deauthentication(packet, time_now):
    if not packet.haslayer(Dot11Deauth):
        return

    try:
        src = packet.addr2   # attacker
        dst = packet.addr1   # victim
        bssid = packet.addr3
        current_time = time.time()
        if src not in deauth_tracker:
            deauth_tracker[src] = []
        deauth_tracker[src].append((dst, bssid, current_time, num))
        deauth_tracker[src] = [
            (d, b, t, n)
            for (d, b, t, n) in deauth_tracker[src]
            if current_time - t <= DEAUTH_TIME_WINDOW
        ]
        count = len(deauth_tracker[src])
        if count >= DEAUTH_THRESHOLD:
            last = deauth_reported.get(src, 0)
            if current_time - last < DEAUTH_COOLDOWN:
                if src in deauth_sessions:
                    deauth_sessions[src]['count'] = count
                    deauth_sessions[src]['details'] = deauth_tracker[src].copy()
                return
            deauth_reported[src] = current_time
            deauth_sessions[src] = {
                "count": count,
                "details": deauth_tracker[src].copy(),
                "time": time_now,
                "bssid": bssid
            }
            deauth_tracker[src] = []
    except:
        pass
def flush_deauth_reports():
    for src, session in deauth_sessions.items():
        details_lines = []
        count = session['count']
        if count >= 100:
            score = 10
        elif count >= 50:
            score = 8
        elif count >= 20:
            score = 6
        else:
            score = 4
        if score >= 9:
            level = "CRITICAL"
        elif score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            level = "LOW"
        for dst, bssid, t, pkt_num in session['details']:
            details_lines.append(
                f"Time: {time.strftime('%H:%M:%S', time.localtime(t))} | Packet: {pkt_num} | Victim: {dst} | AP: {bssid}"
            )
        report = f'''
{"="*80}
                "DEAUTHENTICATION ATTACK DETECTED!"
{"="*80}
Attack Level:   {level} (Score {score})
Attack Time: {session['time']}
Attacker MAC: {src}
Target AP (BSSID): {session['bssid']}
 Packets Count: {session['count']}

Attack Details:
''' + "\n".join(details_lines)
        add_alert(report)
        save_report(f"Deauth_{session['time']}.txt", report)
        if mode == '1':
            # Deauth is L2 management frame — no IP available
            pass
    deauth_sessions.clear()
##############################Evil Twin Detection##############################
def detect_evil_twin(packet, time_now):
    if not packet.haslayer(Dot11Beacon) and not packet.haslayer(Dot11ProbeReq):
        return
    if not packet.haslayer(Dot11Elt):
        return
    try:
        ssid = packet[Dot11Elt].info.decode(errors='ignore').strip()
    except:
        return
    if not ssid or ssid == "":
        return
    bssid = packet[Dot11].addr3 or packet[Dot11].addr2
    if not bssid:
        return
    current_time = time.time()
    if ssid not in ap_tracker:
        ap_tracker[ssid] = {}
    signal = "N/A"
    try:
        signal = packet[scapy.RadioTap].dBm_AntSignal
    except:
        pass
    if bssid not in ap_tracker[ssid]:
        ap_tracker[ssid][bssid] = {
            'first_seen': time_now,
            'signal': signal
        }
    if len(ap_tracker[ssid]) >= 2:
        last_reported = evil_twin_reported.get(ssid, 0)
        if current_time - last_reported < EVIL_TWIN_COOLDOWN:
            return
        evil_twin_reported[ssid] = current_time
        if len(ap_tracker[ssid]) == 2:
            score = 7
        elif len(ap_tracker[ssid]) > 2:
            score = 9
        elif signal > -40:
            score = 10
        if score >= 9:
            level = "CRITICAL"
        elif score >= 7:
            level = "HIGH"
        elif score >= 4:
            level = "MEDIUM"
        else:
            evel = "LOW"
        report = f'''
{("=" * 80)}
                "EVIL TWIN ATTACK DETECTED!"
{("=" * 80)}
        Attack Level:   {level} (Score {score})
        Attack Time:    {time_now}
        SSID:           {ssid}
        Suspicious APs: {len(ap_tracker[ssid])} APs with same name
        Access Points:
'''
        for b, info in ap_tracker[ssid].items():
            report += f"                    BSSID: {b}  ({get_mac_vendor(b)})  Signal: {info['signal']} dBm  First Seen: {info['first_seen']}\n"
        report += f'''
        Detection Reason: Multiple APs broadcasting same SSID — possible Evil Twin
{("=" * 80)}
'''
        add_alert(report)
        save_report(f"EvilTwin_{time_now}.txt", report)
##########################################'END'##########################################
def process_packet_live(packet):
    global num
    num += 1
    process_packet(packet)
def process_packet_pcap(packets):
    global num
    for idx, packet in enumerate(packets, start=1):
        num = idx
        process_packet(packet)
def analyze_pcap(file):
    packets = scapy.rdpcap(file)
    detect_gateway_from_pcap(packets)
    process_packet_pcap(packets)
def box(title, body_lines, width=70):
    out = []
    out.append(f"┌{'─'*width}┐")
    if title:
        out.append(f"│  {title}{' '*(width-4-len(title))}│")
        out.append(f"├{'─'*width}┤")
    for b in body_lines:
        out.append(f"│  {b}{' '*(width-4-len(b))}│")
    out.append(f"└{'─'*width}┘")
    return out
def generate_customer_report():
    from ip_tracking import ip_timeline, mac_timeline
    H = "═" * 70
    h = "─" * 70
    now_d = datetime.datetime.now().strftime("%d/%m/%Y")
    attackers = {ip: e for ip, e in ip_timeline.items() if e["is_attacker"]}
    normals   = {ip: e for ip, e in ip_timeline.items() if not e["is_attacker"]}
    ext_ips   = set()
    for ip, e in ip_timeline.items():
        for c in e["connections"]:
            dip = c.get("dst_ip", "")
            if dip and not dip.startswith(("192.168.", "10.", "172.16.", "127.")):
                ext_ips.add(dip)
    durations = []
    for e in ip_timeline.values():
        if e["first_seen"] not in ("N/A", "") and e["last_seen"] not in ("N/A", ""):
            try:
                f = e["first_seen"]
                l = e["last_seen"]
                durations.append(f"{f} - {l}")
            except:
                pass
    total_events = len(attackers)
    attack_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    atk_scores = {"Port Scanning": 9, "IP Spoofing": 8, "DNS Spoofing": 7,
                  "UDP DoS": 6, "ICMP DoS": 6, "SYN DoS": 6,
                  "UDP DDoS": 9, "ICMP DDoS": 9, "SYN Flood": 9,
                  "ARP Spoofing": 7, "Botnet": 10,
                  "Rogue AP": 8, "Deauthentication": 5, "Evil Twin": 9}
    sev = lambda s: "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else "LOW"
    for ip, e in attackers.items():
        for at in e["attack_types"]:
            sc = atk_scores.get(at, 5)
            attack_counts[sev(sc)] += 1
    recs = {
        "Port Scanning": "1. Isolate device\n2. Run antivirus scan\n3. Monitor for data exfiltration",
        "IP Spoofing": "1. Check ARP tables\n2. Investigate device\n3. Update firewall rules",
        "DNS Spoofing": "1. Change DNS to trusted server\n2. Clear DNS cache\n3. Scan for malware",
        "DoS": "1. Apply rate limiting\n2. Block source IP\n3. Check for compromised devices",
        "DDoS": "1. Enable DDoS protection\n2. Contact ISP\n3. Analyze traffic patterns",
        "Botnet": "1. Disconnect infected device\n2. Full system scan\n3. Change all passwords",
        "ARP Spoofing": "1. Enable Dynamic ARP Inspection\n2. Use static ARP entries\n3. Segment network",
        "Rogue AP": "1. Locate and remove rogue AP\n2. Review wireless policies\n3. Enable 802.1X",
        "Deauthentication": "1. Enable 802.11w\n2. Monitor for deauth floods\n3. Check channel usage",
        "Evil Twin": "1. Educate users\n2. Use WPA2-Enterprise\n3. Verify AP certificates",
    }
    def get_recommendation(at):
        for k, v in recs.items():
            if k.lower().startswith(at.split()[0].lower()):
                return v
        return "1. Investigate the device\n2. Review logs\n3. Update security policies"
    lines = []
    W = 70
    lines.append(f"{'═'*W}")
    lines.append(f"CUSTOMER SECURITY REPORT".center(W))
    lines.append(f"{'='*W}")
    lines.append(f"Date: {now_d}".center(W))
    lines.append(f"{'═'*W}")
    lines.append("")
    # Executive Summary
    summ = []
    summ.append(f"Total Security Events:  {total_events}")
    summ.append("")
    for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        c = attack_counts[s]
        if c:
            summ.append(f"{s:<10} {c}")
    summ.append("")
    summ.append(f"Devices on Network:     {len(ip_timeline)}")
    summ.append(f"Suspicious Devices:     {len(attackers)}")
    summ.append(f"External IPs:           {len(ext_ips)}")
    lines.extend(box("EXECUTIVE SUMMARY", summ, W))
    lines.append("")
    # Incident Details
    idx = 1
    for ip, e in attackers.items():
        all_types = e["attack_types"]
        top_at = all_types[0] if all_types else "Unknown"
        sc = atk_scores.get(top_at, 5)
        lev = sev(sc)
        dev = e["device_type"] or "Unknown"
        t1 = e.get("first_seen", "—")
        t2 = e.get("last_seen", "—")
        body = []
        body.append(f"Device:   {ip}  [{dev}]")
        body.append(f"Severity: {lev} (Score: {sc}/10)")
        body.append(f"Time:     {t1} — {t2}")
        body.append("")
        body.append(f"What happened:")
        body.append(f"  Device {ip} conducted {top_at.lower()}.")
        body.append("")
        body.append(f"Recommended Action:")
        for rline in get_recommendation(top_at).split("\n"):
            body.append(f"  {rline}")
        lines.extend(box(f"{idx}. {top_at.upper()}", body, W))
        lines.append("")
        idx += 1
    # Network Summary Table
    col_ip = 18; col_dev = 18; col_st = 10; col_at = 16
    sep = f"  {'─'*col_ip}┬{'─'*col_dev}┬{'─'*col_st}┬{'─'*col_at}"
    hdr = f"  {'IP'.ljust(col_ip)}│{'Device'.ljust(col_dev)}│{'Status'.ljust(col_st)}│{'Attacks'.ljust(col_at)}"
    rows = []
    for ip, e in ip_timeline.items():
        ats = ", ".join(e["attack_types"]) if e["is_attacker"] else "-"
        st = "ATTACKER" if e["is_attacker"] else "Normal"
        dev = e.get("device_type", "Unknown")[:col_dev]
        rows.append(f"  {ip:<{col_ip}}│{dev:<{col_dev}}│{st:<{col_st}}│{ats:<{col_at}}")
    tbl = []
    tbl.append(hdr)
    tbl.append(sep)
    tbl.extend(rows)
    lines.extend(box("NETWORK SUMMARY TABLE", tbl, W))
    lines.append("")
    lines.append("─" * W)
    return "\n".join(lines)
def generate_technical_report_boxed(alerts=None):
    from ip_tracking import ip_timeline
    W = 90
    now_d = datetime.datetime.now().strftime("%d/%m/%Y")
    lines = []
    lines.append(f"{'═'*W}")
    lines.append("TECHNICAL FORENSIC REPORT".center(W))
    lines.append(f"{'='*W}")
    lines.append(f"Date: {now_d}".center(W))
    lines.append(f"{'═'*W}")
    lines.append("")
    if alerts is None:
        alerts = []
    if alerts:
        for alert in alerts:
            for line in alert.strip().split("\n"):
                lines.append(line)
            lines.append("")
    else:
        lines.append("No attacks detected.".center(W))
        lines.append("")
    col_ip = 18; col_mac = 20; col_dev = 18; col_st = 10; col_at = 16
    sep_t = f"  {'─'*col_ip}┬{'─'*col_mac}┬{'─'*col_dev}┬{'─'*col_st}┬{'─'*col_at}"
    hdr_t = f"  {'IP'.ljust(col_ip)}│{'MAC'.ljust(col_mac)}│{'Device'.ljust(col_dev)}│{'Status'.ljust(col_st)}│{'Attacks'.ljust(col_at)}"
    rows = []
    for ip, e in ip_timeline.items():
        ats = ", ".join(e["attack_types"]) if e["is_attacker"] else "-"
        st = "ATTACKER" if e["is_attacker"] else "Normal"
        dev = e.get("device_type", "Unknown")[:col_dev]
        mac = e.get("current_mac", "N/A")[:col_mac]
        rows.append(f"  {ip:<{col_ip}}│{mac:<{col_mac}}│{dev:<{col_dev}}│{st:<{col_st}}│{ats:<{col_at}}")
    tbl = []
    tbl.append(hdr_t)
    tbl.append(sep_t)
    tbl.extend(rows)
    lines.extend(box("NETWORK SUMMARY TABLE", tbl, W))
    lines.append("")
    lines.append("─" * W)
    return "\n".join(lines)
def real_ip_status(ip, mac="N/A"):
    if not ip or ip == "N/A":
        return ""
    try:
        res = real_ip.analyze_identity(ip, mac)
        lines = [f"  {k}: {v}" for k, v in res.items()]
        return "\n" + "\n".join(lines)
    except:
        return ""
def add_alert(report, ip_src=None):
    if not ip_src:
        import re
        m = re.search(r"(?:Attacker IP|Infected Host IP|Spoofed IP|Real IP)\s*[|:]\s*([0-9.]+)", report)
        if m:
            ip_src = m.group(1)
    mac = "N/A"
    mm = re.search(r"(?:Source MAC|MAC Address)\s*[|:]\s*([0-9a-fA-F:]{17})", report)
    if mm:
        mac = mm.group(1)
    if ip_src and not ip_src.startswith(("192.168.", "10.", "172.16.", "127.")):
        status = real_ip_status(ip_src, mac)
        if status:
            report += f"\n{'='*30}\nAttacker Identity:{status}\n{'='*30}"
    alerts_output.append(report)
###############################################################################
mode = input("1) Live\n2) PCAP\nChoose: ")
if mode == "1":
    #wpa2_decrypt.WPA2_PSK = input("Enter WiFi password (PSK): ").strip()
    #wpa2_decrypt.WPA2_SSID = input("Enter WiFi SSID: ").strip()
    ENABLE_ACTIVE_SCAN = True
    MONITOR_IFACE = input("Enter monitor interface (e.g., wlan0mon): ").strip() or None
    ch = input("Enter channel to lock (or empty to skip): ").strip()
    if ch and MONITOR_IFACE:
        MONITOR_CHANNEL = ch
        os.system(f"iw dev {MONITOR_IFACE} set channel {MONITOR_CHANNEL}")
        print(f"[+] Interface {MONITOR_IFACE} locked to channel {MONITOR_CHANNEL}")
    MY_BSSID = input("Enter your router BSSID to filter (or empty for all): ").strip().lower()
    threading.Thread(target=stdin_listener, daemon=True).start()
    print("\n" + "="*80)
    print("  NETWORK FORENSICS & INTRUSION DETECTION SYSTEM  ".center(80))
    print("="*80+"\n")
    build_arp_table()
    threading.Thread(target=run_scan, daemon=True).start()
    threading.Thread(target=output_thread, daemon=True).start()
    sniff_kwargs = dict(prn=process_packet_live, store=0, promisc=True)
    if MONITOR_IFACE:
        sniff_kwargs['iface'] = MONITOR_IFACE
        if platform.system() != "Darwin":
            sniff_kwargs['monitor'] = True
    threading.Thread(
        target=lambda: scapy.sniff(**sniff_kwargs),
        daemon=True
    ).start()
    def generate_report_on_exit():
        print("\n[!] Generating customer report...")
        r = generate_customer_report()
        print(r)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        save_report(f"Customer_Report_{ts}.txt", r)
        print("\n[!] Generating technical report...")
        tr = generate_technical_report_boxed()
        print(tr)
        save_report(f"Technical_Report_{ts}.txt", tr)
    atexit.register(generate_report_on_exit)
    while True:
        time.sleep(1)
###############################################################################
elif mode == "2":
    file = input("Enter PCAP file path: ")
    if file.endswith((".pcap", ".pcapng", ".cap", ".dump", ".pcap.gz")):
        print("\n" + "="*80)
        print("  NETWORK FORENSICS & INTRUSION DETECTION SYSTEM  ".center(80))
        print("="*80+"\n")
        analyze_pcap(file)
        flush_port_scan_reports()
        flush_dos_reports()
        flush_udp_ddos_reports()
        flush_icmp_ddos_reports()
        flush_syn_ddos_reports()
        flush_botnet_reports()
        flush_deauth_reports()
        tech_alerts = list(alerts_output)
        render_output()
        final_report = generate_technical_report_boxed(tech_alerts)
        print(final_report)
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        save_report(f"Technical_Report_{ts}.txt", final_report)
        customer_report = generate_customer_report()
        print(customer_report)
        save_report(f"Customer_Report_{ts}.txt", customer_report)
    else: print("Invalid file type")