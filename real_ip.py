import urllib.request
import os
import time
import socket
from netaddr import EUI
TOR_LIST_URLS = [
    "https://check.torproject.org/torbulkexitlist",

    "https://www.dan.me.uk/torlist/",

    "https://torstatus.blutmagie.de/ip_list_all.php",

]
TOR_CACHE_FILE = "tor_cache.txt"
TOR_CACHE_TTL = 1800
tor_nodes = set()
tor_cache_time = 0
ASN_CACHE = {}
DC_ASNS = {
15169:"Google",
16509:"Amazon AWS",
14618:"Amazon AWS",
8075:"Microsoft Azure",
8074:"Microsoft Azure",
13335:"Cloudflare",
20940:"Akamai",
24940:"Hetzner",
16276:"OVH",
35540:"OVH",
14061:"DigitalOcean",
20473:"Vultr",
63949:"Linode",
51167:"Contabo",
}
VPN_ASNS={
204254:"NordVPN",
209531:"NordVPN",
213023:"NordVPN",
393386:"ExpressVPN",
398121:"Surfshark",
202448:"CyberGhost",
207155:"IPVanish",
161689:"TorGuard",
202792:"ProtonVPN",
399796:"Mullvad",
396356:"Windscribe",
}
def get_asn(ip):
    if ip in ASN_CACHE:
        return ASN_CACHE[ip]
    if ip.startswith(
    (
    "192.168.",
    "10.",
    "172.16.",
    "127."
    )
    ):
        return None
    try:
        s=socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
        )
        s.settimeout(5)
        s.connect(
        (
        "whois.cymru.com",
        43
        )
        )
        s.send(
        f"{ip}\r\n".encode()
        )
        data=b""
        while True:
            chunk=s.recv(4096)
            if not chunk:
                break
            data+=chunk
        s.close()
        lines=data.decode().strip().split("\n")
        if len(lines)>=2:
            parts=lines[1].split("|")
            asn_num=int(
            parts[0].strip()
            )
            asn_name=parts[2].strip()
            ASN_CACHE[ip]=(
            asn_num,
            asn_name
            )
            return (
            asn_num,
            asn_name
            )
    except:
        pass
    return None
def load_tor_list():
    global tor_nodes
    global tor_cache_time
    now=time.time()
    if now-tor_cache_time<TOR_CACHE_TTL and tor_nodes:
        return
    for url in TOR_LIST_URLS:
        try:
            with urllib.request.urlopen(
            url,
            timeout=10
            ) as f:
                data=f.read().decode()
                tor_nodes={
                line.strip()
                for line in
                data.split("\n")
                if line.strip()
                and
                not line.startswith("#")
                }
                if tor_nodes:
                    tor_cache_time=now
                    with open(
                    TOR_CACHE_FILE,
                    "w"
                    ) as cache:
                        for ip in tor_nodes:
                            cache.write(
                            ip+"\n"
                            )
                    return
        except:
            continue
def is_tor_exit(ip):
    load_tor_list()
    if ip in tor_nodes:
        return "TOR Exit Node"
    return None
def is_datacenter(ip):
    result=get_asn(ip)
    if result:
        asn_num,asn_name=result
        if asn_num in DC_ASNS:
            return DC_ASNS[asn_num]
    return None
def is_vpn(ip):
    result=get_asn(ip)
    if result:
        asn_num,asn_name=result
        if asn_num in VPN_ASNS:
            return VPN_ASNS[asn_num]
    return None
def is_proxy(ip):
    try:
        hostname=socket.gethostbyaddr(ip)[0].lower()
        keywords=[
        "proxy",
        "vpn",
        "nordvpn",
        "expressvpn",
        "surfshark",
        "cyberghost",
        "privateinternetaccess",
        "mullvad",
        "protonvpn",
        ]
        for kw in keywords:
            if kw in hostname:
                return "Possible Proxy"
    except:
        pass
    return None
def analyze_mac(mac):
    try:
        eui=EUI(mac)
        vendor=str(
        eui.oui.registration().org
        )
    except:
        vendor="Unknown"
    first_byte=int(
    mac.split(":")[0],
    16
    )
    randomized=bool(
    first_byte & 0b10
    )
    return {
    "vendor":
    vendor,
    "randomized":
    randomized,
    "status":
    "Possible MAC Spoofing"
    if randomized
    or
    vendor=="Unknown"
    else
    "Normal"
    }
def risk_score(ip):
    score=0
    if is_tor_exit(ip):
        score+=60
    if is_vpn(ip):
        score+=40
    if is_proxy(ip):
        score+=30
    if is_datacenter(ip):
        score+=15
    return min(
    score,
    100
    )
def analyze_identity(
ip,
mac,
hostname=None
):
    mac_info=analyze_mac(mac)
    vpn=is_vpn(ip)
    tor=is_tor_exit(ip)
    proxy=is_proxy(ip)
    dc=is_datacenter(ip)
    if tor:
        ip_type="TOR"
    elif vpn:
        ip_type="VPN"
    elif proxy:
        ip_type="Possible Proxy"
    elif dc:
        ip_type="Hosting Provider"
    else:
        ip_type="Residential / Real IP"
    return {
    "IP":ip,
    "Hostname":hostname,
    "IP Type":
    ip_type,
    "VPN":
    vpn,
    "TOR":
    tor,
    "Proxy":
    proxy,
    "Hosting":
    dc,
    "MAC":
    mac,
    "Vendor":
    mac_info["vendor"],
    "MAC Status":
    mac_info["status"],
    "Risk Score":
    f"{risk_score(ip)}/100"
    }
