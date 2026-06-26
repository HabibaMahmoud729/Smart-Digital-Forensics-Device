import threading
ip_timeline = {}
mac_timeline = {}
timeline_lock = threading.Lock()
MAX_CONNECTIONS_PER_IP = 2000
def _wrap_text(text, width):
    text = str(text)
    if len(text) <= width:
        return [text]
    chunks = text.split(", ")
    lines = []
    current = ""
    for chunk in chunks:
        piece = chunk if not current else ", " + chunk
        if len(current) + len(piece) <= width:
            current += piece
        else:
            if current:
                lines.append(current)
            while len(chunk) > width:
                lines.append(chunk[:width])
                chunk = chunk[width:]
            current = chunk
    if current:
        lines.append(current)
    return lines or [""]
def _make_table(headers, rows, indent="        ", max_col_width=40):
    if not rows:
        rows = [["-"] * len(headers)]
    wrapped_rows = []
    for row in rows:
        wrapped_rows.append([_wrap_text(cell, max_col_width) for cell in row])
    col_widths = []
    for i, h in enumerate(headers):
        max_cell = max(
            (max(len(line) for line in cell_lines) for row in wrapped_rows for cell_lines in [row[i]]),
            default=0,
        )
        col_widths.append(min(max(len(h), max_cell), max_col_width))

    def fmt_line(cells):
        return indent + " | ".join(
            str(c).ljust(col_widths[i]) for i, c in enumerate(cells)
        )
    sep = indent + "-+-".join("-" * w for w in col_widths)
    lines = [fmt_line(headers), sep]
    for wrapped_row in wrapped_rows:
        height = max(len(c) for c in wrapped_row)
        for line_idx in range(height):
            cells = [
                wrapped_row[i][line_idx] if line_idx < len(wrapped_row[i]) else ""
                for i in range(len(wrapped_row))
            ]
            lines.append(fmt_line(cells))
    return "\n".join(lines)
def _ensure_ip(ip, mac, time_now, device_type):
    if ip not in ip_timeline:
        ip_timeline[ip] = {
            "macs_seen": {},
            "current_mac": mac,
            "first_seen": time_now,
            "last_seen": time_now,
            "device_type": device_type,
            "connections": [],
            "ports_targeted": set(),
            "protocols_used": {},
            "is_attacker": False,
            "attack_types": [],
        }
    entry = ip_timeline[ip]
    entry["last_seen"] = time_now
    if device_type and device_type != "Unknown":
        entry["device_type"] = device_type
    if mac and mac != "N/A":
        if mac not in entry["macs_seen"]:
            entry["macs_seen"][mac] = {"first_seen": time_now, "last_seen": time_now}
        else:
            entry["macs_seen"][mac]["last_seen"] = time_now
        entry["current_mac"] = mac
    return entry
def _ensure_mac(mac, ip, time_now):
    if not mac or mac == "N/A":
        return
    if mac not in mac_timeline:
        mac_timeline[mac] = {
            "ips_seen": {},
            "current_ip": ip,
            "first_seen": time_now,
            "last_seen": time_now,
        }
    entry = mac_timeline[mac]
    entry["last_seen"] = time_now
    if ip and ip != "N/A":
        if ip not in entry["ips_seen"]:
            entry["ips_seen"][ip] = {"first_seen": time_now, "last_seen": time_now}
        else:
            entry["ips_seen"][ip]["last_seen"] = time_now
        entry["current_ip"] = ip
def update_ip_timeline(src_ip, src_mac, dst_ip, dst_mac, dst_port,
                        proto, flags_info, device_type, time_now):
    if not src_ip or src_ip == "N/A":
        return
    with timeline_lock:
        entry = _ensure_ip(src_ip, src_mac, time_now, device_type)
        _ensure_mac(src_mac, src_ip, time_now)
        if dst_ip and dst_ip != "N/A":
            _ensure_ip(dst_ip, dst_mac, time_now, "Unknown")
            _ensure_mac(dst_mac, dst_ip, time_now)
        if dst_port and dst_port != "N/A":
            try:
                entry["ports_targeted"].add(int(dst_port))
            except (ValueError, TypeError):
                pass
        entry["protocols_used"][proto] = entry["protocols_used"].get(proto, 0) + 1
        if len(entry["connections"]) < MAX_CONNECTIONS_PER_IP:
            entry["connections"].append({
                "time": time_now,
                "dst_ip": dst_ip,
                "dst_port": dst_port,
                "proto": proto,
                "flags": flags_info,
            })
def mark_as_attacker(ip, attack_type):
    if not ip or ip == "N/A":
        return
    with timeline_lock:
        if ip not in ip_timeline:
            ip_timeline[ip] = {
                "macs_seen": {}, "current_mac": "N/A",
                "first_seen": "N/A", "last_seen": "N/A",
                "device_type": "Unknown", "connections": [],
                "ports_targeted": set(), "protocols_used": {},
                "is_attacker": False, "attack_types": [],
            }
        entry = ip_timeline[ip]
        entry["is_attacker"] = True
        if attack_type not in entry["attack_types"]:
            entry["attack_types"].append(attack_type)
def append_timeline_to_report(ip):
    with timeline_lock:
        entry = ip_timeline.get(ip)
        if not entry:
            return ""
        block = "\n\n" + ("-" * 80)
        block += "\n        FULL IP/MAC ACTIVITY TIMELINE FOR THIS ATTACKER"
        block += "\n" + ("-" * 80)
        block += format_ip_report(ip, entry)
        block += "\n" + ("-" * 80) + "\n"
        return block
def get_spoofing_warnings(ip):
    warnings = []
    entry = ip_timeline.get(ip)
    if entry and len(entry["macs_seen"]) > 1:
        macs = ", ".join(entry["macs_seen"].keys())
        warnings.append(f"This IP was seen with {len(entry['macs_seen'])} different MACs: {macs}")
    mac = entry["current_mac"] if entry else None
    if mac and mac in mac_timeline and len(mac_timeline[mac]["ips_seen"]) > 1:
        ips = ", ".join(mac_timeline[mac]["ips_seen"].keys())
        warnings.append(f"This MAC was seen with {len(mac_timeline[mac]['ips_seen'])} different IPs: {ips}")
    return warnings
def format_ip_report(ip, entry):
    spoof_warnings = get_spoofing_warnings(ip)
    proto_summary = ", ".join(f"{p}:{c}" for p, c in entry["protocols_used"].items()) or "None"
    ports = ", ".join(str(p) for p in sorted(entry["ports_targeted"])) or "None"
    all_macs = ", ".join(entry["macs_seen"].keys()) or "N/A"
    attack_types = ", ".join(entry["attack_types"]) if entry["is_attacker"] else "-"
    info_headers = ["Field", "Value"]
    info_rows = [
        ["IP", ip],
        ["Current MAC", entry["current_mac"]],
        ["All MACs Seen", all_macs],
        ["Device Type", entry["device_type"]],
        ["First Seen", entry["first_seen"]],
        ["Last Seen", entry["last_seen"]],
        ["Total Connections", str(len(entry["connections"]))],
        ["Protocols Used", proto_summary],
        ["Ports Targeted", ports],
        ["Flagged As Attacker", "YES" if entry["is_attacker"] else "No"],
        ["Attack Types", attack_types],
    ]
    lines = [f"\n        {'-'*76}"]
    lines.append(_make_table(info_headers, info_rows))

    if spoof_warnings:
        lines.append("\n        Spoofing Indicators:")
        for w in spoof_warnings:
            lines.append(f"            - {w}")
    shown = entry["connections"][:200]
    if shown:
        conn_headers = ["Time", "Dest IP", "Port", "Proto", "Flags"]
        conn_rows = [
            [c["time"], c["dst_ip"], str(c["dst_port"]), c["proto"], c["flags"]]
            for c in shown
        ]
        lines.append("\n        Connection Log:")
        lines.append(_make_table(conn_headers, conn_rows))
        if len(entry["connections"]) > 200:
            lines.append(f"        ... and {len(entry['connections']) - 200} more connections")
    else:
        lines.append("\n        Connection Log: (none recorded)")

    return "\n".join(lines)
def generate_summary_table():
    headers = ["IP", "MAC", "Device", "Attacker?", "Attack Type"]
    rows = []
    for ip, entry in ip_timeline.items():
        attack_types = ", ".join(entry["attack_types"]) if entry["is_attacker"] else "-"
        rows.append([
            ip,
            entry["current_mac"],
            entry["device_type"],
            "YES" if entry["is_attacker"] else "No",
            attack_types,
        ])
    return _make_table(headers, rows)
def generate_full_pcap_report():
    with timeline_lock:
        attacker_ips = {ip: e for ip, e in ip_timeline.items() if e["is_attacker"]}
        normal_ips = {ip: e for ip, e in ip_timeline.items() if not e["is_attacker"]}
        report = "\n" + "=" * 80
        report += "\n                    IP/MAC FORENSIC ACTIVITY REPORT"
        report += "\n" + "=" * 80
        report += "\n\n>>> ATTACKER ACTIVITY SUMMARY <<<\n"
        if not attacker_ips:
            report += "\n        No attacker activity detected in this capture.\n"
        else:
            for ip, entry in attacker_ips.items():
                report += format_ip_report(ip, entry) + "\n"
        report += "\n\n>>> SUMMARY TABLE (All Tracked IPs) <<<\n\n"
        report += generate_summary_table()

        report += "\n" + "=" * 80 + "\n"
        return report
def generate_attacker_report_live(ip):
    with timeline_lock:
        entry = ip_timeline.get(ip)
        if not entry:
            return ""
        report = "\n" + "=" * 80
        report += "\n              ATTACKER FULL ACTIVITY TIMELINE (Live)"
        report += "\n" + "=" * 80
        report += format_ip_report(ip, entry)
        report += "\n" + "=" * 80 + "\n"
        return report