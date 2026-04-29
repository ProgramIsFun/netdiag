#!/usr/bin/env python3
"""Network diagnostic snapshot — cross-platform (macOS, Linux, Windows)."""
import subprocess, re, platform

OS = platform.system()  # Darwin, Linux, Windows

# Common VPN/proxy/security services to detect
VPN_SERVICES = {
    "Cisco AnyConnect": {"proc": ["vpnagentd", "aciseagent"], "win_proc": ["vpnagent", "vpnui"]},
    "Tailscale":      {"proc": ["tailscaled"], "win_proc": ["tailscale"]},
    "Fortinet":       {"proc": ["forticlient", "fortitray"], "win_proc": ["FortiClient", "FortiTray"]},
    "Zscaler":        {"proc": ["zscaler", "ZSATunnel", "ZSAService"], "win_proc": ["ZSATunnel", "Zscaler"]},
    "OpenVPN":        {"proc": ["openvpn"], "win_proc": ["openvpn"]},
    "NordVPN":        {"proc": ["nordvpn", "nordlynx"], "win_proc": ["NordVPN"]},
    "Cloudflare WARP": {"proc": ["warp-svc", "cloudflared"], "win_proc": ["Cloudflare WARP"]},
    "GlobalProtect":  {"proc": ["GlobalProtect", "PanGPA", "PanGPS"], "win_proc": ["PanGPA", "GlobalProtect"]},
    "WireGuard":      {"proc": ["wireguard", "wg-quick"], "win_proc": ["wireguard"]},
    "Netskope":       {"proc": ["nsclient", "nsagent"], "win_proc": ["nsclient", "STAgent"]},
}

def run(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout.strip()

def header(title):
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")

print("\n╔════════════════════════════════════════════════════════════╗")
print("║              NETWORK DIAGNOSTIC SNAPSHOT                  ║")
print(f"║  OS: {OS:<53s} ║")
print("╚════════════════════════════════════════════════════════════╝")

# --- DNS ---
header("🌐 DNS Servers")
seen = set()
if OS == "Darwin":
    for line in run("scutil --dns").splitlines():
        if "nameserver" in line and "arpa" not in line and "local" not in line:
            ip = line.strip().split()[-1]
            if ip not in seen:
                seen.add(ip)
elif OS == "Linux":
    for line in run("cat /etc/resolv.conf 2>/dev/null").splitlines():
        if line.strip().startswith("nameserver"):
            ip = line.strip().split()[-1]
            if ip not in seen:
                seen.add(ip)
else:  # Windows
    for line in run("ipconfig /all").splitlines():
        if "DNS" in line and ":" in line:
            ip = line.split(":")[-1].strip()
            if re.match(r"\d+\.\d+\.\d+\.\d+", ip) and ip not in seen:
                seen.add(ip)
for ip in seen:
    print(f"    • {ip}")
if not seen:
    print("    (none found)")

# --- Interfaces ---
header("🔌 Active Network Interfaces")
known_labels = {"en0": "Wi-Fi", "wlan0": "Wi-Fi", "eth0": "Ethernet", "tun0": "VPN Tunnel"}
if OS == "Darwin":
    # Detect VPN network extensions (most reliable on macOS)
    net_ext_map = {}
    ext_keywords = {
        "paloalto": "GlobalProtect", "globalprotect": "GlobalProtect",
        "zscaler": "Zscaler", "cisco": "Cisco AnyConnect",
        "openvpn": "OpenVPN", "wireguard": "WireGuard",
        "cloudflare": "Cloudflare WARP", "fortinet": "Fortinet", "forticlient": "Fortinet",
        "nordvpn": "NordVPN", "tailscale": "Tailscale", "netskope": "Netskope",
    }
    in_net_ext = False
    for line in run("systemextensionsctl list 2>/dev/null").splitlines():
        if "network_extension" in line:
            in_net_ext = True
            continue
        if line.startswith("---"):
            in_net_ext = False
        if in_net_ext and "activated enabled" in line:
            line_lower = line.lower()
            for kw, svc_name in ext_keywords.items():
                if kw in line_lower:
                    net_ext_map[svc_name] = True
                    break

    # Detect VPNs registered with macOS
    for line in run("scutil --nc list").splitlines():
        m = re.search(r'"(.+?)"\s+\[.*?\]\s+\((\w+)\)', line)
        if m:
            known_labels[m.group(2)] = m.group(1)
    # Detect VPN utun interfaces by checking for corporate subnet routes
    ps_output = run("ps aux")
    routes_output = run("netstat -rn")
    # Find which VPN services are running
    running_vpns = [name for name, info in VPN_SERVICES.items()
                    if any(p.lower() in ps_output.lower() for p in info["proc"])]
    # Label utun interfaces — prefer network extension owner (most accurate)
    if running_vpns:
        for line in routes_output.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                iface = parts[-1]
                dest = parts[0]
                if iface.startswith("utun") and iface not in known_labels:
                    if dest in ("default", "0/1", "128.0/1") or "172.16/12" in dest or "192.168" in dest or "10/8" in dest:
                        # Use network extension owner if detected, otherwise list all running VPNs
                        ext_vpns = [v for v in running_vpns if v in net_ext_map]
                        if ext_vpns:
                            label = " / ".join(ext_vpns)
                        else:
                            label = " / ".join(running_vpns)
                        known_labels[iface] = f"{label} VPN"
                        break
if OS == "Darwin":
    for iface in run("ifconfig -l").split():
        info = run(f"ifconfig {iface} 2>/dev/null")
        ips = re.findall(r"inet (\S+)", info)
        if ips and "127.0.0.1" not in ips:
            status = "UP" if "UP" in info else "DOWN"
            label = known_labels.get(iface, "")
            suffix = f"  ← {label}" if label else ""
            print(f"    {iface:10s}  {', '.join(ips):20s}  [{status}]{suffix}")
elif OS == "Linux":
    for block in re.split(r"(?=^\d+:)", run("ip -o addr show"), flags=re.M):
        m = re.search(r"^\d+:\s+(\S+)\s+.*inet\s+(\S+)", block)
        if m and "127.0.0.1" not in m.group(2):
            iface, ip = m.group(1), m.group(2).split("/")[0]
            state = "UP" if "UP" in block else "DOWN"
            label = known_labels.get(iface, "")
            suffix = f"  ← {label}" if label else ""
            print(f"    {iface:10s}  {ip:20s}  [{state}]{suffix}")
else:  # Windows
    current_iface = ""
    for line in run("ipconfig /all").splitlines():
        m = re.match(r"(\S.*adapter\s+.+):", line)
        if m:
            current_iface = m.group(1)
        m2 = re.search(r"IPv4 Address.*?:\s*(\d+\.\d+\.\d+\.\d+)", line)
        if m2 and "127.0.0.1" not in m2.group(1):
            print(f"    {current_iface[:30]:30s}  {m2.group(1):20s}  [UP]")

# --- Routes ---
header("🗺️  Key Routes")
print(f"    {'Destination':<22s} {'Gateway':<20s} {'Interface':<10s}")
print(f"    {'─'*22} {'─'*20} {'─'*10}")
prefixes = ["default", "0.0.0.0", "10.", "172.", "192.168.", "100.64"]
if OS == "Darwin":
    for line in run("netstat -rn").splitlines():
        if any(line.startswith(p) for p in prefixes):
            parts = line.split()
            if len(parts) >= 4:
                print(f"    {parts[0]:<22s} {parts[1]:<20s} {parts[3]:<10s}")
elif OS == "Linux":
    for line in run("ip route").splitlines():
        parts = line.split()
        dest = parts[0] if parts else ""
        gw = dev = ""
        for i, p in enumerate(parts):
            if p == "via" and i + 1 < len(parts): gw = parts[i + 1]
            if p == "dev" and i + 1 < len(parts): dev = parts[i + 1]
        if not gw: gw = "direct"
        print(f"    {dest:<22s} {gw:<20s} {dev:<10s}")
else:  # Windows
    for line in run("route print").splitlines():
        parts = line.split()
        if len(parts) >= 5 and re.match(r"\d+\.\d+", parts[0]):
            dest, mask, gw, iface = parts[0], parts[1], parts[2], parts[3]
            print(f"    {dest + '/' + mask:<22s} {gw:<20s} {iface:<10s}")

print()
print("    💡 How to read this table:")
print("       Destination = IP range the packet is headed to")
print("       Gateway     = who your machine hands the packet to (next hop)")
print("       Interface   = which network adapter sends it out")
print()
print("       • If gateway is an IP → packet is forwarded by that device")
print("       • If gateway is link#N/MAC/direct → direct delivery, no middleman")
print("       • If gateway is an interface name (e.g. utun4) → into the tunnel")
print()
print("       Most specific route wins: /32 > /24 > /16 > /12 > default")

# --- VPN Tunnels ---
header("🔒 VPN Tunnels")
tunnels = [l.strip() for l in run("netstat -an").splitlines() if ".4501 " in l or ".4500 " in l or ".500 " in l]
if tunnels:
    for t in tunnels:
        print(f"    • {t}")
else:
    print("    (no active VPN tunnels detected)")

# --- Services ---
header("🛡️  Security Services (process check)")
if OS == "Windows":
    ps = run("tasklist")
    for svc_name, svc_info in VPN_SERVICES.items():
        found = any(p in ps for p in svc_info["win_proc"])
        print(f"    {svc_name + ':':<22s} {'✅ Running' if found else '❌ Not running'}")
else:
    ps = run("ps aux")
    for svc_name, svc_info in VPN_SERVICES.items():
        found = any(p.lower() in ps.lower() for p in svc_info["proc"])
        print(f"    {svc_name + ':':<22s} {'✅ Running' if found else '❌ Not running'}")

# --- Connectivity ---
header("📡 Connectivity Check")
ping_cmd = "ping -n 1 -w 1000" if OS == "Windows" else "ping -c1 -W1"
ping_ok = "Reply from" if OS == "Windows" else "1 packets received"
for host, label in [("8.8.8.8", "Google DNS (internet)")]:
    r = run(f"{ping_cmd} {host} 2>/dev/null")
    ok = "✅ Reachable" if ping_ok in r else "❌ Unreachable"
    print(f"    {label:<30s}  {host:<16s}  {ok}")

# --- Conflict Detection ---
header("⚠️  Conflict Detection")
has_issue = False

# Detect: VPN tunnel has default route, but some private subnets bypass it via Wi-Fi/Ethernet
# that are NOT the local LAN subnet (local LAN bypassing VPN is normal)
vpn_ifaces = [k for k, v in known_labels.items() if "VPN" in v]
if vpn_ifaces:
    # Find local LAN subnets (directly connected via Wi-Fi/Ethernet)
    local_subnets = set()
    if OS == "Darwin":
        for line in run("netstat -rn").splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[1] in ("link#11", "link#12", "link#13") and parts[3] in ("en0", "en1"):
                local_subnets.add(parts[0])

        # Check if VPN carries default route
        vpn_has_default = any(
            line.split()[0] == "default" and line.split()[-1] in vpn_ifaces
            for line in run("netstat -rn").splitlines()
            if len(line.split()) >= 4
        )

        if vpn_has_default:
            for line in run("netstat -rn").splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[3] in ("en0", "en1"):
                    dest = parts[0]
                    # Skip: local LAN, broadcast, loopback, link-local, own IP
                    if dest in local_subnets or "/32" in dest or dest.endswith(".255") or dest == "127.0.0.1":
                        continue
                    # Skip: individual host routes (MAC address gateways = ARP entries on local LAN)
                    if re.match(r"[0-9a-f]{1,2}:[0-9a-f]", parts[1]):
                        continue
                    # Skip: default route via Wi-Fi (normal fallback)
                    if dest == "default":
                        continue
                    # Remaining: a private subnet route going through Wi-Fi that should go through VPN
                    if re.match(r"(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)", dest):
                        if not has_issue:
                            print("    ℹ️  Private subnets routed via Wi-Fi instead of VPN:")
                            print("       (normal if on corporate network, check if off-site)")
                            has_issue = True
                        print(f"       • {dest} → {parts[3]}")

    elif OS == "Linux":
        vpn_has_default = any(
            line.startswith("default") and any(v in line for v in vpn_ifaces)
            for line in run("ip route").splitlines()
        )
        if vpn_has_default:
            for line in run("ip route").splitlines():
                parts = line.split()
                dest = parts[0] if parts else ""
                dev = ""
                for i, p in enumerate(parts):
                    if p == "dev" and i + 1 < len(parts): dev = parts[i + 1]
                if dest == "default" or not re.match(r"\d+\.\d+", dest):
                    continue
                if dev and dev not in vpn_ifaces and "scope link" not in line:
                    if re.match(r"(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)", dest):
                        if not has_issue:
                            print("    ℹ️  Private subnets routed via physical interface instead of VPN:")
                            print("       (normal if on corporate network, check if off-site)")
                            has_issue = True
                        print(f"       • {dest} → {dev}")

if not has_issue:
    if vpn_ifaces:
        print("    ✅ No routing conflicts detected. VPN tunnel is carrying traffic correctly.")
    else:
        print("    ✅ No VPN tunnel active — nothing to check.")

# --- LAN Devices ---
# NOTE: For a full device scan, arp-scan uses raw sockets:
#   socket(AF_PACKET, SOCK_RAW, ...) — a syscall that requires root (sudo).
#   This is because arp-scan crafts packets directly at layer 2, which
#   eventually invokes a system call that requires admin/root privileges.
# Without sudo, we fall back to reading the ARP cache (only recently contacted devices).
header("🏠 Devices on Local Network")
import os, sys
if "--scan" not in sys.argv:
    print("    (skipped — run with --scan for ARP device discovery)")
else:
    is_root = os.geteuid() == 0 if OS != "Windows" else (run("net session 2>&1") and "denied" not in run("net session 2>&1").lower())
    if not is_root:
        print("    ⚠️  Not running as root/admin — showing ARP cache only (may be incomplete).")
        print("       arp-scan requires raw sockets (AF_PACKET, SOCK_RAW), which is a")
        print("       system call that needs admin/root privileges.")
        if OS == "Windows":
            print("       Run as Administrator for a full scan.\n")
        else:
            print("       Run with sudo for a full arp-scan of all devices.\n")
    if is_root and OS != "Windows" and run("which arp-scan 2>/dev/null"):
        arp_out = run("sudo arp-scan -l 2>/dev/null")
    elif OS == "Linux":
        arp_out = run("ip neigh 2>/dev/null") or run("arp -a 2>/dev/null")
    else:
        arp_out = run("arp -a")
    devices = []
    for line in arp_out.splitlines():
        m = re.match(r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+(\S+)\s+on\s+(\S+)", line)
        if m and m.group(3) != "(incomplete)":
            devices.append((m.group(2), m.group(3), m.group(4), m.group(1) if m.group(1) != "?" else ""))
            continue
        m2 = re.match(r"(\d+\.\d+\.\d+\.\d+)\s+dev\s+(\S+)\s+lladdr\s+(\S+)", line)
        if m2:
            devices.append((m2.group(1), m2.group(3), m2.group(2), ""))
    if devices:
        print(f"    {'IP':<18s} {'MAC':<20s} {'Interface':<8s} {'Hostname'}")
        print(f"    {'─'*18} {'─'*20} {'─'*8} {'─'*20}")
        for ip, mac, iface, name in sorted(devices, key=lambda x: list(map(int, x[0].split('.')))):
            print(f"    {ip:<18s} {mac:<20s} {iface:<8s} {name}")
    else:
        print("    (no devices found)")

print(f"\n{'═' * 60}\n")
