# netdiag

Network diagnostic snapshot tool. Single script, no dependencies, cross-platform.

## What it does

Runs a quick network health check and prints everything in one snapshot:

- **DNS servers** — what's resolving your domains
- **Active interfaces** — Wi-Fi, Ethernet, VPN tunnels (auto-labels detected VPN services)
- **Routing table** — where your traffic goes, with a guide on how to read it
- **VPN tunnels** — active IPsec/IKEv2 connections
- **Security services** — detects 10 common VPN/proxy services (Cisco AnyConnect, Tailscale, Fortinet, Zscaler, OpenVPN, NordVPN, Cloudflare WARP, GlobalProtect, WireGuard, Netskope)
- **Connectivity check** — can you reach the internet?
- **Conflict detection** — flags routing conflicts (e.g. corporate traffic bypassing VPN)
- **LAN devices** — ARP cache or full scan (opt-in)

## Usage

```bash
python3 netdiag.py            # quick snapshot (no LAN scan)
python3 netdiag.py --scan     # includes LAN device discovery
```

No `pip install`, no venv, no dependencies. Just Python 3 and your OS.

## Supported platforms

| OS | Tested |
|----|--------|
| macOS | ✅ |
| Linux | ✅ |
| Windows | ✅ (PowerShell or CMD) |

## Example output

```
╔════════════════════════════════════════════════════════════╗
║              NETWORK DIAGNOSTIC SNAPSHOT                  ║
║  OS: Darwin                                                ║
╚════════════════════════════════════════════════════════════╝

  🌐 DNS Servers
    • 8.8.8.8
    • 8.8.4.4

  🔌 Active Network Interfaces
    en0         192.168.1.100         [UP]  ← Wi-Fi
    utun4       10.167.17.85          [UP]  ← VPN

  🛡️  Security Services (process check)
    Cisco AnyConnect:      ✅ Running
    Tailscale:             ❌ Not running
    Fortinet:              ❌ Not running
    Zscaler:               ❌ Not running
    OpenVPN:               ❌ Not running
    NordVPN:               ❌ Not running
    Cloudflare WARP:       ❌ Not running
    GlobalProtect:         ❌ Not running
    WireGuard:             ❌ Not running
    Netskope:              ❌ Not running

  📡 Connectivity Check
    Google DNS (internet)           8.8.8.8           ✅ Reachable

  ⚠️  Conflict Detection
    ✅ No routing conflicts detected.
```
