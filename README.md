# Global Threat Intelligence

A real-time 3D globe visualization of cyber threats using real threat intelligence data. No simulations - only real data from security research organizations.

## Features

- **3D Interactive Globe** - Beautiful Earth visualization with atmosphere effects, built with Globe.gl and Three.js
- **Real Threat Data Only** - No fake or simulated data
  - **Threat Infrastructure** (Red) - C2 servers and malware hosts from Abuse.ch
  - **Active Attackers** (Orange) - Top attacking IPs from SANS DShield honeypot network
- **Live Statistics** - Track threat infrastructure, active attackers, affected countries, and report counts
- **Live Feed** - Real-time feed of threats as they're loaded with IP addresses and locations
- **Premium UI** - Dark theme with glassmorphism panels, Inter + JetBrains Mono fonts

## Data Sources

All data comes from legitimate security research organizations:

| Source | Type | Data Provided |
|--------|------|---------------|
| [Abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) | Threat Infrastructure | Botnet C2 server IPs |
| [Abuse.ch ThreatFox](https://threatfox.abuse.ch/) | Threat Infrastructure | IOCs (Indicators of Compromise) |
| [SANS DShield](https://isc.sans.edu/) | Active Attackers | Top attacking IPs from global honeypot network |
| [ipapi.co](https://ipapi.co/) | Geolocation | IP to location mapping |

## Quick Start

1. Navigate to the project directory:
```bash
cd CyberAttackMap
```

2. Start a local server:
```bash
python3 -m http.server 8080
```

3. Open your browser:
```
http://localhost:8080
```

## How It Works

1. **Fetches threat data** from Abuse.ch and SANS DShield APIs via CORS proxy
2. **Geolocates each IP** using ipapi.co to get coordinates
3. **Displays points on globe** with glow effects - red for infrastructure, orange for attackers
4. **Ring animations** pulse outward when new threats appear
5. **Updates feed** with threat details (IP, location, type, source)

## What the Data Represents

### Threat Infrastructure (Red Points)
These are known malicious servers - C2 (Command & Control) servers that malware communicates with, or hosts serving malicious payloads. This data comes from security researchers who track botnets.

### Active Attackers (Orange Points)
These are IP addresses that have been observed attacking honeypot sensors in the SANS DShield network. The size of points reflects the number of attack reports.

## Controls

- **Drag** - Rotate the globe
- **Scroll** - Zoom in/out
- **Rotation button** - Toggle auto-rotation
- **Reset button** - Return to default view

## Technology Stack

- **Globe.gl** - 3D globe rendering
- **Three.js** - WebGL graphics
- **Vanilla JS** - No frameworks
- **Inter & JetBrains Mono** - Typography

## Privacy & Ethics

- Only queries public threat intelligence APIs
- No user data is collected or transmitted
- All displayed IPs are from public blocklists or honeypot reports
- Data is used for educational visualization only

## License

MIT License
