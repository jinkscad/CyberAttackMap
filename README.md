# Global Threat Intelligence

A real-time 3D globe visualization of cyber threats using real threat intelligence data. No simulations - only real data from security research organizations.

# Live Demo
 https://jinkscad.github.io/CyberAttackMap/

## Features

- **3D Interactive Globe** - Satellite imagery with Mapbox GL JS, 3D terrain, atmosphere effects, and star field
- **Real Threat Data Only** - No fake or simulated data
  - **C2/Malware** (Red) - C2 servers and malware hosts from Abuse.ch
  - **Active Attackers** (Orange) - Top attacking IPs from SANS DShield and Blocklist.de
  - **Malicious URLs** (Cyan) - Phishing and malware distribution sites from URLhaus
  - **Suspicious IPs** (Yellow) - Known bad actors from CINS Army honeypot network
- **Interactive Features**
  - Click feed entries to fly to threat location
  - Click markers to view threat details popup
  - About modal with comprehensive glossary
- **Live Statistics** - Track all threat types and affected countries
- **Live Feed** - Real-time feed of threats with IP addresses and locations
- **Mobile Support** - Bottom sheet interface for mobile devices
- **Premium UI** - Dark theme with glassmorphism panels, Inter + JetBrains Mono fonts

## Data Sources

All data comes from legitimate security research organizations:

| Source | Type | Data Provided |
|--------|------|---------------|
| [Abuse.ch Feodo Tracker](https://feodotracker.abuse.ch/) | C2/Malware | Botnet C2 server IPs |
| [Abuse.ch ThreatFox](https://threatfox.abuse.ch/) | C2/Malware | IOCs (Indicators of Compromise) |
| [Abuse.ch URLhaus](https://urlhaus.abuse.ch/) | Malicious URLs | Malware distribution sites |
| [CINS Army](https://cinsscore.com/) | Suspicious IPs | Known bad actors from honeypot network |
| [SANS DShield](https://isc.sans.edu/) | Active Attackers | Top attacking IPs from global honeypot network |
| [Blocklist.de](https://www.blocklist.de/) | Active Attackers | Brute force attackers from fail2ban |
| [ipapi.co](https://ipapi.co/) | Geolocation | IP to location mapping |

## Quick Start

1. Get a free Mapbox token at [mapbox.com/signup](https://account.mapbox.com/auth/signup/)

2. Add your token to `app.js` line 9:
```javascript
mapboxgl.accessToken = 'YOUR_TOKEN_HERE';
```

3. Start a local server:
```bash
python3 -m http.server 8000
```

4. Open your browser:
```
http://localhost:8000
```

## How It Works

1. **Fetches threat data** from 6 different sources via CORS proxy
2. **Geolocates each IP** using ipapi.co to get coordinates
3. **Displays markers on globe** with color-coded glow effects
4. **Click any marker** to see threat details in a popup
5. **Click feed entries** to fly to that location on the globe
6. **Auto-refreshes** every 10 minutes with fresh data

## What the Data Represents

### C2/Malware Infrastructure (Red Points)
These are known malicious servers - C2 (Command & Control) servers that malware communicates with, or hosts serving malicious payloads. This data comes from security researchers who track botnets.

### Active Attackers (Orange Points)
These are IP addresses that have been observed attacking honeypot sensors in the SANS DShield network or reported to Blocklist.de. The size of points reflects the number of attack reports.

### Malicious URLs (Cyan Points)
These are servers hosting phishing pages or malware distribution sites. The IPs are extracted from URLs collected by URLhaus.

### Suspicious IPs (Yellow Points)
These are IPs flagged as "bad actors" by the CINS Army collective intelligence network based on observed malicious activity patterns including scanning, exploitation attempts, and other suspicious behavior.

## Controls

- **Drag** - Rotate the globe
- **Scroll** - Zoom in/out
- **Rotation button** - Toggle auto-rotation
- **Reset button** - Return to default view
- **About button** - View glossary and documentation
- **Click marker** - View threat details
- **Click feed entry** - Fly to location

## Technology Stack

- **Mapbox GL JS** - 3D globe with satellite imagery
- **Vanilla JS** - No frameworks
- **Inter & JetBrains Mono** - Typography

## Privacy & Ethics

- Only queries public threat intelligence APIs
- No user data is collected or transmitted
- All displayed IPs are from public blocklists or honeypot reports
- Data is used for educational visualization only

## License

MIT License
