# Cyber Attack Map 🛡️

A real-time interactive web application that visualizes cyber attacks on a global world map. The app displays live threat intelligence with attack markers, statistics, and a live feed of security events.

## Features

- 🌍 **Interactive World Map** - Built with Leaflet.js using OpenStreetMap
- 🔴 **Real-time Attack Visualization** - Live attack markers with color-coded types
- 📊 **Live Statistics** - Track active threats, affected countries, attack types, and real vs simulated threats
- 🎯 **Attack Types** - Visualize malware, phishing, DDoS, ransomware, intrusion, and exploits
- 🔌 **Real API Integration** - Uses Abuse.ch (Feodo Tracker, ThreatFox) for real threat intelligence
- 🌐 **IP Geolocation** - Maps threat IPs to real-world locations using ip-api.com
- 📱 **Responsive Design** - Works on desktop and mobile devices
- 🎨 **Modern UI** - Dark theme with smooth animations
- ⚠️ **Smart Fallback** - Gracefully falls back to simulated data if APIs are unavailable

## Quick Start

### Option 1: Simple HTTP Server (No Installation Required)

1. Navigate to the project directory:
```bash
cd CyberAttackMap
```

2. Start a local server:
```bash
# Using Python 3
python3 -m http.server 8000

# Or using Python 2
python -m http.server 8000

# Or using Node.js (if you have npx)
npx serve .
```

3. Open your browser and visit:
```
http://localhost:8000
```

### Option 2: Using npm scripts

```bash
npm start
# or
npm run serve
```

## How It Works

- **Real Threat Intelligence**: The app fetches real cyber threat data from Abuse.ch APIs:
  - **Feodo Tracker**: Lists malware C2 (Command & Control) servers
  - **ThreatFox**: IOC (Indicators of Compromise) feed with various threat types
- **IP Geolocation**: Threat IPs are geolocated using ip-api.com to display attacks on the map
- **Smart Rate Limiting**: Respects API rate limits (45 requests/minute for geolocation API)
- **Fallback System**: If APIs are unavailable (due to CORS restrictions or network issues), the app gracefully falls back to simulated data
- **Real-time Updates**: New attacks appear every 30-60 seconds (to respect rate limits)
- **Interactive Markers**: Click on attack markers to see detailed information including malware names, IPs, and timestamps
- **Filtering**: Filter attacks by type (malware, phishing, DDoS, etc.)
- **Live Feed**: View a chronological feed of recent attacks with real threat indicators

## Attack Types

- 🔴 **Malware** - Malicious software attacks
- 🟠 **Phishing** - Social engineering attacks
- 🟡 **DDoS** - Distributed Denial of Service attacks
- 🟢 **Ransomware** - Encryption-based attacks
- 🔵 **Intrusion** - Unauthorized access attempts
- 🟣 **Exploit** - Vulnerability exploitation attacks

## Controls

- **Play/Pause Button**: Start or pause the attack simulation
- **Clear Map**: Remove all attacks from the map
- **Filter Dropdown**: Filter attacks by specific type

## Customization

You can customize the app by:

- Modifying attack generation frequency in `app.js`
- Adding more cities/coordinates in the `majorCities` array
- Changing colors in the `attackColors` object
- Adjusting styling in `styles.css`

## Future Enhancements

- ✅ Integration with real threat intelligence APIs (Done!)
- WebSocket support for true real-time updates
- Historical attack analysis
- Geographic heat maps
- Attack pattern detection
- Additional threat intelligence sources
- CORS proxy server for better API access (if needed)

## Technology Stack

- **HTML5** - Structure
- **CSS3** - Styling with modern features
- **JavaScript (ES6+)** - Logic and interactivity
- **Leaflet.js** - Interactive mapping library
- **OpenStreetMap** - Map tiles
- **Abuse.ch APIs** - Real threat intelligence (Feodo Tracker, ThreatFox)
- **ip-api.com** - IP geolocation service

## API Information

### Data Sources (Free, No API Key Required)

1. **Abuse.ch Feodo Tracker**
   - Endpoint: `https://feodotracker.abuse.ch/downloads/ipblocklist.json`
   - Provides: Malware C2 server IPs
   - Free, publicly available

2. **Abuse.ch ThreatFox**
   - Endpoint: `https://threatfox.abuse.ch/export/json/recent/`
   - Provides: IOCs (Indicators of Compromise)
   - Free, publicly available

3. **ip-api.com** (IP Geolocation)
   - Endpoint: `http://ip-api.com/json/{ip}`
   - Free tier: 45 requests/minute
   - No API key required for basic use

### Important Notes

- **CORS Restrictions**: Some security APIs may block browser CORS requests. The app handles this gracefully and falls back to simulated data if needed.
- **Rate Limits**: The app respects API rate limits by caching geolocation data and spacing requests appropriately.
- **Privacy**: Only public threat intelligence IPs are queried for geolocation. No user data is sent to APIs.

## License

MIT License - See LICENSE file for details