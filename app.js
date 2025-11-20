// Initialize the map
const map = L.map('map').setView([20, 0], 2);

// Add OpenStreetMap tiles
L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
    attribution: '© OpenStreetMap contributors',
    maxZoom: 19,
}).addTo(map);

// Dark theme tile layer (alternative)
// L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
//     attribution: '© OpenStreetMap contributors © CARTO',
//     subdomains: 'abcd',
//     maxZoom: 19
// }).addTo(map);

// Attack type colors
const attackColors = {
    malware: '#ff4444',
    phishing: '#ff8800',
    ddos: '#ffdd00',
    ransomware: '#00ff88',
    intrusion: '#0088ff',
    exploit: '#8800ff'
};

// Store markers and attacks
let markers = [];
let attacks = [];
let isPlaying = true;
let updateInterval;
let countriesAffected = new Set();
let attackTypesSet = new Set();
let lastUpdateTime = null;
let geolocationCache = new Map(); // Cache IP geolocations to avoid rate limits
let realThreatCount = 0; // Track real vs simulated attacks

// API Configuration
const API_CONFIG = {
    // CORS proxy to bypass browser CORS restrictions
    // Using allorigins.win (free, no API key needed)
    CORS_PROXY: 'https://api.allorigins.win/get?url=',
    // Abuse.ch APIs (free, no API key needed)
    FEODO_TRACKER: 'https://feodotracker.abuse.ch/downloads/ipblocklist.json',
    URLHAUS: 'https://urlhaus.abuse.ch/downloads/csv_recent/',
    THREATFOX: 'https://threatfox.abuse.ch/export/json/recent/',
    // Alternative: Use Abuse.ch IP blocklist (plain text format that works better)
    FEODO_IPBLOCKLIST: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    // IP Geolocation APIs (multiple fallbacks)
    // Primary: BigDataCloud (free, good CORS support, no API key needed)
    IP_API_BIGDATACLOUD: 'https://api.bigdatacloud.net/data/ip-geolocation',
    // Fallback 1: ipapi.co (free, 1,000 req/day, no key needed)
    IP_API_IPAPI: 'https://ipapi.co',
    // Fallback 2: ip-api.com (45 req/min, no key needed)
    IP_API_IPAPI_COM: 'https://ip-api.com/json/',
    // Fallback 3: ip-api.io (alternative format)
    IP_API_IPAPI_IO: 'https://ip-api.io/json',
    // Rate limiting
    MIN_UPDATE_INTERVAL: 30000, // 30 seconds between API calls
    GEOLOCATION_DELAY: 2000, // 2 seconds between geolocation requests (30 req/min)
};

// Helper function to fetch text/JSON with CORS proxy fallback
async function fetchWithProxy(url) {
    let responseText = null;
    
    try {
        // First try direct fetch
        const directResponse = await fetch(url, {
            method: 'GET',
            mode: 'cors',
            headers: {
                'Accept': 'application/json, text/plain, */*',
            },
        });
        
        if (directResponse.ok) {
            responseText = await directResponse.text();
            return responseText;
        } else {
            throw new Error(`HTTP ${directResponse.status}`);
        }
    } catch (error) {
        // If direct fails (likely CORS), try with CORS proxy
        console.log('Direct fetch failed, trying CORS proxy...', error.message);
    }
    
    // Use CORS proxy
    try {
        const proxyUrl = `${API_CONFIG.CORS_PROXY}${encodeURIComponent(url)}`;
        const proxyResponse = await fetch(proxyUrl, {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
            },
        });
        
        if (!proxyResponse.ok) {
            throw new Error(`Proxy fetch failed: ${proxyResponse.status}`);
        }
        
        // The proxy wraps the response in a JSON object
        const proxyData = await proxyResponse.json();
        
        if (!proxyData || !proxyData.contents) {
            throw new Error('Invalid proxy response format');
        }
        
        responseText = proxyData.contents;
        return responseText;
    } catch (proxyError) {
        console.error('CORS proxy also failed:', proxyError);
        throw new Error(`Both direct and proxy fetch failed: ${proxyError.message}`);
    }
}

// Helper function to extract IP from various formats
function extractIP(text) {
    const ipRegex = /\b(?:\d{1,3}\.){3}\d{1,3}\b/;
    const match = text?.match(ipRegex);
    return match ? match[0] : null;
}

// Get geolocation for an IP address using multiple API fallbacks
async function getIPGeolocation(ip) {
    // Check cache first
    if (geolocationCache.has(ip)) {
        return geolocationCache.get(ip);
    }

    // Skip private/local IPs
    if (ip.startsWith('192.168.') || ip.startsWith('10.') || ip.startsWith('172.16.') || ip === '127.0.0.1') {
        return null;
    }

    // Try multiple APIs in order with fallbacks
    const apis = [
        // API 1: BigDataCloud (good CORS support, free)
        async () => {
            try {
                const url = `${API_CONFIG.IP_API_BIGDATACLOUD}?ip=${ip}`;
                const responseText = await fetchWithProxy(url);
                const data = JSON.parse(responseText);
                if (data && data.location && data.location.latitude && data.location.longitude) {
                    return {
                        lat: data.location.latitude,
                        lon: data.location.longitude,
                        city: data.location.city || data.city || 'Unknown',
                        country: data.location.country?.name || data.country || 'Unknown',
                        countryCode: data.location.country?.isoAlpha2 || data.countryCode || 'XX',
                    };
                }
                throw new Error('Invalid response format');
            } catch (error) {
                // If proxy fails, try direct
                const response = await fetch(`${API_CONFIG.IP_API_BIGDATACLOUD}?ip=${ip}`, {
                    method: 'GET',
                    headers: { 'Accept': 'application/json' }
                });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const data = await response.json();
                if (data && data.location && data.location.latitude && data.location.longitude) {
                    return {
                        lat: data.location.latitude,
                        lon: data.location.longitude,
                        city: data.location.city || data.city || 'Unknown',
                        country: data.location.country?.name || data.country || 'Unknown',
                        countryCode: data.location.country?.isoAlpha2 || data.countryCode || 'XX',
                    };
                }
                throw new Error('Invalid response format');
            }
        },
        // API 2: ipapi.co (1,000 req/day free tier, good CORS)
        async () => {
            try {
                const url = `${API_CONFIG.IP_API_IPAPI}/${ip}/json/`;
                const responseText = await fetchWithProxy(url);
                const data = JSON.parse(responseText);
                if (data && !data.error && data.latitude && data.longitude) {
                    return {
                        lat: parseFloat(data.latitude),
                        lon: parseFloat(data.longitude),
                        city: data.city || 'Unknown',
                        country: data.country_name || 'Unknown',
                        countryCode: data.country_code || 'XX',
                    };
                }
                throw new Error(data.reason || 'Invalid response');
            } catch (error) {
                // Try direct if proxy fails
                const response = await fetch(`${API_CONFIG.IP_API_IPAPI}/${ip}/json/`, {
                    method: 'GET',
                    headers: { 'Accept': 'application/json' }
                });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const data = await response.json();
                if (data && !data.error && data.latitude && data.longitude) {
                    return {
                        lat: parseFloat(data.latitude),
                        lon: parseFloat(data.longitude),
                        city: data.city || 'Unknown',
                        country: data.country_name || 'Unknown',
                        countryCode: data.country_code || 'XX',
                    };
                }
                throw new Error(data.reason || 'Invalid response');
            }
        },
        // API 3: ip-api.com (45 req/min, fallback)
        async () => {
            try {
                const url = `${API_CONFIG.IP_API_IPAPI_COM}${ip}?fields=status,country,countryCode,lat,lon,city`;
                const responseText = await fetchWithProxy(url);
                const data = JSON.parse(responseText);
                if (data.status === 'success' && data.lat && data.lon) {
                    return {
                        lat: data.lat,
                        lon: data.lon,
                        city: data.city || 'Unknown',
                        country: data.country || 'Unknown',
                        countryCode: data.countryCode || 'XX',
                    };
                }
                throw new Error('Failed to geolocate');
            } catch (error) {
                // Try direct if proxy fails
                const response = await fetch(`${API_CONFIG.IP_API_IPAPI_COM}${ip}?fields=status,country,countryCode,lat,lon,city`, {
                    method: 'GET',
                    headers: { 'Accept': 'application/json' }
                });
                if (!response.ok) throw new Error(`HTTP ${response.status}`);
                const data = await response.json();
                if (data.status === 'success' && data.lat && data.lon) {
                    return {
                        lat: data.lat,
                        lon: data.lon,
                        city: data.city || 'Unknown',
                        country: data.country || 'Unknown',
                        countryCode: data.countryCode || 'XX',
                    };
                }
                throw new Error('Failed to geolocate');
            }
        },
    ];

    // Try each API until one works
    const apiNames = ['BigDataCloud', 'ipapi.co', 'ip-api.com'];
    for (let i = 0; i < apis.length; i++) {
        try {
            const geoData = await apis[i]();
            if (geoData && geoData.lat && geoData.lon) {
                // Cache for 1 hour
                geolocationCache.set(ip, geoData);
                setTimeout(() => geolocationCache.delete(ip), 3600000);
                // Log successful API (only occasionally to avoid spam)
                if (Math.random() < 0.1) { // 10% chance to log
                    console.log(`✓ Geolocated ${ip} using ${apiNames[i]}`);
                }
                return geoData;
            }
        } catch (error) {
            // If this is not the last API, continue to next one silently
            if (i < apis.length - 1) {
                // Only log occasionally to avoid console spam
                if (Math.random() < 0.05) { // 5% chance
                    console.log(`${apiNames[i]} failed for ${ip}, trying next API...`);
                }
                continue;
            } else {
                // Last API failed, log warning
                console.warn(`All geolocation APIs failed for IP ${ip}. Last error:`, error.message);
            }
        }
    }

    return null;
}

// Fetch malware IPs from Feodo Tracker
async function fetchFeodoTrackerData() {
    try {
        // Try JSON endpoint first
        const responseText = await fetchWithProxy(API_CONFIG.FEODO_TRACKER);
        
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (parseError) {
            // If JSON fails, try the text blocklist format
            console.log('JSON parse failed, trying text format...');
            return await fetchFeodoTrackerTextFormat();
        }
        
        if (data && Array.isArray(data)) {
            updateAPIStatus('✅ Connected to Feodo Tracker (Abuse.ch)', true);
            return data
                .filter(item => item.ip_address)
                .slice(0, 20) // Limit to 20 most recent
                .map(item => ({
                    ip: item.ip_address,
                    type: 'malware',
                    malware: item.malware || 'Unknown Malware',
                    port: item.port || 'Unknown',
                    status: item.status || 'online',
                    firstSeen: item.first_seen,
                }));
        }
    } catch (error) {
        console.warn('Failed to fetch Feodo Tracker JSON, trying text format:', error);
        return await fetchFeodoTrackerTextFormat();
    }
    return [];
}

// Fetch Feodo Tracker in text format (more reliable for CORS)
async function fetchFeodoTrackerTextFormat() {
    try {
        const text = await fetchWithProxy(API_CONFIG.FEODO_IPBLOCKLIST);
        
        // Parse text blocklist format
        // Format: IP addresses, one per line (may have comments starting with #)
        const lines = text.split('\n');
        const ips = [];
        
        for (const line of lines) {
            const trimmedLine = line.trim();
            // Skip empty lines and comments
            if (!trimmedLine || trimmedLine.startsWith('#')) continue;
            
            // Extract IP (may have whitespace or comments after)
            const ipMatch = trimmedLine.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
            if (ipMatch) {
                ips.push({
                    ip: ipMatch[1],
                    type: 'malware',
                    malware: 'Feodo C2 Server',
                    status: 'online',
                });
            }
            
            // Limit to 20 IPs
            if (ips.length >= 20) break;
        }
        
        if (ips.length > 0) {
            updateAPIStatus('✅ Connected to Feodo Tracker (Abuse.ch)', true);
            return ips;
        }
    } catch (error) {
        console.warn('Failed to fetch Feodo Tracker text format:', error);
    }
    return [];
}

// Fetch recent threats from ThreatFox
async function fetchThreatFoxData() {
    try {
        const responseText = await fetchWithProxy(API_CONFIG.THREATFOX);
        
        let data;
        try {
            data = JSON.parse(responseText);
        } catch (parseError) {
            console.warn('Failed to parse ThreatFox JSON:', parseError);
            return [];
        }
        
        if (data && data.query_status === 'ok' && Array.isArray(data.data)) {
            updateAPIStatus('✅ Connected to ThreatFox (Abuse.ch)', true);
            const threats = [];
            for (const item of data.data.slice(0, 15)) {
                const ip = extractIP(item.ioc || item.malware || '');
                if (ip) {
                    // Determine attack type based on threat type
                    let attackType = 'intrusion';
                    if (item.malware && item.malware.toLowerCase().includes('ransomware')) {
                        attackType = 'ransomware';
                    } else if (item.threat_type === 'botnet_cc') {
                        attackType = 'malware';
                    } else if (item.threat_type === 'payload_delivery') {
                        attackType = 'exploit';
                    }
                    
                    threats.push({
                        ip: ip,
                        type: attackType,
                        malware: item.malware || 'Unknown Threat',
                        threatType: item.threat_type || 'unknown',
                        confidence: item.confidence_level || 50,
                        firstSeen: item.first_seen,
                    });
                }
            }
            return threats;
        }
    } catch (error) {
        console.warn('Failed to fetch ThreatFox data:', error);
        // Don't update status here as Feodo might work
    }
    return [];
}

// Create attack from real threat data
async function createAttackFromThreat(threat) {
    // Safety check
    if (!threat || !threat.ip) {
        return null;
    }
    
    try {
        const geoData = await getIPGeolocation(threat.ip);
        
        if (!geoData || !geoData.lat || !geoData.lon) {
            return null; // Skip if we can't geolocate
        }

        // Calculate severity based on confidence or status
        let severity = 3; // Default
        if (threat.confidence) {
            severity = Math.min(5, Math.max(1, Math.floor(threat.confidence / 20)));
        } else if (threat.status === 'online') {
            severity = 4;
        }

        const attack = {
            id: `${threat.ip}-${Date.now()}-${Math.random()}`,
            lat: geoData.lat,
            lon: geoData.lon,
            type: threat.type || 'intrusion',
            city: geoData.city || 'Unknown',
            country: geoData.country || 'Unknown',
            countryCode: geoData.countryCode || 'XX',
            timestamp: new Date(),
            severity: severity,
            sourceIP: threat.ip,
            targetIP: null,
            malware: threat.malware,
            threatType: threat.threatType,
            confidence: threat.confidence,
            firstSeen: threat.firstSeen,
            isReal: true, // Mark as real data
        };

        return attack;
    } catch (error) {
        console.warn(`Error creating attack from threat ${threat.ip}:`, error);
        return null;
    }
}

// Generate a fallback simulated attack if API fails
function generateFallbackAttack() {
    // Fallback cities for simulated attacks
    const fallbackCities = [
        { name: 'New York', lat: 40.7128, lon: -74.0060, country: 'USA' },
        { name: 'London', lat: 51.5074, lon: -0.1278, country: 'UK' },
        { name: 'Tokyo', lat: 35.6762, lon: 139.6503, country: 'Japan' },
        { name: 'Moscow', lat: 55.7558, lon: 37.6173, country: 'Russia' },
        { name: 'Beijing', lat: 39.9042, lon: 116.4074, country: 'China' },
        { name: 'Paris', lat: 48.8566, lon: 2.3522, country: 'France' },
        { name: 'Berlin', lat: 52.5200, lon: 13.4050, country: 'Germany' },
    ];

    const attackTypes = ['malware', 'phishing', 'ddos', 'ransomware', 'intrusion', 'exploit'];
    const city = fallbackCities[Math.floor(Math.random() * fallbackCities.length)];
    const attackType = attackTypes[Math.floor(Math.random() * attackTypes.length)];
    
    const lat = city.lat + (Math.random() - 0.5) * 2;
    const lon = city.lon + (Math.random() - 0.5) * 2;
    
    return {
        id: Date.now() + Math.random(),
        lat: lat,
        lon: lon,
        type: attackType,
        city: city.name,
        country: city.country,
        timestamp: new Date(),
        severity: Math.floor(Math.random() * 5) + 1,
        sourceIP: generateRandomIP(),
        targetIP: generateRandomIP(),
        isReal: false,
    };
}

// Generate random IP address (for fallback)
function generateRandomIP() {
    return `${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}`;
}

// Create marker for an attack
function createMarker(attack) {
    const color = attackColors[attack.type];
    const size = 5 + attack.severity * 2;
    
    // Use different border for real vs simulated attacks
    const borderColor = attack.isReal ? '#ff0000' : '#ffffff';
    const borderWidth = attack.isReal ? 2 : 1;
    
    const marker = L.circleMarker([attack.lat, attack.lon], {
        radius: size,
        fillColor: color,
        color: borderColor,
        weight: borderWidth,
        opacity: 1,
        fillOpacity: 0.8,
    }).addTo(map);
    
    // Build popup content
    let popupContent = `
        <div style="color: #333; font-family: Arial, sans-serif;">
            <strong>🚨 ${attack.type.toUpperCase()}</strong>
            ${attack.isReal ? ' <span style="color: #ff0000; font-size: 0.8em;">[REAL]</span>' : ''}
            <br>
            <strong>Location:</strong> ${attack.city}, ${attack.country}<br>
            <strong>Severity:</strong> ${'⭐'.repeat(attack.severity)}<br>
            <strong>Source IP:</strong> ${attack.sourceIP}<br>
    `;
    
    if (attack.targetIP) {
        popupContent += `<strong>Target IP:</strong> ${attack.targetIP}<br>`;
    }
    
    if (attack.malware) {
        popupContent += `<strong>Malware/Threat:</strong> ${attack.malware}<br>`;
    }
    
    if (attack.confidence !== undefined) {
        popupContent += `<strong>Confidence:</strong> ${attack.confidence}%<br>`;
    }
    
    if (attack.firstSeen) {
        popupContent += `<strong>First Seen:</strong> ${new Date(attack.firstSeen * 1000).toLocaleString()}<br>`;
    }
    
    popupContent += `<strong>Detected:</strong> ${attack.timestamp.toLocaleTimeString()}</div>`;
    
    marker.bindPopup(popupContent);
    
    // Add animation
    marker.setStyle({ fillOpacity: 0.8 });
    
    // Pulsing animation for real attacks
    if (attack.isReal) {
        let pulseCount = 0;
        const pulseInterval = setInterval(() => {
            pulseCount++;
            if (pulseCount >= 5) {
                clearInterval(pulseInterval);
                return;
            }
            const currentOpacity = marker.options.fillOpacity;
            marker.setStyle({ fillOpacity: currentOpacity === 0.8 ? 0.4 : 0.8 });
        }, 500);
    }
    
    return marker;
}

// Update API status indicator
function updateAPIStatus(message, isSuccess = true) {
    const statusElement = document.getElementById('statusText');
    const statusContainer = document.getElementById('apiStatus');
    if (statusElement && statusContainer) {
        statusElement.textContent = message;
        statusContainer.className = `api-status ${isSuccess ? 'success' : 'warning'}`;
    }
}

// Add attack to map and feed
function addAttack(attack) {
    // Safety check: make sure attack is valid
    if (!attack || !attack.lat || !attack.lon) {
        console.warn('Invalid attack data:', attack);
        return;
    }
    
    attacks.push(attack);
    countriesAffected.add(attack.country);
    attackTypesSet.add(attack.type);
    
    if (attack.isReal) {
        realThreatCount++;
    }
    
    try {
        const marker = createMarker(attack);
        markers.push({ marker, attack });
        
        // Add to feed
        addToFeed(attack);
        
        // Update stats
        updateStats();
    } catch (error) {
        console.error('Error adding attack to map:', error);
        // Remove from arrays if marker creation failed
        attacks.pop();
        if (attack.isReal) {
            realThreatCount--;
        }
    }
    
    // Keep only last 1000 attacks in memory
    if (attacks.length > 1000) {
        const oldest = attacks.shift();
        if (oldest && oldest.isReal) {
            realThreatCount--;
        }
        const markerIndex = markers.findIndex(m => m.attack.id === oldest.id);
        if (markerIndex !== -1) {
            try {
                if (map.hasLayer(markers[markerIndex].marker)) {
                    map.removeLayer(markers[markerIndex].marker);
                }
            } catch (error) {
                console.warn('Error removing old marker:', error);
            }
            markers.splice(markerIndex, 1);
        }
    }
}

// Add attack to feed
function addToFeed(attack) {
    const feedContent = document.getElementById('feedContent');
    const attackItem = document.createElement('div');
    attackItem.className = `attack-item ${attack.type}`;
    
    const timeStr = attack.timestamp.toLocaleTimeString();
    const realBadge = attack.isReal ? ' <span style="color: #ff4444;">[REAL]</span>' : '';
    let description = `
        <div class="time">${timeStr}</div>
        <div class="description">
            <strong>${attack.type.toUpperCase()}</strong>${realBadge} detected in ${attack.city}, ${attack.country}
            <br>Severity: ${'⭐'.repeat(attack.severity)}
    `;
    
    if (attack.malware) {
        description += `<br>Threat: ${attack.malware}`;
    }
    
    if (attack.sourceIP) {
        description += `<br>IP: ${attack.sourceIP}`;
    }
    
    description += '</div>';
    
    attackItem.innerHTML = description;
    
    feedContent.insertBefore(attackItem, feedContent.firstChild);
    
    // Keep only last 30 items in feed
    while (feedContent.children.length > 30) {
        feedContent.removeChild(feedContent.lastChild);
    }
}

// Update statistics
function updateStats() {
    document.getElementById('activeThreats').textContent = attacks.length;
    document.getElementById('countriesAffected').textContent = countriesAffected.size;
    document.getElementById('attackTypes').textContent = attackTypesSet.size;
    const realThreatsElement = document.getElementById('realThreats');
    if (realThreatsElement) {
        realThreatsElement.textContent = realThreatCount;
    }
}

// Filter attacks by type
function filterAttacks(type) {
    markers.forEach(({ marker, attack }) => {
        if (type === 'all' || attack.type === type) {
            if (!map.hasLayer(marker)) {
                marker.addTo(map);
            }
        } else {
            if (map.hasLayer(marker)) {
                map.removeLayer(marker);
            }
        }
    });
}

// Clear all attacks
function clearMap() {
    // Remove all markers from map
    markers.forEach(({ marker }) => {
        if (map.hasLayer(marker)) {
            map.removeLayer(marker);
        }
    });
    
    // Clear all arrays and sets
    markers = [];
    attacks = [];
    countriesAffected.clear();
    attackTypesSet.clear();
    realThreatCount = 0;
    
    // Clear the feed
    const feedContent = document.getElementById('feedContent');
    if (feedContent) {
        feedContent.innerHTML = '';
    }
    
    // Reset rate limiting to allow immediate new data fetch
    lastUpdateTime = null;
    
    // Clear geolocation cache to allow fresh lookups
    geolocationCache.clear();
    
    // Update stats
    updateStats();
    
    // Update status
    updateAPIStatus('🗺️ Map cleared. Fetching new data...', true);
    
    // Optionally trigger a new fetch if playing
    if (isPlaying) {
        // Wait a moment then fetch new data
        setTimeout(() => {
            updateAttacks();
        }, 500);
    }
}

// Main update loop - fetch real threat data
async function updateAttacks() {
    if (!isPlaying) return;
    
    // Check rate limiting
    const now = Date.now();
    if (lastUpdateTime && (now - lastUpdateTime) < API_CONFIG.MIN_UPDATE_INTERVAL) {
        // Use fallback if too soon
        const fallback = generateFallbackAttack();
        addAttack(fallback);
        return;
    }
    
    lastUpdateTime = now;
    
    // Show loading status
    updateAPIStatus('🔄 Fetching threat data...', true);
    
    try {
        // Fetch real threat data from multiple sources
        const [feodoData, threatFoxData] = await Promise.allSettled([
            fetchFeodoTrackerData(),
            fetchThreatFoxData(),
        ]);
        
        // Extract successful results
        const feodoResults = feodoData.status === 'fulfilled' ? feodoData.value : [];
        const threatFoxResults = threatFoxData.status === 'fulfilled' ? threatFoxData.value : [];
        
        // Log failures for debugging
        if (feodoData.status === 'rejected') {
            console.warn('Feodo Tracker fetch failed:', feodoData.reason);
        }
        if (threatFoxData.status === 'rejected') {
            console.warn('ThreatFox fetch failed:', threatFoxData.reason);
        }
        
        // Combine all threats
        const allThreats = [...feodoResults, ...threatFoxResults];
        
        if (allThreats.length > 0) {
            updateAPIStatus('🔄 Geolocating threat IPs...', true);
            
            // Process threats (limit concurrent geolocation requests)
            // Reduced to 5 per update to be safe with rate limits
            const threatsToProcess = allThreats.slice(0, 5);
            
            let processedCount = 0;
            for (const threat of threatsToProcess) {
                const attack = await createAttackFromThreat(threat);
                if (attack) {
                    addAttack(attack);
                    processedCount++;
                    // Delay to avoid rate limits on geolocation APIs
                    await new Promise(resolve => setTimeout(resolve, API_CONFIG.GEOLOCATION_DELAY)); // ~2 sec = 30 req/min
                }
            }
            
            if (processedCount > 0) {
                updateAPIStatus(`✅ Loaded ${processedCount} real threats`, true);
            } else {
                // If no attacks were geolocated, add a fallback
                updateAPIStatus('⚠️ Using simulated data (geolocation failed)', false);
                const fallback = generateFallbackAttack();
                addAttack(fallback);
            }
        } else {
            // Fallback to simulated if no data available
            updateAPIStatus('⚠️ Using simulated data (no API data available). Check console for details.', false);
            const fallback = generateFallbackAttack();
            addAttack(fallback);
        }
    } catch (error) {
        console.error('Error fetching threat data:', error);
        updateAPIStatus('⚠️ Using simulated data (error occurred). Check console for details.', false);
        // Fallback to simulated attack
        const fallback = generateFallbackAttack();
        addAttack(fallback);
    }
}

// Event listeners
document.getElementById('playPauseBtn').addEventListener('click', () => {
    isPlaying = !isPlaying;
    const btn = document.getElementById('playPauseBtn');
    btn.textContent = isPlaying ? '⏸ Pause' : '▶ Play';
    if (isPlaying) {
        updateAttacks();
    }
});

document.getElementById('clearBtn').addEventListener('click', clearMap);

document.getElementById('attackTypeFilter').addEventListener('change', (e) => {
    filterAttacks(e.target.value);
});

// Start the threat intelligence monitoring
function startMonitoring() {
    // Initial load - fetch real data
    updateAttacks();
    
    // Update every 30-60 seconds (to respect rate limits)
    updateInterval = setInterval(() => {
        updateAttacks();
    }, 35000 + Math.random() * 25000); // 35-60 seconds
    
    // Also show some initial markers with a slight delay for visualization
    setTimeout(() => {
        for (let i = 0; i < 3; i++) {
            setTimeout(() => {
                const fallback = generateFallbackAttack();
                addAttack(fallback);
            }, i * 500);
        }
    }, 2000);
}

// Initialize
startMonitoring();

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (updateInterval) {
        clearInterval(updateInterval);
    }
});

