// ============================================
// GLOBAL THREAT INTELLIGENCE
// Real data only - no simulations
// ============================================

let globe;
let isRotating = true;

// Data stores
const threatPoints = [];
const attackerPoints = [];
const countryStats = new Map();
const geoCache = new Map();

// Stats
let totalInfra = 0;
let totalAttackers = 0;
let totalReports = 0;

// Colors
const COLORS = {
    infrastructure: '#ef4444',
    attacker: '#f97316',
    glow: {
        infra: 'rgba(239, 68, 68, 0.6)',
        attacker: 'rgba(249, 115, 22, 0.6)'
    }
};

// API endpoints
const API = {
    CORS_PROXY: 'https://api.allorigins.win/raw?url=',
    FEODO_TEXT: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    THREATFOX: 'https://threatfox.abuse.ch/export/json/recent/',
    DSHIELD_TOP: 'https://isc.sans.edu/api/topips/records/50?json',
    UPDATE_INTERVAL: 120000,
    GEO_DELAY: 400  // Faster loading
};

// ============================================
// GLOBE INITIALIZATION
// ============================================

// Major world cities for labels
const MAJOR_CITIES = [
    // North America
    { name: 'New York', lat: 40.7128, lng: -74.0060 },
    { name: 'Los Angeles', lat: 34.0522, lng: -118.2437 },
    { name: 'Chicago', lat: 41.8781, lng: -87.6298 },
    { name: 'Houston', lat: 29.7604, lng: -95.3698 },
    { name: 'Phoenix', lat: 33.4484, lng: -112.0740 },
    { name: 'Dallas', lat: 32.7767, lng: -96.7970 },
    { name: 'San Francisco', lat: 37.7749, lng: -122.4194 },
    { name: 'Seattle', lat: 47.6062, lng: -122.3321 },
    { name: 'Denver', lat: 39.7392, lng: -104.9903 },
    { name: 'Atlanta', lat: 33.7490, lng: -84.3880 },
    { name: 'Miami', lat: 25.7617, lng: -80.1918 },
    { name: 'Boston', lat: 42.3601, lng: -71.0589 },
    { name: 'Washington DC', lat: 38.9072, lng: -77.0369 },
    { name: 'Las Vegas', lat: 36.1699, lng: -115.1398 },
    { name: 'Toronto', lat: 43.6532, lng: -79.3832 },
    { name: 'Vancouver', lat: 49.2827, lng: -123.1207 },
    { name: 'Montreal', lat: 45.5017, lng: -73.5673 },
    { name: 'Mexico City', lat: 19.4326, lng: -99.1332 },
    // Europe
    { name: 'London', lat: 51.5074, lng: -0.1278 },
    { name: 'Paris', lat: 48.8566, lng: 2.3522 },
    { name: 'Berlin', lat: 52.5200, lng: 13.4050 },
    { name: 'Moscow', lat: 55.7558, lng: 37.6173 },
    { name: 'Amsterdam', lat: 52.3676, lng: 4.9041 },
    { name: 'Frankfurt', lat: 50.1109, lng: 8.6821 },
    { name: 'Madrid', lat: 40.4168, lng: -3.7038 },
    { name: 'Rome', lat: 41.9028, lng: 12.4964 },
    { name: 'Istanbul', lat: 41.0082, lng: 28.9784 },
    // Asia
    { name: 'Tokyo', lat: 35.6762, lng: 139.6503 },
    { name: 'Beijing', lat: 39.9042, lng: 116.4074 },
    { name: 'Shanghai', lat: 31.2304, lng: 121.4737 },
    { name: 'Seoul', lat: 37.5665, lng: 126.9780 },
    { name: 'Hong Kong', lat: 22.3193, lng: 114.1694 },
    { name: 'Singapore', lat: 1.3521, lng: 103.8198 },
    { name: 'Dubai', lat: 25.2048, lng: 55.2708 },
    { name: 'Mumbai', lat: 19.0760, lng: 72.8777 },
    { name: 'Bangkok', lat: 13.7563, lng: 100.5018 },
    { name: 'Jakarta', lat: -6.2088, lng: 106.8456 },
    // Other
    { name: 'Sydney', lat: -33.8688, lng: 151.2093 },
    { name: 'Sao Paulo', lat: -23.5505, lng: -46.6333 },
    { name: 'Cairo', lat: 30.0444, lng: 31.2357 },
    { name: 'Lagos', lat: 6.5244, lng: 3.3792 },
    { name: 'Johannesburg', lat: -26.2041, lng: 28.0473 },
];

function initGlobe() {
    const container = document.getElementById('globe');

    globe = Globe()
        // Night earth with city lights
        .globeImageUrl('//unpkg.com/three-globe/example/img/earth-night.jpg')
        .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
        .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
        .showAtmosphere(true)
        .atmosphereColor('#4f46e5')
        .atmosphereAltitude(0.15)
        // Country polygons with borders
        .polygonsData([])
        .polygonCapColor(() => 'rgba(30, 30, 60, 0.3)')
        .polygonSideColor(() => 'rgba(100, 100, 255, 0.1)')
        .polygonStrokeColor(() => 'rgba(100, 150, 255, 0.6)')
        .polygonAltitude(0.006)
        // Threat points
        .htmlElementsData([])
        .htmlElement(d => {
            const el = document.createElement('div');
            el.style.cssText = `
                width: ${d.size}px;
                height: ${d.size}px;
                border-radius: 50%;
                background: ${d.color};
                box-shadow: 0 0 ${d.size * 2}px ${d.glow}, 0 0 ${d.size * 4}px ${d.glow};
                pointer-events: none;
            `;
            return el;
        })
        .htmlAltitude(0.01)
        // Ring animations
        .ringsData([])
        .ringColor(() => t => `rgba(239, 68, 68, ${1 - t})`)
        .ringMaxRadius(4)
        .ringPropagationSpeed(3)
        .ringRepeatPeriod(800)
        (container);

    globe.pointOfView({ lat: 30, lng: 0, altitude: 2.2 });
    globe.controls().autoRotate = true;
    globe.controls().autoRotateSpeed = 0.4;
    globe.controls().minDistance = 120; // Allow closer zoom

    const resize = () => {
        globe.width(container.clientWidth);
        globe.height(container.clientHeight);
    };
    window.addEventListener('resize', resize);
    resize();
}

// ============================================
// API FUNCTIONS
// ============================================

async function fetchViaProxy(url) {
    const proxyUrl = `${API.CORS_PROXY}${encodeURIComponent(url)}`;
    console.log('Fetching via proxy:', url);

    const response = await fetch(proxyUrl);
    if (!response.ok) {
        throw new Error(`Proxy fetch failed: ${response.status}`);
    }
    return await response.text();
}

async function geolocateIP(ip) {
    if (geoCache.has(ip)) {
        return geoCache.get(ip);
    }

    // Skip private IPs
    if (ip.startsWith('192.168.') || ip.startsWith('10.') ||
        ip.startsWith('172.16.') || ip.startsWith('127.') ||
        ip.startsWith('0.') || ip.startsWith('255.')) {
        return null;
    }

    // Try ipapi.co first (HTTPS, good CORS)
    try {
        const response = await fetch(`https://ipapi.co/${ip}/json/`);
        const data = await response.json();

        if (!data.error && data.latitude && data.longitude) {
            const result = {
                lat: data.latitude,
                lon: data.longitude,
                city: data.city || 'Unknown',
                country: data.country_name || 'Unknown'
            };
            geoCache.set(ip, result);
            console.log(`Geolocated ${ip}: ${result.city}, ${result.country}`);
            return result;
        }
    } catch (e) {
        console.warn(`ipapi.co failed for ${ip}:`, e.message);
    }

    // Fallback to ip-api.com via proxy
    try {
        const url = `http://ip-api.com/json/${ip}?fields=status,country,city,lat,lon`;
        const text = await fetchViaProxy(url);
        const data = JSON.parse(text);

        if (data.status === 'success' && data.lat && data.lon) {
            const result = {
                lat: data.lat,
                lon: data.lon,
                city: data.city || 'Unknown',
                country: data.country || 'Unknown'
            };
            geoCache.set(ip, result);
            console.log(`Geolocated ${ip} via proxy: ${result.city}, ${result.country}`);
            return result;
        }
    } catch (e) {
        console.warn(`ip-api.com proxy failed for ${ip}:`, e.message);
    }

    return null;
}

// ============================================
// DATA FETCHING
// ============================================

async function fetchThreatInfrastructure() {
    console.log('Fetching threat infrastructure...');
    setStatus('Fetching threat infrastructure...', false);
    const threats = [];

    // Feodo Tracker
    try {
        const text = await fetchViaProxy(API.FEODO_TEXT);
        console.log('Feodo response length:', text.length);

        const lines = text.split('\n');
        for (const line of lines) {
            if (!line.trim() || line.startsWith('#')) continue;
            const match = line.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
            if (match) {
                threats.push({
                    ip: match[1],
                    type: 'C2 Server',
                    source: 'Feodo Tracker'
                });
            }
        }
        console.log('Feodo threats found:', threats.length);
    } catch (e) {
        console.error('Feodo fetch failed:', e);
    }

    // ThreatFox
    try {
        const text = await fetchViaProxy(API.THREATFOX);
        const data = JSON.parse(text);

        if (data.query_status === 'ok' && data.data) {
            let added = 0;
            for (const item of data.data) {
                if (added >= 30) break;
                const ipMatch = (item.ioc || '').match(/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/);
                if (ipMatch) {
                    threats.push({
                        ip: ipMatch[0],
                        type: item.threat_type || 'Malware',
                        malware: item.malware || 'Unknown',
                        source: 'ThreatFox'
                    });
                    added++;
                }
            }
            console.log('ThreatFox threats added:', added);
        }
    } catch (e) {
        console.error('ThreatFox fetch failed:', e);
    }

    return threats;
}

async function fetchActiveAttackers() {
    console.log('Fetching active attackers...');
    setStatus('Fetching active attackers...', false);
    const attackers = [];

    try {
        const text = await fetchViaProxy(API.DSHIELD_TOP);
        const data = JSON.parse(text);

        if (Array.isArray(data)) {
            for (const item of data) {
                if (item.source) {
                    attackers.push({
                        ip: item.source,
                        reports: parseInt(item.reports) || 0,
                        targets: parseInt(item.targets) || 0,
                        source: 'DShield'
                    });
                    totalReports += parseInt(item.reports) || 0;
                }
            }
            console.log('DShield attackers found:', attackers.length);
        }
    } catch (e) {
        console.error('DShield fetch failed:', e);
    }

    return attackers;
}

// ============================================
// POINT MANAGEMENT
// ============================================

async function processThreats(threats, type) {
    console.log(`Processing ${threats.length} ${type} threats...`);
    let processed = 0;

    for (const threat of threats) {
        const geo = await geolocateIP(threat.ip);

        if (geo) {
            const point = {
                lat: geo.lat,
                lng: geo.lon,
                type: type,
                color: type === 'infra' ? COLORS.infrastructure : COLORS.attacker,
                glow: type === 'infra' ? COLORS.glow.infra : COLORS.glow.attacker,
                size: type === 'infra' ? 6 : Math.min(10, 4 + (threat.reports || 0) / 50000),
                data: { ip: threat.ip, city: geo.city, country: geo.country, ...threat }
            };

            if (type === 'infra') {
                threatPoints.push(point);
                totalInfra++;
            } else {
                attackerPoints.push(point);
                totalAttackers++;
            }

            countryStats.set(geo.country, (countryStats.get(geo.country) || 0) + 1);

            addToFeed(point);
            addRing(geo.lat, geo.lon);
            updateGlobe();
            updateStats();

            processed++;
            setStatus(`Processing: ${processed} points loaded`, false);
        }

        // Rate limit for geolocation API
        await sleep(API.GEO_DELAY);
    }

    console.log(`Processed ${processed} ${type} points`);
    return processed;
}

function updateGlobe() {
    globe.htmlElementsData([...threatPoints, ...attackerPoints]);
}

function addRing(lat, lng) {
    const rings = globe.ringsData();
    const ring = { lat, lng };
    rings.push(ring);
    globe.ringsData(rings);

    setTimeout(() => {
        const idx = rings.indexOf(ring);
        if (idx > -1) rings.splice(idx, 1);
        globe.ringsData([...rings]);
    }, 2500);
}

// ============================================
// UI UPDATES
// ============================================

function updateStats() {
    document.getElementById('threatInfraCount').textContent = totalInfra;
    document.getElementById('activeAttackers').textContent = totalAttackers;
    document.getElementById('countriesCount').textContent = countryStats.size;
    document.getElementById('lastHourAttacks').textContent = formatNumber(totalReports);
    updateCountryList();
}

function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(0) + 'K';
    return n.toString();
}

function updateCountryList() {
    const container = document.getElementById('countryList');
    const sorted = [...countryStats.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8);
    container.innerHTML = sorted.map(([country, count]) => `
        <div class="country-item">
            <span class="country-name">${country}</span>
            <span class="country-count">${count}</span>
        </div>
    `).join('');
}

function addToFeed(point) {
    const feedList = document.getElementById('feedList');
    const empty = feedList.querySelector('.feed-empty');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = `feed-item ${point.type === 'attacker' ? 'attacker' : ''}`;

    const typeLabel = point.type === 'infra' ? point.data.type : 'Active Attacker';
    const detail = point.type === 'infra'
        ? (point.data.malware || point.data.source)
        : `${formatNumber(point.data.reports)} reports`;

    item.innerHTML = `
        <div class="feed-type">${typeLabel}</div>
        <div class="feed-location">${point.data.city}, ${point.data.country}</div>
        <div class="feed-detail">${point.data.ip} - ${detail}</div>
        <div class="feed-time">${new Date().toLocaleTimeString()}</div>
    `;

    feedList.insertBefore(item, feedList.firstChild);
    while (feedList.children.length > 50) feedList.removeChild(feedList.lastChild);
}

function setStatus(message, connected) {
    document.getElementById('statusDot').className = 'status-dot' + (connected ? ' connected' : '');
    document.getElementById('statusText').textContent = message;
    if (connected) {
        document.getElementById('updateTime').textContent = `Updated ${new Date().toLocaleTimeString()}`;
    }
}

// ============================================
// MAIN
// ============================================

async function fetchAllData() {
    console.log('=== Starting data fetch ===');

    try {
        const threats = await fetchThreatInfrastructure();
        if (threats.length > 0) {
            await processThreats(threats.slice(0, 40), 'infra');
        }

        const attackers = await fetchActiveAttackers();
        if (attackers.length > 0) {
            await processThreats(attackers.slice(0, 40), 'attacker');
        }

        const total = totalInfra + totalAttackers;
        if (total > 0) {
            setStatus(`Connected - ${total} threats loaded`, true);
        } else {
            setStatus('No data available - check console', false);
        }
    } catch (e) {
        console.error('Fetch error:', e);
        setStatus('Error: ' + e.message, false);
    }
}

function setupControls() {
    document.getElementById('toggleRotation').addEventListener('click', function() {
        isRotating = !isRotating;
        globe.controls().autoRotate = isRotating;
        this.classList.toggle('active', isRotating);
    });

    document.getElementById('resetView').addEventListener('click', () => {
        globe.pointOfView({ lat: 30, lng: 0, altitude: 2.2 }, 1000);
    });
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

async function init() {
    console.log('Initializing globe...');
    initGlobe();
    setupControls();
    document.getElementById('toggleRotation').classList.add('active');

    // Load country borders
    try {
        const countriesRes = await fetch('https://unpkg.com/world-atlas@2/countries-110m.json');
        const countriesData = await countriesRes.json();
        const countries = topojson.feature(countriesData, countriesData.objects.countries).features;
        globe.polygonsData(countries);
        console.log('Country borders loaded');
    } catch (e) {
        console.log('Could not load country borders:', e);
    }

    console.log('Starting data fetch...');
    await fetchAllData();

    // Live updates every 2 minutes
    setInterval(async () => {
        console.log('=== Refreshing data ===');

        // Clear old data
        threatPoints.length = 0;
        attackerPoints.length = 0;
        totalInfra = 0;
        totalAttackers = 0;
        totalReports = 0;
        countryStats.clear();

        // Clear feed
        const feedList = document.getElementById('feedList');
        feedList.innerHTML = '<div class="feed-empty">Refreshing...</div>';

        // Fetch fresh data
        await fetchAllData();
    }, API.UPDATE_INTERVAL);
}

document.addEventListener('DOMContentLoaded', init);
