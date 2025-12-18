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

function initGlobe() {
    const container = document.getElementById('globe');

    globe = Globe()
        .globeImageUrl('//unpkg.com/three-globe/example/img/earth-blue-marble.jpg')
        .bumpImageUrl('//unpkg.com/three-globe/example/img/earth-topology.png')
        .backgroundImageUrl('//unpkg.com/three-globe/example/img/night-sky.png')
        .showAtmosphere(true)
        .atmosphereColor('#3b82f6')
        .atmosphereAltitude(0.2)
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
        .ringsData([])
        .ringColor(() => t => `rgba(239, 68, 68, ${1 - t})`)
        .ringMaxRadius(4)
        .ringPropagationSpeed(3)
        .ringRepeatPeriod(800)
        (container);

    globe.pointOfView({ lat: 30, lng: 0, altitude: 2.2 });
    globe.controls().autoRotate = true;
    globe.controls().autoRotateSpeed = 0.4;

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

    console.log('Starting data fetch...');
    await fetchAllData();
}

document.addEventListener('DOMContentLoaded', init);
