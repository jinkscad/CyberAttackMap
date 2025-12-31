// ============================================
// GLOBAL THREAT INTELLIGENCE
// Real data only - no simulations
// Powered by Mapbox GL JS
// ============================================

// !! IMPORTANT: Add your Mapbox token here !!
// Get a free token at: https://account.mapbox.com/auth/signup/
mapboxgl.accessToken = 'pk.eyJ1Ijoiamlua3NzIiwiYSI6ImNtanRlaHc0djR6YW4zZXB1YzhmdGRtZXoifQ.0lPLh02JMh-mFNSRucuWTA';

let map;
let isRotating = true;
let rotationAnimation;
let markers = [];

// Data stores
const threatPoints = [];
const attackerPoints = [];
const phishingPoints = [];
const sslPoints = [];
const countryStats = new Map();
const geoCache = new Map();

// Stats
let totalInfra = 0;
let totalAttackers = 0;
let totalPhishing = 0;
let totalSSL = 0;
let totalReports = 0;

// Colors
const COLORS = {
    infrastructure: '#ef4444',
    attacker: '#f97316',
    phishing: '#06b6d4',
    ssl: '#eab308'
};

// API endpoints
const API = {
    CORS_PROXY: 'https://api.allorigins.win/raw?url=',
    FEODO_TEXT: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt',
    THREATFOX: 'https://threatfox.abuse.ch/export/json/recent/',
    URLHAUS: 'https://urlhaus.abuse.ch/downloads/text_recent/',
    CINS_ARMY: 'https://cinsscore.com/list/ci-badguys.txt',
    DSHIELD_TOP: 'https://isc.sans.edu/api/topips/records/50?json',
    BLOCKLIST_DE: 'https://lists.blocklist.de/lists/all.txt',
    UPDATE_INTERVAL: 600000,
    GEO_DELAY: 350
};

// ============================================
// MAPBOX GLOBE INITIALIZATION
// ============================================

function initGlobe() {
    // Check for token
    if (mapboxgl.accessToken === 'YOUR_MAPBOX_TOKEN_HERE') {
        document.getElementById('globe').innerHTML = `
            <div style="display:flex;flex-direction:column;align-items:center;justify-content:center;height:100%;color:#fff;text-align:center;padding:40px;">
                <h2 style="margin-bottom:16px;">Mapbox Token Required</h2>
                <p style="color:rgba(255,255,255,0.6);margin-bottom:24px;max-width:400px;">
                    To use the satellite globe, you need a free Mapbox access token.
                </p>
                <ol style="text-align:left;color:rgba(255,255,255,0.6);margin-bottom:24px;">
                    <li>Go to <a href="https://account.mapbox.com/auth/signup/" target="_blank" style="color:#3b82f6;">mapbox.com/signup</a></li>
                    <li>Create a free account</li>
                    <li>Copy your public token</li>
                    <li>Paste it in app.js line 10</li>
                </ol>
                <p style="color:rgba(255,255,255,0.4);font-size:12px;">Free tier: 50,000 map loads/month</p>
            </div>
        `;
        setStatus('Mapbox token required - see instructions', false);
        return false;
    }

    map = new mapboxgl.Map({
        container: 'globe',
        style: 'mapbox://styles/mapbox/satellite-streets-v12',
        center: [0, 20],
        zoom: 1.5,
        projection: 'globe',
        antialias: true
    });

    map.on('style.load', () => {
        // Add atmosphere and fog for realistic globe effect
        map.setFog({
            color: 'rgb(20, 20, 30)',
            'high-color': 'rgb(40, 50, 80)',
            'horizon-blend': 0.1,
            'space-color': 'rgb(10, 10, 20)',
            'star-intensity': 0.8
        });

        // Add 3D terrain
        map.addSource('mapbox-dem', {
            type: 'raster-dem',
            url: 'mapbox://mapbox.mapbox-terrain-dem-v1',
            tileSize: 512,
            maxzoom: 14
        });
        map.setTerrain({ source: 'mapbox-dem', exaggeration: 1.5 });

        // Start rotation
        startRotation();
    });

    // Disable some default controls for cleaner look
    map.dragRotate.enable();
    map.touchZoomRotate.enable();

    return true;
}

function startRotation() {
    if (rotationAnimation) cancelAnimationFrame(rotationAnimation);

    function rotate() {
        if (!isRotating || !map) return;

        const center = map.getCenter();
        center.lng += 0.02;
        map.setCenter(center);

        rotationAnimation = requestAnimationFrame(rotate);
    }

    rotate();
}

function stopRotation() {
    if (rotationAnimation) {
        cancelAnimationFrame(rotationAnimation);
        rotationAnimation = null;
    }
}

// Pause rotation on user interaction
function setupInteractionHandlers() {
    if (!map) return;

    map.on('mousedown', () => {
        if (isRotating) stopRotation();
    });

    map.on('mouseup', () => {
        if (isRotating) startRotation();
    });

    map.on('touchstart', () => {
        if (isRotating) stopRotation();
    });

    map.on('touchend', () => {
        if (isRotating) startRotation();
    });
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

    if (ip.startsWith('192.168.') || ip.startsWith('10.') ||
        ip.startsWith('172.16.') || ip.startsWith('127.') ||
        ip.startsWith('0.') || ip.startsWith('255.')) {
        return null;
    }

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

    try {
        const text = await fetchViaProxy(API.FEODO_TEXT);
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
        }
    } catch (e) {
        console.error('DShield fetch failed:', e);
    }

    try {
        const text = await fetchViaProxy(API.BLOCKLIST_DE);
        const lines = text.split('\n');
        let added = 0;
        for (const line of lines) {
            if (added >= 30) break;
            const ip = line.trim();
            if (ip && /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
                attackers.push({
                    ip: ip,
                    reports: 1,
                    targets: 1,
                    source: 'Blocklist.de'
                });
                added++;
            }
        }
    } catch (e) {
        console.error('Blocklist.de fetch failed:', e);
    }

    return attackers;
}

async function fetchMaliciousURLs() {
    console.log('Fetching malicious URLs...');
    setStatus('Fetching malicious URLs...', false);
    const urls = [];

    try {
        const text = await fetchViaProxy(API.URLHAUS);
        const lines = text.split('\n');
        let added = 0;

        for (const line of lines) {
            if (added >= 25) break;
            const urlStr = line.trim();
            if (!urlStr || urlStr.startsWith('#')) continue;

            // Extract IP from URL
            const ipMatch = urlStr.match(/(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/);
            if (ipMatch) {
                urls.push({
                    ip: ipMatch[1],
                    type: 'Malicious URL',
                    url: urlStr.substring(0, 50),
                    source: 'URLhaus'
                });
                added++;
            }
        }
        console.log('URLhaus threats found:', urls.length);
    } catch (e) {
        console.error('URLhaus fetch failed:', e);
    }

    return urls;
}

async function fetchSuspiciousIPs() {
    console.log('Fetching suspicious IPs...');
    setStatus('Fetching suspicious IPs...', false);
    const threats = [];

    try {
        const text = await fetchViaProxy(API.CINS_ARMY);
        const lines = text.split('\n');
        let added = 0;

        for (const line of lines) {
            if (added >= 25) break;
            const ip = line.trim();
            // Skip comments and empty lines
            if (!ip || ip.startsWith('#')) continue;

            // Validate IP format
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) {
                threats.push({
                    ip: ip,
                    type: 'Suspicious IP',
                    reason: 'Known Bad Actor',
                    source: 'CINS Army'
                });
                added++;
            }
        }
        console.log('CINS Army threats found:', threats.length);
    } catch (e) {
        console.error('CINS Army fetch failed:', e);
    }

    return threats;
}

// ============================================
// MARKER MANAGEMENT
// ============================================

function createMarkerElement(color, size) {
    // Create outer container with larger click area
    const container = document.createElement('div');
    container.className = 'threat-marker-container';
    container.style.cssText = `
        width: ${size + 20}px;
        height: ${size + 20}px;
        display: flex;
        align-items: center;
        justify-content: center;
        cursor: pointer;
    `;

    // Inner visible dot
    const dot = document.createElement('div');
    dot.className = 'threat-marker';
    dot.style.cssText = `
        width: ${size}px;
        height: ${size}px;
        border-radius: 50%;
        background: ${color};
        box-shadow: 0 0 ${size}px ${color}, 0 0 ${size * 2}px ${color};
        border: 2px solid rgba(255,255,255,0.4);
        pointer-events: none;
    `;

    container.appendChild(dot);
    return container;
}

function getPopupHTML(data, type) {
    let typeLabel;
    switch (type) {
        case 'infra': typeLabel = data.type || 'C2 Server'; break;
        case 'attacker': typeLabel = 'Active Attacker'; break;
        case 'phishing': typeLabel = 'Malicious URL'; break;
        case 'ssl': typeLabel = 'Suspicious IP'; break;
        default: typeLabel = 'Threat';
    }

    let detail = '';
    if (type === 'infra') detail = data.malware || data.source;
    else if (type === 'attacker') detail = `${formatNumber(data.reports)} reports`;
    else if (type === 'phishing') detail = data.url || data.source;
    else if (type === 'ssl') detail = data.reason || data.source;

    return `
        <div class="popup-content">
            <div class="popup-type ${type}">${typeLabel}</div>
            <div class="popup-location">${data.city}, ${data.country}</div>
            <div class="popup-ip">${data.ip}</div>
            <div class="popup-detail">${detail}</div>
        </div>
    `;
}

function addMarker(lat, lon, color, size, data, type) {
    if (!map) return;

    const el = createMarkerElement(color, size);

    // Create popup
    const popup = new mapboxgl.Popup({
        offset: 15,
        closeButton: true,
        closeOnClick: true,
        maxWidth: '250px'
    }).setHTML(getPopupHTML(data, type));

    const marker = new mapboxgl.Marker({
        element: el,
        anchor: 'center'
    })
        .setLngLat([lon, lat])
        .setPopup(popup)
        .addTo(map);

    markers.push({ marker, lat, lon, data, type });

    
    return marker;
}

function flyToLocation(lat, lon) {
    if (!map) return;
    map.flyTo({
        center: [lon, lat],
        zoom: 5,
        duration: 1500
    });
}

function clearMarkers() {
    markers.forEach(m => m.marker.remove());
    markers = [];
}

async function processThreats(threats, type) {
    console.log(`Processing ${threats.length} ${type} threats...`);
    let processed = 0;

    const colorMap = {
        infra: COLORS.infrastructure,
        attacker: COLORS.attacker,
        phishing: COLORS.phishing,
        ssl: COLORS.ssl
    };

    for (const threat of threats) {
        const geo = await geolocateIP(threat.ip);

        if (geo) {
            const color = colorMap[type] || colorMap.infra;
            const size = type === 'attacker' ? Math.min(18, 12 + (threat.reports || 0) / 50000) : 14;

            const point = {
                lat: geo.lat,
                lng: geo.lon,
                type: type,
                data: { ip: threat.ip, city: geo.city, country: geo.country, ...threat }
            };

            addMarker(geo.lat, geo.lon, color, size, point.data, type);

            switch (type) {
                case 'infra':
                    threatPoints.push(point);
                    totalInfra++;
                    break;
                case 'attacker':
                    attackerPoints.push(point);
                    totalAttackers++;
                    break;
                case 'phishing':
                    phishingPoints.push(point);
                    totalPhishing++;
                    break;
                case 'ssl':
                    sslPoints.push(point);
                    totalSSL++;
                    break;
            }

            countryStats.set(geo.country, (countryStats.get(geo.country) || 0) + 1);

            addToFeed(point);
            updateStats();

            processed++;
            setStatus(`Processing: ${processed} points loaded`, false);
        }

        await sleep(API.GEO_DELAY);
    }

    console.log(`Processed ${processed} ${type} points`);
    return processed;
}

// ============================================
// UI UPDATES
// ============================================

function updateStats() {
    document.getElementById('threatInfraCount').textContent = totalInfra;
    document.getElementById('activeAttackers').textContent = totalAttackers;
    document.getElementById('phishingCount').textContent = totalPhishing;
    document.getElementById('sslCount').textContent = totalSSL;
    document.getElementById('countriesCount').textContent = countryStats.size;
    updateCountryList();
}

function formatNumber(n) {
    if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
    if (n >= 1000) return (n / 1000).toFixed(0) + 'K';
    return n.toString();
}

function updateCountryList() {
    const html = [...countryStats.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
        .map(([country, count]) => `
            <div class="country-item">
                <span class="country-name">${country}</span>
                <span class="country-count">${count}</span>
            </div>
        `).join('');

    const desktop = document.getElementById('countryList');
    const mobile = document.getElementById('mobileCountryList');
    if (desktop) desktop.innerHTML = html;
    if (mobile) mobile.innerHTML = html;
}

function addToFeed(point) {
    let typeLabel, detail;
    switch (point.type) {
        case 'infra':
            typeLabel = point.data.type || 'C2 Server';
            detail = point.data.malware || point.data.source;
            break;
        case 'attacker':
            typeLabel = 'Active Attacker';
            detail = `${formatNumber(point.data.reports)} reports`;
            break;
        case 'phishing':
            typeLabel = 'Malicious URL';
            detail = point.data.url || point.data.source;
            break;
        case 'ssl':
            typeLabel = 'Suspicious IP';
            detail = point.data.reason || point.data.source;
            break;
        default:
            typeLabel = 'Threat';
            detail = point.data.source;
    }

    const itemHTML = `
        <div class="feed-type">${typeLabel}</div>
        <div class="feed-location">${point.data.city}, ${point.data.country}</div>
        <div class="feed-detail">${point.data.ip} - ${detail}</div>
        <div class="feed-time">${new Date().toLocaleTimeString()}</div>
    `;

    const feedLists = [
        document.getElementById('feedList'),
        document.getElementById('mobileFeedList')
    ];

    feedLists.forEach(feedList => {
        if (!feedList) return;

        const empty = feedList.querySelector('.feed-empty');
        if (empty) empty.remove();

        const item = document.createElement('div');
        item.className = `feed-item ${point.type}`;
        item.innerHTML = itemHTML;

        // Click to fly to location
        item.addEventListener('click', () => {
            flyToLocation(point.lat, point.lng);

            // Find and open the marker popup
            const markerData = markers.find(m =>
                m.lat === point.lat && m.lon === point.lng
            );
            if (markerData) {
                markerData.marker.togglePopup();
            }

            // Close mobile sheet if open
            const mobileSheet = document.getElementById('mobileSheet');
            if (mobileSheet && mobileSheet.classList.contains('open')) {
                mobileSheet.classList.remove('open');
                document.getElementById('sheetOverlay').classList.remove('active');
                document.getElementById('mobileToggle').classList.remove('open');
            }
        });

        feedList.insertBefore(item, feedList.firstChild);
        while (feedList.children.length > 50) feedList.removeChild(feedList.lastChild);
    });

    updateMobileBadge();
}

function updateMobileBadge() {
    const badge = document.getElementById('mobileBadge');
    if (badge) {
        const total = totalInfra + totalAttackers + totalPhishing + totalSSL;
        badge.textContent = total > 99 ? '99+' : total;
    }
}

function setStatus(message, connected) {
    const statusDot = document.getElementById('statusDot');
    const statusText = document.getElementById('statusText');
    if (statusDot) statusDot.className = 'status-dot' + (connected ? ' connected' : '');
    if (statusText) statusText.textContent = message;
    if (connected) {
        const updateTime = document.getElementById('updateTime');
        if (updateTime) updateTime.textContent = `Updated ${new Date().toLocaleTimeString()}`;
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
            await processThreats(threats.slice(0, 35), 'infra');
        }

        const attackers = await fetchActiveAttackers();
        if (attackers.length > 0) {
            await processThreats(attackers.slice(0, 35), 'attacker');
        }

        const urls = await fetchMaliciousURLs();
        if (urls.length > 0) {
            await processThreats(urls.slice(0, 25), 'phishing');
        }

        const suspicious = await fetchSuspiciousIPs();
        if (suspicious.length > 0) {
            await processThreats(suspicious.slice(0, 25), 'ssl');
        }

        const total = totalInfra + totalAttackers + totalPhishing + totalSSL;
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
        this.classList.toggle('active', isRotating);
        if (isRotating) {
            startRotation();
        } else {
            stopRotation();
        }
    });

    document.getElementById('resetView').addEventListener('click', () => {
        if (map) {
            map.flyTo({
                center: [0, 20],
                zoom: 1.5,
                pitch: 0,
                bearing: 0,
                duration: 1500
            });
        }
    });

    // About modal handlers
    const aboutBtn = document.getElementById('aboutBtn');
    const aboutModal = document.getElementById('aboutModal');
    const closeModal = document.getElementById('closeModal');

    if (aboutBtn && aboutModal) {
        aboutBtn.addEventListener('click', () => {
            aboutModal.classList.add('active');
        });

        closeModal.addEventListener('click', () => {
            aboutModal.classList.remove('active');
        });

        // Close on overlay click
        aboutModal.addEventListener('click', (e) => {
            if (e.target === aboutModal) {
                aboutModal.classList.remove('active');
            }
        });

        // Close on Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && aboutModal.classList.contains('active')) {
                aboutModal.classList.remove('active');
            }
        });
    }

    setupMobileSheet();
    setupInteractionHandlers();
}

function setupMobileSheet() {
    const toggle = document.getElementById('mobileToggle');
    const sheet = document.getElementById('mobileSheet');
    const overlay = document.getElementById('sheetOverlay');
    const handle = document.getElementById('sheetHandle');

    if (!toggle || !sheet) return;

    function openSheet() {
        sheet.classList.add('open');
        overlay.classList.add('active');
        toggle.classList.add('open');
    }

    function closeSheet() {
        sheet.classList.remove('open');
        overlay.classList.remove('active');
        toggle.classList.remove('open');
    }

    function toggleSheet() {
        sheet.classList.contains('open') ? closeSheet() : openSheet();
    }

    toggle.addEventListener('click', toggleSheet);
    overlay.addEventListener('click', closeSheet);
    handle.addEventListener('click', closeSheet);

    let startY = 0, currentY = 0;

    handle.addEventListener('touchstart', (e) => {
        startY = e.touches[0].clientY;
    }, { passive: true });

    handle.addEventListener('touchmove', (e) => {
        currentY = e.touches[0].clientY;
        const diff = currentY - startY;
        if (diff > 0) sheet.style.transform = `translateY(${diff}px)`;
    }, { passive: true });

    handle.addEventListener('touchend', () => {
        const diff = currentY - startY;
        sheet.style.transform = '';
        if (diff > 80) closeSheet();
        startY = currentY = 0;
    });
}

function sleep(ms) {
    return new Promise(r => setTimeout(r, ms));
}

async function init() {
    console.log('Initializing Mapbox globe...');

    const success = initGlobe();
    if (!success) return;

    setupControls();
    document.getElementById('toggleRotation').classList.add('active');

    // Wait for map to load
    map.on('load', async () => {
        console.log('Map loaded, starting data fetch...');
        await fetchAllData();
    });

    // Live updates every 2 minutes
    setInterval(async () => {
        if (!map) return;

        console.log('=== Refreshing data ===');

        clearMarkers();
        threatPoints.length = 0;
        attackerPoints.length = 0;
        phishingPoints.length = 0;
        sslPoints.length = 0;
        totalInfra = 0;
        totalAttackers = 0;
        totalPhishing = 0;
        totalSSL = 0;
        totalReports = 0;
        countryStats.clear();

        const feedList = document.getElementById('feedList');
        const mobileFeedList = document.getElementById('mobileFeedList');
        if (feedList) feedList.innerHTML = '<div class="feed-empty">Refreshing...</div>';
        if (mobileFeedList) mobileFeedList.innerHTML = '<div class="feed-empty">Refreshing...</div>';
        updateMobileBadge();

        await fetchAllData();
    }, API.UPDATE_INTERVAL);
}

document.addEventListener('DOMContentLoaded', init);
