import { connect } from "cloudflare:sockets";

// ==================== VARIABLES & CONSTANTS ====================
let serviceName = "";
let APP_DOMAIN = "";
let prxIP = "";

const horse = "dHJvamFu";
const flash = "dm1lc3M=";
const v2 = "djJyYXk=";
const neko = "Y2xhc2g=";

const PORTS = [443, 80];
const PROTOCOLS = [atob(horse), atob(flash), "ss"];
const KV_PRX_URL = "https://raw.githubusercontent.com/backup-heavenly-demons/gateway/refs/heads/main/kvProxyList.json";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = {
  host: "udp-relay.hobihaus.space",
  port: 7300,
};
const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// ==================== OPTIMIZATION SETTINGS ====================
const PROXY_CACHE_TTL = 300; // 5 menit
const DNS_CACHE_TTL = 300000; // 5 menit dalam ms
const PROXY_TIMEOUT = 5000; // 5 detik timeout koneksi
const HEALTH_CHECK_INTERVAL = 60000; // 1 menit
const MAX_POOL_SIZE = 5;

// ==================== CACHE & HEALTH STORAGE ====================
const dnsCache = new Map();
const proxyHealth = new Map();
const connectionPool = new Map();

// ==================== REGION MAP ====================
const REGION_MAP = {
  ASIA: ["ID", "SG", "MY", "PH", "TH", "VN", "JP", "KR", "CN", "HK", "TW"],
  SOUTHASIA: ["IN", "BD", "PK", "LK", "NP", "AF", "BT", "MV"],
  CENTRALASIA: ["KZ", "UZ", "TM", "KG", "TJ"],
  NORTHASIA: ["RU"],
  MIDDLEEAST: ["AE", "SA", "IR", "IQ", "JO", "IL", "YE", "SY", "OM", "KW", "QA", "BH", "LB"],
  CIS: ["RU", "UA", "BY", "KZ", "UZ", "AM", "GE", "MD", "TJ", "KG", "TM", "AZ"],
  WESTEUROPE: ["FR", "DE", "NL", "BE", "AT", "CH", "IE", "LU", "MC"],
  EASTEUROPE: ["PL", "CZ", "SK", "HU", "RO", "BG", "MD", "UA", "BY"],
  NORTHEUROPE: ["SE", "FI", "NO", "DK", "EE", "LV", "LT", "IS"],
  SOUTHEUROPE: ["IT", "ES", "PT", "GR", "HR", "SI", "MT", "AL", "BA", "RS", "ME", "MK"],
  EUROPE: ["FR", "DE", "NL", "BE", "AT", "CH", "IE", "LU", "MC", "PL", "CZ", "SK", "HU", "RO", "BG", "MD", "UA", "BY", "SE", "FI", "NO", "DK", "EE", "LV", "LT", "IS", "IT", "ES", "PT", "GR", "HR", "SI", "MT", "AL", "BA", "RS", "ME", "MK"],
  AFRICA: ["ZA", "NG", "EG", "MA", "KE", "DZ", "TN", "GH", "CI", "SN", "ET"],
  NORTHAMERICA: ["US", "CA", "MX"],
  SOUTHAMERICA: ["BR", "AR", "CL", "CO", "PE", "VE", "EC", "UY", "PY", "BO"],
  LATAM: ["MX", "BR", "AR", "CL", "CO", "PE", "VE", "EC", "UY", "PY", "BO", "CR", "GT", "PA", "DO", "HN", "NI", "SV"],
  AMERICA: ["US", "CA", "MX", "BR", "AR", "CL", "CO", "PE", "VE", "EC"],
  OCEANIA: ["AU", "NZ", "PG", "FJ"],
  GLOBAL: []
};

// ==================== OPTIMIZED CACHE FUNCTIONS ====================
async function getCachedData(cacheKey, fetchFunction, ttl = PROXY_CACHE_TTL) {
  try {
    const cache = caches.default;
    let response = await cache.match(cacheKey);
    
    if (!response) {
      const data = await fetchFunction();
      response = new Response(JSON.stringify(data), {
        headers: { 
          'Cache-Control': `public, max-age=${ttl}`,
          'Content-Type': 'application/json'
        }
      });
      
      // Non-blocking cache write
      globalThis.ctx?.waitUntil?.(cache.put(cacheKey, response.clone()));
    }
    
    return await response.json();
  } catch (error) {
    console.error(`Cache error for ${cacheKey}:`, error);
    return await fetchFunction();
  }
}

async function fetchWithTimeout(url, timeout = 5000, retries = 2) {
  for (let i = 0; i <= retries; i++) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);
    
    try {
      const response = await fetch(url, { 
        signal: controller.signal,
        headers: {
          'Accept': 'application/json',
          'User-Agent': 'Cloudflare-Worker/1.0'
        }
      });
      clearTimeout(timeoutId);
      
      if (response.ok) return response;
      
      if (i < retries) {
        console.warn(`Fetch failed (attempt ${i + 1}/${retries + 1}), retrying...`);
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    } catch (error) {
      clearTimeout(timeoutId);
      if (i === retries) throw error;
      console.warn(`Fetch error (attempt ${i + 1}/${retries + 1}):`, error.message);
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  throw new Error(`Failed to fetch ${url} after ${retries + 1} attempts`);
}

async function getKVPrxList(kvPrxUrl = KV_PRX_URL) {
  if (!kvPrxUrl) throw new Error("No URL Provided!");

  return getCachedData(
    `kv-prx-list:${kvPrxUrl}`,
    async () => {
      const response = await fetchWithTimeout(kvPrxUrl, 5000, 2);
      return await response.json();
    },
    PROXY_CACHE_TTL
  );
}

async function getPrxList(prxBankUrl) {
  if (!prxBankUrl) return [];

  return getCachedData(
    `prx-list:${prxBankUrl}`,
    async () => {
      const response = await fetchWithTimeout(prxBankUrl, 5000, 2);
      const data = await response.json();
      
      return data.map(proxy => {
        const ip = proxy.prxIP || proxy.ip || proxy.server;
        const port = proxy.prxPort || proxy.port;
        const country = proxy.country || proxy.cc || 'XX';
        
        if (!ip || !port) {
          console.warn('Invalid proxy format:', proxy);
          return null;
        }
        
        return {
          prxIP: ip,
          prxPort: port,
          country: country.toUpperCase()
        };
      }).filter(Boolean);
    },
    PROXY_CACHE_TTL
  );
}

// ==================== HEALTH CHECK SYSTEM ====================
async function checkProxyHealth(proxyAddress) {
  const [host, port] = proxyAddress.split(':');
  const startTime = Date.now();
  
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), PROXY_TIMEOUT);
    
    const socket = connect({
      hostname: host,
      port: parseInt(port),
    });
    
    const writer = socket.writable.getWriter();
    await writer.write(new Uint8Array([]));
    writer.releaseLock();
    
    clearTimeout(timeoutId);
    const latency = Date.now() - startTime;
    
    const currentHealth = proxyHealth.get(proxyAddress) || { successRate: 0 };
    
    proxyHealth.set(proxyAddress, {
      latency,
      lastCheck: Date.now(),
      alive: true,
      successRate: (currentHealth.successRate + 1) / 2
    });
    
    try { socket.close(); } catch(e) {}
    return { alive: true, latency };
  } catch (error) {
    proxyHealth.set(proxyAddress, {
      latency: 9999,
      lastCheck: Date.now(),
      alive: false,
      successRate: 0
    });
    return { alive: false, latency: 9999 };
  }
}

async function getFastestProxies(candidates, count = 3) {
  const healthChecks = await Promise.allSettled(
    candidates.map(async (proxy) => {
      const address = `${proxy.prxIP}:${proxy.prxPort}`;
      const health = proxyHealth.get(address);
      
      if (health && !health.alive) return null;
      
      if (health && (Date.now() - health.lastCheck) < HEALTH_CHECK_INTERVAL) {
        return { proxy, address, latency: health.latency };
      }
      
      const result = await checkProxyHealth(address);
      return result.alive ? { proxy, address, latency: result.latency } : null;
    })
  );
  
  const aliveProxies = healthChecks
    .filter(r => r.status === 'fulfilled' && r.value !== null)
    .map(r => r.value)
    .sort((a, b) => a.latency - b.latency);
  
  return aliveProxies.slice(0, Math.max(count, 1));
}

async function backgroundHealthCheck(proxies) {
  const shuffled = [...proxies].sort(() => Math.random() - 0.5);
  const toCheck = shuffled.slice(0, 5);
  
  await Promise.allSettled(
    toCheck.map(proxy => 
      checkProxyHealth(`${proxy.prxIP}:${proxy.prxPort}`)
    )
  );
}

// ==================== PROXY SELECTION LOGIC ====================
function matchProxyPattern(path) {
  const proxyListMatch = path.match(/^\/PROXYLIST\/([A-Z]{2}(,[A-Z]{2})*)$/i);
  if (proxyListMatch) {
    return { type: 'PROXYLIST', countries: proxyListMatch[1].toUpperCase().split(",") };
  }
  
  const allMatch = path.match(/^\/ALL(\d+)?$/i);
  if (allMatch) {
    return { type: 'ALL', index: allMatch[1] ? parseInt(allMatch[1], 10) - 1 : null };
  }
  
  const putarMatch = path.match(/^\/PUTAR(\d+)?$/i);
  if (putarMatch) {
    return { type: 'PUTAR', count: putarMatch[1] ? parseInt(putarMatch[1], 10) : null };
  }
  
  const regionMatch = path.match(/^\/([A-Z]+)(\d+)?$/i);
  if (regionMatch && REGION_MAP[regionMatch[1].toUpperCase()] !== undefined) {
    return {
      type: 'REGION',
      region: regionMatch[1].toUpperCase(),
      index: regionMatch[2] ? parseInt(regionMatch[2], 10) - 1 : null
    };
  }
  
  const countryMatch = path.match(/^\/([A-Z]{2})(\d+)?$/);
  if (countryMatch && !REGION_MAP[countryMatch[1].toUpperCase()]) {
    return {
      type: 'COUNTRY',
      country: countryMatch[1].toUpperCase(),
      index: countryMatch[2] ? parseInt(countryMatch[2], 10) - 1 : null
    };
  }
  
  const ipPortMatch = path.match(/^\/(.+[:=-]\d+)$/);
  if (ipPortMatch) {
    return { type: 'DIRECT', ip: ipPortMatch[1].replace(/[=:-]/, ":") };
  }
  
  if (path.length === 3 || path.includes(',')) {
    return { type: 'LEGACY', keys: path.replace("/", "").toUpperCase().split(",") };
  }
  
  return null;
}

function groupBy(array, key) {
  return array.reduce((acc, item) => {
    const groupKey = item[key];
    if (!acc[groupKey]) acc[groupKey] = [];
    acc[groupKey].push(item);
    return acc;
  }, {});
}

function getRandomItem(arr) {
  return arr[Math.floor(Math.random() * arr.length)];
}

function selectProxyFromPattern(pattern, proxies, kvPrx) {
  switch (pattern.type) {
    case 'PROXYLIST': {
      if (proxies.length > 0) {
        const filtered = proxies.filter(p => pattern.countries.includes(p.country));
        if (filtered.length > 0) {
          const selected = getRandomItem(filtered);
          return `${selected.prxIP}:${selected.prxPort}`;
        }
      }
      
      const availableCountries = pattern.countries.filter(code => kvPrx[code] && kvPrx[code].length > 0);
      if (availableCountries.length > 0) {
        const prxKey = getRandomItem(availableCountries);
        return getRandomItem(kvPrx[prxKey]);
      }
      return null;
    }
    
    case 'ALL': {
      if (proxies.length > 0) {
        if (pattern.index !== null) {
          const grouped = groupBy(proxies, 'country');
          const selected = [];
          for (const country in grouped) {
            if (pattern.index < grouped[country].length) {
              selected.push(grouped[country][pattern.index]);
            }
          }
          if (selected.length > 0) {
            const proxy = getRandomItem(selected);
            return `${proxy.prxIP}:${proxy.prxPort}`;
          }
        } else {
          const proxy = getRandomItem(proxies);
          return `${proxy.prxIP}:${proxy.prxPort}`;
        }
      }
      
      const allProxies = Object.values(kvPrx).flat();
      if (allProxies.length > 0) return getRandomItem(allProxies);
      return null;
    }
    
    case 'PUTAR': {
      if (proxies.length > 0) {
        const grouped = groupBy(proxies, 'country');
        const countries = Object.keys(grouped);
        
        let selectedCountries;
        if (pattern.count === null) {
          selectedCountries = countries;
        } else {
          const shuffled = [...countries].sort(() => Math.random() - 0.5);
          selectedCountries = shuffled.slice(0, Math.min(pattern.count, countries.length));
        }
        
        const selectedProxies = selectedCountries.map(c => getRandomItem(grouped[c]));
        const proxy = getRandomItem(selectedProxies);
        return `${proxy.prxIP}:${proxy.prxPort}`;
      }
      
      const kvCountries = Object.keys(kvPrx).filter(code => kvPrx[code] && kvPrx[code].length > 0);
      if (kvCountries.length > 0) {
        let selected;
        if (pattern.count === null) {
          selected = kvCountries;
        } else {
          const shuffled = [...kvCountries].sort(() => Math.random() - 0.5);
          selected = shuffled.slice(0, Math.min(pattern.count, kvCountries.length));
        }
        const prxKey = getRandomItem(selected);
        return getRandomItem(kvPrx[prxKey]);
      }
      return null;
    }
    
    case 'REGION': {
      const countries = REGION_MAP[pattern.region];
      
      if (proxies.length > 0) {
        const filtered = pattern.region === "GLOBAL" 
          ? proxies 
          : proxies.filter(p => countries.includes(p.country));
        
        if (filtered.length > 0) {
          let proxy;
          if (pattern.index !== null && pattern.index < filtered.length) {
            proxy = filtered[pattern.index];
          } else {
            proxy = getRandomItem(filtered);
          }
          return `${proxy.prxIP}:${proxy.prxPort}`;
        }
      }
      
      let availableProxies = [];
      if (pattern.region === "GLOBAL") {
        availableProxies = Object.values(kvPrx).flat();
      } else {
        for (const country of countries) {
          if (kvPrx[country]) {
            availableProxies.push(...kvPrx[country]);
          }
        }
      }
      
      if (availableProxies.length > 0) {
        if (pattern.index !== null && pattern.index < availableProxies.length) {
          return availableProxies[pattern.index];
        }
        return getRandomItem(availableProxies);
      }
      return null;
    }
    
    case 'COUNTRY': {
      if (proxies.length > 0) {
        const filtered = proxies.filter(p => p.country === pattern.country);
        if (filtered.length > 0) {
          let proxy;
          if (pattern.index !== null && pattern.index < filtered.length) {
            proxy = filtered[pattern.index];
          } else {
            proxy = getRandomItem(filtered);
          }
          return `${proxy.prxIP}:${proxy.prxPort}`;
        }
      }
      
      if (kvPrx[pattern.country] && kvPrx[pattern.country].length > 0) {
        if (pattern.index !== null && pattern.index < kvPrx[pattern.country].length) {
          return kvPrx[pattern.country][pattern.index];
        }
        return getRandomItem(kvPrx[pattern.country]);
      }
      return null;
    }
    
    case 'DIRECT': {
      return pattern.ip;
    }
    
    case 'LEGACY': {
      const prxKey = getRandomItem(pattern.keys);
      if (kvPrx[prxKey] && kvPrx[prxKey].length > 0) {
        return getRandomItem(kvPrx[prxKey]);
      }
      return null;
    }
    
    default:
      return null;
  }
}

// ==================== REVERSE PROXY ====================
async function reverseWeb(request, target, targetPath) {
  const targetUrl = new URL(request.url);
  const targetChunk = target.split(":");

  targetUrl.hostname = targetChunk[0];
  targetUrl.port = targetChunk[1]?.toString() || "443";
  targetUrl.pathname = targetPath || targetUrl.pathname;

  const modifiedRequest = new Request(targetUrl, request);
  modifiedRequest.headers.set("X-Forwarded-Host", request.headers.get("Host"));

  const response = await fetch(modifiedRequest);

  const newResponse = new Response(response.body, response);
  for (const [key, value] of Object.entries(CORS_HEADER_OPTIONS)) {
    newResponse.headers.set(key, value);
  }
  newResponse.headers.set("X-Proxied-By", "Cloudflare Worker");

  return newResponse;
}

// ==================== ASSET EMBEDDING ====================
function bufferToBase64(buffer) {
    let binary = '';
    const bytes = new Uint8Array(buffer);
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

async function embedAssets(response, originalUrl) {
  const rewriter = new HTMLRewriter();

  const fetchAndEncode = async (assetUrl) => {
    try {
      const absoluteUrl = new URL(assetUrl, originalUrl.href).href;
      const assetResponse = await fetch(absoluteUrl);
      if (!assetResponse.ok) return null;

      const contentType = assetResponse.headers.get('content-type') || 'application/octet-stream';
      const buffer = await assetResponse.arrayBuffer();
      const base64 = bufferToBase64(buffer);
      return `data:${contentType};base64,${base64}`;
    } catch (e) {
      console.error(`Failed to fetch and embed asset: ${assetUrl}`, e);
      return null;
    }
  };

  rewriter.on('link[rel="stylesheet"]', {
    async element(element) {
      const href = element.getAttribute('href');
      if (href) {
        const absoluteUrl = new URL(href, originalUrl.href).href;
        const cssResponse = await fetch(absoluteUrl);
        if (cssResponse.ok) {
            const cssText = await cssResponse.text();
            element.replace(`<style>${cssText}</style>`, { html: true });
        }
      }
    },
  });

  rewriter.on('img', {
    async element(element) {
      const src = element.getAttribute('src');
      if (src && !src.startsWith('data:')) {
        const dataUri = await fetchAndEncode(src);
        if (dataUri) {
          element.setAttribute('src', dataUri);
        }
      }
    },
  });

  rewriter.on('script[src]', {
      async element(element) {
          const src = element.getAttribute('src');
          if (src) {
              const absoluteUrl = new URL(src, originalUrl.href).href;
              const scriptResponse = await fetch(absoluteUrl);
              if (scriptResponse.ok) {
                  const scriptText = await scriptResponse.text();
                  element.removeAttribute('src');
                  element.append(scriptText, { html: false });
              }
          }
      }
  });

  return rewriter.transform(response);
}

// ==================== PRELOAD PROXY LIST ====================
async function preloadProxyList(env) {
  const promises = [];
  
  promises.push(
    getKVPrxList().catch(err => {
      console.error('Failed to load KV proxy list:', err);
      return {};
    })
  );
  
  if (env.PRX_BANK_URL) {
    promises.push(
      getPrxList(env.PRX_BANK_URL).catch(err => {
        console.error('Failed to load bank proxy list:', err);
        return [];
      })
    );
  }
  
  const results = await Promise.allSettled(promises);
  
  const kvPrx = results[0].status === 'fulfilled' ? results[0].value : {};
  const proxies = results[1]?.status === 'fulfilled' ? results[1].value : [];
  
  // Background health check
  if (proxies.length > 0) {
    globalThis.ctx?.waitUntil?.(backgroundHealthCheck(proxies));
  }
  
  return { kvPrx, proxies };
}

// ==================== MAIN FETCH HANDLER ====================
export default {
  async fetch(request, env, ctx) {
    // Store ctx globally untuk cache API
    globalThis.ctx = ctx;
    
    try {
      const url = new URL(request.url);
      APP_DOMAIN = url.hostname;
      serviceName = APP_DOMAIN.split(".")[0];

      const upgradeHeader = request.headers.get("Upgrade");

      if (upgradeHeader === "websocket") {
        const path = url.pathname;
        console.log(`[WS] Path: ${path}`);

        // Kunci path: harus diawali /Benxx-Project/
        if (!path.startsWith("/Benxx-Project/")) {
          return new Response("Not Found", { status: 404 });
        }

        // Hapus prefix /Benxx-Project biar pattern matching jalan normal
        const cleanPath = path.replace(/^\/Benxx-Project/, "") || "/";
        const pattern = matchProxyPattern(cleanPath);
        
        if (pattern) {
          // Langsung accept WebSocket tanpa nunggu proxy siap
          const webSocketPair = new WebSocketPair();
          const [client, webSocket] = Object.values(webSocketPair);
          webSocket.accept();
          
          // Setup di background
          ctx.waitUntil(
            (async () => {
              try {
                const startTime = Date.now();
                const { proxies, kvPrx } = await preloadProxyList(env);
                console.log(`[PERF] Proxy list loaded in ${Date.now() - startTime}ms`);
                
                const selectedPrxIP = selectProxyFromPattern(pattern, proxies, kvPrx);
                
                if (!selectedPrxIP) {
                  console.error(`No proxy available for pattern: ${pattern.type}`);
                  safeCloseWebSocket(webSocket);
                  return;
                }
                
                prxIP = selectedPrxIP;
                console.log(`[SELECTED] ${prxIP}`);
                
                await setupWebSocketStream(webSocket, request, env);
              } catch (error) {
                console.error('WebSocket setup error:', error);
                safeCloseWebSocket(webSocket);
              }
            })()
          );
          
          // Return WebSocket response SEGERA
          return new Response(null, {
            status: 101,
            webSocket: client,
          });
        }
        
        return new Response('Invalid WebSocket path', { status: 400 });
      }

      // Handle non-WebSocket
      const targetReversePrx = env.REVERSE_PRX_TARGET || "cinema.xinquins.de5.net";
      const response = await reverseWeb(request, targetReversePrx);

      const contentType = response.headers.get('content-type') || '';

      if (env.EMBED_ASSETS === 'true' && contentType.includes('text/html')) {
        return embedAssets(response, new URL(request.url));
      }

      return response;
    } catch (err) {
      console.error('Global error:', err);
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: CORS_HEADER_OPTIONS,
      });
    }
  },
};

// ==================== WEBSOCKET STREAM SETUP ====================
async function setupWebSocketStream(webSocket, request, env) {
  let addressLog = "";
  let portLog = "";
  
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = { value: null };
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS) {
            return handleUDPOutbound(
              DNS_SERVER_ADDRESS,
              DNS_SERVER_PORT,
              chunk,
              webSocket,
              null,
              log,
              RELAY_SERVER_UDP
            );
          }
          
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === atob(horse)) {
            protocolHeader = readHorseHeader(chunk);
          } else if (protocol === atob(flash)) {
            protocolHeader = readFlashHeader(chunk);
          } else if (protocol === "ss") {
            protocolHeader = readSsHeader(chunk);
          } else {
            throw new Error("Unknown Protocol!");
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
              return handleUDPOutbound(
                DNS_SERVER_ADDRESS,
                DNS_SERVER_PORT,
                chunk,
                webSocket,
                protocolHeader.version,
                log,
                RELAY_SERVER_UDP
              );
            }

            return handleUDPOutbound(
              protocolHeader.addressRemote,
              protocolHeader.portRemote,
              chunk,
              webSocket,
              protocolHeader.version,
              log,
              RELAY_SERVER_UDP
            );
          }

          handleTCPOutBound(
            remoteSocketWrapper,
            protocolHeader.addressRemote,
            protocolHeader.portRemote,
            protocolHeader.rawClientData,
            webSocket,
            protocolHeader.version,
            log
          );
        },
        close() {
          log(`readableWebSocketStream is close`);
        },
        abort(reason) {
          log(`readableWebSocketStream is abort`, JSON.stringify(reason));
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });
}

// ==================== PROTOCOL SNIFFER ====================
async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
      if (horseDelimiter[2] === 0x01 || horseDelimiter[2] === 0x03 || horseDelimiter[2] === 0x7f) {
        if (horseDelimiter[3] === 0x01 || horseDelimiter[3] === 0x03 || horseDelimiter[3] === 0x04) {
          return atob(horse);
        }
      }
    }
  }

  const flashDelimiter = new Uint8Array(buffer.slice(1, 17));
  if (arrayBufferToHex(flashDelimiter).match(/^[0-9a-f]{8}[0-9a-f]{4}4[0-9a-f]{3}[89ab][0-9a-f]{3}[0-9a-f]{12}$/i)) {
    return atob(flash);
  }

  return "ss";
}

// ==================== TCP OUTBOUND (OPTIMIZED) ====================
async function handleTCPOutBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  responseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    
    remoteSocket.value = tcpSocket;
    
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    
    const startTime = Date.now();
    log(`Connected to ${address}:${port}`);
    
    // Update health
    const key = `${address}:${port}`;
    proxyHealth.set(key, {
      latency: Date.now() - startTime,
      lastCheck: Date.now(),
      alive: true
    });

    return tcpSocket;
  }

  async function retry() {
    log('Retrying with proxy...');
    
    if (prxIP) {
      const [proxyHost, proxyPort] = prxIP.split(':');
      
      try {
        const tcpSocket = await connectAndWrite(
          proxyHost || addressRemote,
          parseInt(proxyPort) || portRemote
        );
        
        tcpSocket.closed
          .catch((error) => {
            log("Retry tcpSocket closed error", error);
          })
          .finally(() => {
            safeCloseWebSocket(webSocket);
          });
        
        remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
        return;
      } catch (error) {
        log(`Proxy connection failed: ${error.message}`);
      }
    }
    
    // Fallback: coba langsung lagi
    log('Trying direct connection again...');
    try {
      const tcpSocket = await connectAndWrite(addressRemote, portRemote);
      remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
    } catch (error) {
      log(`All connections failed: ${error.message}`);
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
  } catch (error) {
    log(`Direct connection failed: ${error.message}`);
    await retry();
  }
}

// ==================== UDP OUTBOUND ====================
async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, log, relay) {
  try {
    let protocolHeader = responseHeader;

    const tcpSocket = connect({
      hostname: relay.host,
      port: relay.port,
    });

    const header = `udp:${targetAddress}:${targetPort}`;
    const headerBuffer = new TextEncoder().encode(header);
    const separator = new Uint8Array([0x7c]);
    const relayMessage = new Uint8Array(headerBuffer.length + separator.length + dataChunk.byteLength);
    relayMessage.set(headerBuffer, 0);
    relayMessage.set(separator, headerBuffer.length);
    relayMessage.set(new Uint8Array(dataChunk), headerBuffer.length + separator.length);

    const writer = tcpSocket.writable.getWriter();
    await writer.write(relayMessage);
    writer.releaseLock();

    await tcpSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            if (protocolHeader) {
              webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
              protocolHeader = null;
            } else {
              webSocket.send(chunk);
            }
          }
        },
        close() {
          log(`UDP connection to ${targetAddress} closed`);
        },
        abort(reason) {
          console.error(`UDP connection aborted due to ${reason}`);
        },
      })
    );
  } catch (e) {
    console.error(`Error while handling UDP outbound: ${e.message}`);
  }
}

// ==================== STREAM HELPERS ====================
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) return;
        const message = event.data;
        controller.enqueue(message);
      });
      
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) return;
        controller.close();
      });
      
      webSocketServer.addEventListener("error", (err) => {
        log("webSocketServer has error");
        controller.error(err);
      });
      
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) return;
      log(`ReadableStream was canceled, due to ${reason}`);
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

// ==================== PROTOCOL READERS ====================
function readSsHeader(ssBuffer) {
  const view = new DataView(ssBuffer);

  const addressType = view.getUint8(0);
  let addressLength = 0;
  let addressValueIndex = 1;
  let addressValue = "";

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `Invalid addressType for SS: ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `Destination address empty, address type is: ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = ssBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 2,
    rawClientData: ssBuffer.slice(portIndex + 2),
    version: null,
    isUDP: portRemote == 53,
  };
}

function readFlashHeader(buffer) {
  const version = new Uint8Array(buffer.slice(0, 1));
  let isUDP = false;

  const optLength = new Uint8Array(buffer.slice(17, 18))[0];

  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  if (cmd === 1) {
  } else if (cmd === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${cmd} is not supported`,
    };
  }
  
  const portIndex = 18 + optLength + 1;
  const portBuffer = buffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1));

  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }
  
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    rawClientData: buffer.slice(addressValueIndex + addressLength),
    version: new Uint8Array([version[0], 0]),
    isUDP: isUDP,
  };
}

function readHorseHeader(buffer) {
  const dataBuffer = buffer.slice(58);
  if (dataBuffer.byteLength < 6) {
    return {
      hasError: true,
      message: "invalid request data",
    };
  }

  let isUDP = false;
  const view = new DataView(dataBuffer);
  const cmd = view.getUint8(0);
  
  if (cmd == 3) {
    isUDP = true;
  } else if (cmd != 1) {
    throw new Error("Unsupported command type!");
  }

  let addressType = view.getUint8(1);
  let addressLength = 0;
  let addressValueIndex = 2;
  let addressValue = "";
  
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invalid addressType is ${addressType}`,
      };
  }

  if (!addressValue) {
    return {
      hasError: true,
      message: `address is empty, addressType is ${addressType}`,
    };
  }

  const portIndex = addressValueIndex + addressLength;
  const portBuffer = dataBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);
  
  return {
    hasError: false,
    addressRemote: addressValue,
    addressType: addressType,
    portRemote: portRemote,
    rawDataIndex: portIndex + 4,
    rawClientData: dataBuffer.slice(portIndex + 4),
    version: null,
    isUDP: isUDP,
  };
}

// ==================== SOCKET HELPERS ====================
async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {
          log(`remoteConnection readable is close, hasIncomingData: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`remoteConnection readable abort`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`remoteSocketToWS has exception`, error.stack || error);
      safeCloseWebSocket(webSocket);
    });
    
  if (hasIncomingData === false && retry) {
    log(`No incoming data, retrying...`);
    retry();
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {
    console.error("safeCloseWebSocket error", error);
  }
}

// ==================== HELPERS ====================
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}
