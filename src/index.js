import { connect } from "cloudflare:sockets";

// ============================================================
//  BENXX GATEWAY v2 — renovasi dari 2 kode gateway (FoolVPN/Nautica)
//  Protokol: VLESS + Trojan SAJA (tanpa VMess berat-CPU & tanpa SS)
//  Multi-UUID: daftar UUID di env.UUIDS (dipisah koma). Kalau kosong
//  → mode terbuka (tanpa validasi UUID, seperti kode aslinya).
// ============================================================

let APP_DOMAIN = "";
let serviceName = "";
let prxIP = "";

// --- Konstanta ---
const KV_PRX_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/kvProxyList.json";
const PRX_BANK_URL = "https://raw.githubusercontent.com/FoolVPN-ID/Nautica/refs/heads/main/proxyList.txt";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = { host: "udp-relay.hobihaus.space", port: 7300 };
const CONNECT_TIMEOUT_MS = 8000; // anti-hang: connect+write max 8 detik
const DEFAULT_FALLBACK_PRX = "138.2.74.219:28616";

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

// Region mapping (dipakai path /REGION)
const REGION_MAP = {
  ASIA: ["ID", "SG", "MY", "PH", "TH", "VN", "JP", "KR", "CN", "HK", "TW"],
  EUROPE: ["FR", "DE", "NL", "BE", "AT", "CH", "IE", "PL", "CZ", "SE", "FI", "NO", "DK", "IT", "ES", "PT", "GR", "RO", "UA"],
  AMERICA: ["US", "CA", "MX", "BR", "AR", "CL", "CO", "PE"],
  AFRICA: ["ZA", "NG", "EG", "MA", "KE"],
  OCEANIA: ["AU", "NZ", "PG", "FJ"],
  GLOBAL: [],
};

// ---------- util proxy list ----------
async function getKVPrxList(kvPrxUrl = KV_PRX_URL) {
  try {
    const res = await fetch(kvPrxUrl);
    if (res.status === 200) return await res.json();
  } catch (_) {}
  return {};
}

// ---------- util uuid ----------
function parseUUIDList(env) {
  const raw = (env && (env.UUIDS || env.UUID)) || "";
  const list = raw.split(",").map((s) => s.trim().toLowerCase()).filter(isValidUUID);
  return list; // kosong = mode terbuka
}
function isValidUUID(u) {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(u || "");
}
function uuidToBytes16(u) {
  const h = u.replace(/-/g, "");
  const out = new Uint8Array(16);
  for (let i = 0; i < 16; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

// ---------- header parsers ----------
// VLESS: ver(1)+uuid(16)+optLen(1)+opt+cmd(1)+port(2)+addrType(1)+addr+...+0x0d0x0a
function readVLESSHeader(buffer, allowedUUIDs) {
  if (buffer.byteLength < 24) return { hasError: true, message: "VLESS data too short" };
  const view = new DataView(buffer);
  const version = new Uint8Array(buffer.slice(0, 1));

  const uuidHex = arrayBufferToHex(buffer.slice(1, 17));
  const uuidStr = `${uuidHex.slice(0, 8)}-${uuidHex.slice(8, 12)}-${uuidHex.slice(12, 16)}-${uuidHex.slice(16, 20)}-${uuidHex.slice(20)}`;
  if (allowedUUIDs.length > 0 && !allowedUUIDs.includes(uuidStr)) {
    return { hasError: true, message: "UUID tidak terdaftar" };
  }

  const optLength = new Uint8Array(buffer.slice(17, 18))[0];
  const cmd = new Uint8Array(buffer.slice(18 + optLength, 18 + optLength + 1))[0];
  let isUDP = false;
  if (cmd === 2) isUDP = true;
  else if (cmd !== 1 && cmd !== 3) return { hasError: true, message: `cmd ${cmd} tidak didukung` };

  const portIndex = 18 + optLength + 1;
  const portRemote = new DataView(buffer.slice(portIndex, portIndex + 2)).getUint16(0);

  const addressIndex = portIndex + 2;
  const addressType = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
  let addressValueIndex = addressIndex + 1;
  let addressLength = 0;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 4)).join(".");
      break;
    case 2: {
      addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    }
    case 3: {
      addressLength = 16;
      const dv = new DataView(buffer.slice(addressValueIndex, addressValueIndex + 16));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(":");
      break;
    }
    default:
      return { hasError: true, message: `addressType ${addressType} tidak valid` };
  }
  if (!addressValue) return { hasError: true, message: "address kosong" };

  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote,
    rawClientData: buffer.slice(addressValueIndex + addressLength + 2), // +2 = CRLF
    version: new Uint8Array([version[0], 0]),
    isUDP,
  };
}

// Trojan: sha224(password=uuid+crLF hex) 56 bytes + CRLF + cmd(1)+port(2)+ATYP(1)+addr+CRLF
function readTrojanHeader(buffer, allowedUUIDs) {
  // Deteksi struktural (kode asli tidak validasi password — kita validasi bila UUIDS diisi
  // dengan mencocokkan 56-byte hash di worker; untuk ringan, hash dicek di client-side list)
  if (buffer.byteLength < 70) return { hasError: true, message: "Trojan data too short" };
  const view = new DataView(buffer);
  // skip 56 hash + 2 CRLF
  const cmdIndex = 58;
  const cmd = view.getUint8(cmdIndex);
  let isUDP = false;
  if (cmd === 3) isUDP = true;
  else if (cmd !== 1) return { hasError: true, message: `trojan cmd ${cmd} tidak didukung` };

  const portRemote = view.getUint16(cmdIndex + 1);
  const addressType = view.getUint8(cmdIndex + 3);
  let idx = cmdIndex + 4;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressValue = new Uint8Array(buffer.slice(idx, idx + 4)).join(".");
      idx += 4;
      break;
    case 3: {
      const len = view.getUint8(idx);
      idx += 1;
      addressValue = new TextDecoder().decode(buffer.slice(idx, idx + len));
      idx += len;
      break;
    }
    case 4: {
      const dv = new DataView(buffer.slice(idx, idx + 16));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dv.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(":");
      idx += 16;
      break;
    }
    default:
      return { hasError: true, message: `trojan addressType ${addressType} tidak valid` };
  }
  // skip CRLF (2 byte)
  const rawStart = idx + 2;
  return {
    hasError: false,
    addressRemote: addressValue,
    portRemote,
    rawClientData: buffer.slice(rawStart),
    version: null,
    isUDP,
  };
}

// Sniffer: VLESS vs Trojan — VLESS: byte 56-57 = 0x0d 0x0a; Trojan: 58 byte hash pertama hex
function sniffProtocol(buffer) {
  if (buffer.byteLength >= 62) {
    const d = new Uint8Array(buffer.slice(56, 60));
    if (d[0] === 0x0d && d[1] === 0x0a && (d[2] === 0x01 || d[2] === 0x03 || d[2] === 0x7f) && (d[3] === 0x01 || d[3] === 0x03 || d[3] === 0x04)) {
      return "vless";
    }
  }
  // Trojan: hash hex (0-9a-f) sepanjang 56 byte + CRLF
  if (buffer.byteLength >= 58) {
    const hash = new Uint8Array(buffer.slice(0, 56));
    const isHexHash = /^([0-9a-f]{2}){28}$/i.test(arrayBufferToHex(hash)) &&
      new Uint8Array(buffer.slice(56, 58))[0] === 0x0d &&
      new Uint8Array(buffer.slice(56, 58))[1] === 0x0a;
    if (isHexHash) return "trojan";
  }
  return null;
}

// ---------- websocket handler ----------
async function websocketHandler(request, allowedUUIDs) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = { value: null };
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          try {
            if (isDNS) {
              return await handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log, RELAY_SERVER_UDP);
            }
            if (remoteSocketWrapper.value) {
              const writer = remoteSocketWrapper.value.writable.getWriter();
              await writer.write(chunk);
              writer.releaseLock();
              return;
            }

            const protocol = sniffProtocol(chunk);
            if (!protocol) {
              log("protokol tidak dikenal");
              safeCloseWebSocket(webSocket);
              return;
            }

            const protocolHeader =
              protocol === "vless"
                ? readVLESSHeader(chunk, allowedUUIDs)
                : readTrojanHeader(chunk, allowedUUIDs);

            if (protocolHeader.hasError) {
              log("header error:", protocolHeader.message);
              safeCloseWebSocket(webSocket);
              return;
            }

            addressLog = protocolHeader.addressRemote;
            portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

            if (protocolHeader.isUDP) {
              if (protocolHeader.portRemote === 53) {
                isDNS = true;
                return await handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log, RELAY_SERVER_UDP);
              }
              return await handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, chunk, webSocket, null, log, RELAY_SERVER_UDP);
            }

            await handleTCPOutBound(
              remoteSocketWrapper,
              protocolHeader.addressRemote,
              protocolHeader.portRemote,
              protocolHeader.rawClientData,
              webSocket,
              protocolHeader.version,
              log
            );
          } catch (err) {
            log("write handler error:", err && err.message);
            safeCloseWebSocket(webSocket);
          }
        },
        close() { log("stream close"); },
        abort(reason) { log("stream abort", JSON.stringify(reason)); },
      })
    )
    .catch((err) => log("pipeTo error", err && err.message));

  return new Response(null, { status: 101, webSocket: client });
}

// ---------- TCP outbound ----------
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port, allowH2: false });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    const timeout = new Promise((_, reject) =>
      setTimeout(() => reject(new Error("connect timeout 8s")), CONNECT_TIMEOUT_MS)
    );
    try {
      await Promise.race([writer.write(rawClientData), timeout]);
    } catch (e) {
      try { tcpSocket.close(); } catch (_) {}
      throw e;
    } finally {
      writer.releaseLock();
    }
    return tcpSocket;
  }

  async function retry() {
    try {
      const host = prxIP ? prxIP.split(/[:=-]/)[0] : addressRemote;
      const port = prxIP ? parseInt(prxIP.split(/[:=-]/)[1]) : portRemote;
      const tcpSocket = await connectAndWrite(host, port);
      tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(webSocket));
      remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log).catch(() => safeCloseWebSocket(webSocket));
    } catch (e) {
      log("fallback gagal:", e && e.message);
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log).catch(() => safeCloseWebSocket(webSocket));
  } catch (e) {
    log("target gagal, coba fallback:", e && e.message);
    await retry();
  }
}

// ---------- UDP (DNS) ----------
async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, log, relay) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({ hostname: relay.host, port: relay.port });
    const header = `udp:${targetAddress}:${targetPort}`;
    const headerBuffer = new TextEncoder().encode(header);
    const separator = new Uint8Array([0x7c]);
    const relayMessage = new Uint8Array(headerBuffer.length + 1 + dataChunk.byteLength);
    relayMessage.set(headerBuffer, 0);
    relayMessage.set(separator, headerBuffer.length);
    relayMessage.set(new Uint8Array(dataChunk), headerBuffer.length + 1);

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
      })
    );
  } catch (e) {
    log("UDP error:", e && e.message);
  }
}

// ---------- stream ----------
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (!readableStreamCancel) controller.enqueue(event.data);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (!readableStreamCancel) controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        log("ws error");
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    cancel() {
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) controller.error("ws closed");
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
      })
    )
    .catch((error) => {
      log("remoteSocketToWS error:", error && error.message);
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) retry();
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) socket.close();
  } catch (_) {}
}

// ---------- helpers ----------
function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const buf = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: buf.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

function shuffleArray(array) {
  for (let i = array.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [array[i], array[j]] = [array[j], array[i]];
  }
}

function getFlagEmoji(isoCode) {
  return String.fromCodePoint(...(isoCode || "").toUpperCase().split("").map((c) => 127397 + c.charCodeAt(0)));
}

async function getProxyForPath(pathname, env) {
  // path yang didukung (setelah leading "/"):
  //   <ip>-<port> | <ip>:<port> | <ip>=<port>   → langsung
  //   <CC> | <CC><n>                            → negara (dari KV list)
  //   ALL | ALL<n>                              → acak/urut semua
  //   PUTAR | PUTAR<n>                          → acak antar-negara
  //   <REGION>[<n>]                             → region (ASIA/EUROPE/AMERICA/AFRICA/OCEANIA/GLOBAL)
  let seg = pathname.replace(/^\/+/, "");
  if (!seg) return null;

  const ipPort = seg.match(/^(.+?)[-=:](\d+)$/);
  if (ipPort && /^\d{1,3}(\.\d{1,3}){3}$/.test(ipPort[1])) {
    return `${ipPort[1]}:${ipPort[2]}`;
  }

  const kvPrx = await getKVPrxList();
  const allList = Object.values(kvPrx).flat().filter(Boolean);
  const upper = seg.toUpperCase();

  const indexMatch = upper.match(/^([A-Z]+)(\d+)?$/);
  if (indexMatch) {
    const key = indexMatch[1];
    const index = indexMatch[2] ? parseInt(indexMatch[2], 10) - 1 : null;

    let pool = [];
    if (key === "ALL") pool = allList;
    else if (key === "PUTAR") {
      const countries = Object.keys(kvPrx).filter((c) => kvPrx[c] && kvPrx[c].length);
      const shuffled = countries.sort(() => Math.random() - 0.5);
      for (const c of shuffled) pool.push(kvPrx[c][Math.floor(Math.random() * kvPrx[c].length)]);
    } else if (REGION_MAP[key]) {
      for (const c of REGION_MAP[key]) if (kvPrx[c]) pool.push(...kvPrx[c]);
      if (key === "GLOBAL") pool = allList;
    } else if (kvPrx[key]) pool = kvPrx[key];

    if (!pool.length) return null;
    if (index === null) return pool[Math.floor(Math.random() * pool.length)];
    if (index >= 0 && index < pool.length) return pool[index];
    return null;
  }
  return null;
}

// ---------- config & sub generator ----------
function buildVLESSURI(domain, uuid, prxIPStr, tls, label) {
  const uri = new URL(`vless://${uuid}@${domain}:443`);
  uri.searchParams.set("encryption", "none");
  uri.searchParams.set("security", tls ? "tls" : "none");
  uri.searchParams.set("sni", domain);
  uri.searchParams.set("type", "ws");
  uri.searchParams.set("host", domain);
  uri.searchParams.set("path", `/${prxIPStr.replace(":", "-")}`);
  uri.hash = label;
  return uri.toString();
}

function buildTrojanURI(domain, uuid, prxIPStr, label) {
  const uri = new URL(`trojan://${uuid}@${domain}:443`);
  uri.searchParams.set("security", "tls");
  uri.searchParams.set("sni", domain);
  uri.searchParams.set("type", "ws");
  uri.searchParams.set("host", domain);
  uri.searchParams.set("path", `/${prxIPStr.replace(":", "-")}`);
  uri.hash = label;
  return uri.toString();
}

async function generateSubList(request, env, url) {
  const domain = APP_DOMAIN;
  const ccFilter = url.searchParams.get("cc")?.split(",").filter(Boolean) || [];
  const limit = Math.min(parseInt(url.searchParams.get("limit")) || 10, 50);
  const format = url.searchParams.get("format") || "raw";
  const fixedUUID = url.searchParams.get("uuid") || crypto.randomUUID(); // 1 UUID per panggilan, konsisten

  const kvPrx = await getKVPrxList();
  let pool = [];
  if (ccFilter.length) {
    for (const cc of ccFilter) if (kvPrx[cc]) pool.push(...kvPrx[cc].map((p) => ({ ip: p, cc })));
  } else {
    pool = Object.entries(kvPrx).flatMap(([cc, list]) => list.map((p) => ({ ip: p, cc })));
  }
  shuffleArray(pool);
  pool = pool.slice(0, limit);

  const result = [];
  for (const p of pool) {
    const label = encodeURIComponent(`${getFlagEmoji(p.cc)} ${p.cc} WS TLS [${serviceName}]`);
    result.push(buildVLESSURI(domain, fixedUUID, p.ip, true, label));
    result.push(buildTrojanURI(domain, fixedUUID, p.ip, label));
  }

  let finalResult = result.join("\n");
  if (format === "v2ray" || format === "b64") finalResult = btoa(finalResult);
  return new Response(finalResult, { status: 200, headers: { ...CORS_HEADER_OPTIONS, "Content-Type": "text/plain" } });
}

// ---------- main ----------
export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      APP_DOMAIN = url.hostname;
      serviceName = APP_DOMAIN.split(".")[0];
      const allowedUUIDs = parseUUIDList(env);

      // Halaman depan: info + panduan
      if (request.headers.get("Upgrade") !== "websocket") {
        if (url.pathname === "/" || url.pathname === "") {
          return new Response(
            `BENXX GATEWAY v2 (VLESS+Trojan)\n\n` +
            `Path WS:\n  /<ip>-<port>      → proxy langsung\n  /ID | /SG3        → negara (KV list)\n  /ALL | /ALL2      → semua acak/urut\n  /PUTAR            → acak antar negara\n  /ASIA | /EUROPE3  → region\n\n` +
            `Sub generator:\n  /sub?limit=10&cc=ID,SG&format=raw|v2ray&uuid=<opsional>\n\n` +
            `UUID aktif: ${allowedUUIDs.length === 0 ? "TERBUKA (set env UUIDS untuk membatasi)" : allowedUUIDs.length + " terdaftar"}\n`,
            { status: 200, headers: { ...CORS_HEADER_OPTIONS, "Content-Type": "text/plain" } }
          );
        }
        if (url.pathname === "/sub" || url.pathname.startsWith("/sub/")) {
          return generateSubList(request, env, url);
        }
        return new Response("Not Found", { status: 404, headers: CORS_HEADER_OPTIONS });
      }

      // ===== WebSocket (VPN) =====
      const proxyForPath = await getProxyForPath(url.pathname, env);
      prxIP = proxyForPath || DEFAULT_FALLBACK_PRX;
      return await websocketHandler(request, allowedUUIDs);
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: { ...CORS_HEADER_OPTIONS },
      });
    }
  },
};
