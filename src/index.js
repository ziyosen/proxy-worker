
// ============================================
// VPN CONFIG MANAGER & MULTI-PROTOCOL WORKER 
// ============================================

import { connect } from "cloudflare:sockets";

let serviceName = "";
let APP_DOMAIN = "";
const KV_PRX_URL = "https://raw.githubusercontent.com/ziyosen/tunel-worker/refs/heads/main/proxy.json";
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

// ==================== VMESS AEAD CRYPTO HELPERS ====================
const str2arr = (str) => new TextEncoder().encode(str);
const arr2str = (arr) => new TextDecoder().decode(arr);
const concat = (...arrays) => {
    const result = new Uint8Array(arrays.reduce((sum, arr) => sum + arr.length, 0));
    let offset = 0;
    for (const arr of arrays) {
        result.set(arr, offset);
        offset += arr.length;
    }
    return result;
};
const alloc = (size, fill = 0) => {
    const arr = new Uint8Array(size);
    if (fill) arr.fill(fill);
    return arr;
};

const KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY = str2arr("VMess Header AEAD Key_Length");
const KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV = str2arr("VMess Header AEAD Nonce_Length");
const KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY = str2arr("VMess Header AEAD Key");
const KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV = str2arr("VMess Header AEAD Nonce");
const KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY = str2arr("AEAD Resp Header Len Key");
const KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV = str2arr("AEAD Resp Header Len IV");
const KDFSALT_CONST_AEAD_RESP_HEADER_KEY = str2arr("AEAD Resp Header Key");
const KDFSALT_CONST_AEAD_RESP_HEADER_IV = str2arr("AEAD Resp Header IV");

const PROTOCOLS = {
    P1: 'Trojan',
    P2: 'VLESS',
    P3: 'Shadowsocks',
    P4: 'VMess'
};

function sha256(message) {
    const msg = message instanceof Uint8Array ? message : str2arr(message);
    const K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);
    let H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
    const rotr = (x, n) => (x >>> n) | (x << (32 - n));
    const len = msg.length;
    const paddingLen = ((56 - (len + 1) % 64) + 64) % 64;
    const padded = new Uint8Array(len + 1 + paddingLen + 8);
    padded.set(msg); padded[len] = 0x80;
    new DataView(padded.buffer).setUint32(padded.length - 4, len * 8, false);
    const W = new Uint32Array(64);
    for (let i = 0; i < padded.length; i += 64) {
        const block = new DataView(padded.buffer, i, 64);
        for (let t = 0; t < 16; t++) W[t] = block.getUint32(t * 4, false);
        for (let t = 16; t < 64; t++) {
            const s0 = rotr(W[t - 15], 7) ^ rotr(W[t - 15], 18) ^ (W[t - 15] >>> 3);
            const s1 = rotr(W[t - 2], 17) ^ rotr(W[t - 2], 19) ^ (W[t - 2] >>> 10);
            W[t] = (W[t - 16] + s0 + W[t - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h] = H;
        for (let t = 0; t < 64; t++) {
            const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const ch = (e & f) ^ (~e & g);
            const T1 = (h + S1 + ch + K[t] + W[t]) >>> 0;
            const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const T2 = (S0 + maj) >>> 0;
            h = g; g = f; f = e; e = (d + T1) >>> 0;
            d = c; c = b; b = a; a = (T1 + T2) >>> 0;
        }
        H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
    }
    const result = new Uint8Array(32);
    const rv = new DataView(result.buffer);
    for (let i = 0; i < 8; i++) rv.setUint32(i * 4, H[i], false);
    return result;
}

function md5(data, salt) {
    let msg = data instanceof Uint8Array ? data : str2arr(data);
    if (salt) msg = concat(msg, salt instanceof Uint8Array ? salt : str2arr(salt));
    const K = new Uint32Array([
        0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
        0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
        0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
        0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
        0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
        0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
        0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
    ]);
    const S = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
        4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
    ];
    let [a0, b0, c0, d0] = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476];
    const len = msg.length;
    const paddingLen = ((56 - (len + 1) % 64) + 64) % 64;
    const padded = new Uint8Array(len + 1 + paddingLen + 8);
    padded.set(msg); padded[len] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(padded.length - 8, (len * 8) >>> 0, true);
    view.setUint32(padded.length - 4, (len * 8 / 0x100000000) >>> 0, true);
    const rotl = (x, n) => (x << n) | (x >>> (32 - n));
    for (let i = 0; i < padded.length; i += 64) {
        const M = new Uint32Array(16);
        for (let j = 0; j < 16; j++) M[j] = view.getUint32(i + j * 4, true);
        let [A, B, C, D] = [a0, b0, c0, d0];
        for (let j = 0; j < 64; j++) {
            let F, g;
            if (j < 16) { F = (B & C) | (~B & D); g = j; }
            else if (j < 32) { F = (D & B) | (~D & C); g = (5 * j + 1) % 16; }
            else if (j < 48) { F = B ^ C ^ D; g = (3 * j + 5) % 16; }
            else { F = C ^ (B | ~D); g = (7 * j) % 16; }
            F = (F + A + K[j] + M[g]) >>> 0;
            A = D; D = C; C = B; B = (B + rotl(F, S[j])) >>> 0;
        }
        a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
    }
    const result = new Uint8Array(16);
    const rv = new DataView(result.buffer);
    rv.setUint32(0, a0, true); rv.setUint32(4, b0, true); rv.setUint32(8, c0, true); rv.setUint32(12, d0, true);
    return result;
}

function createRecursiveHash(key, underlyingHashFn) {
    const ipad = alloc(64, 0x36);
    const opad = alloc(64, 0x5c);
    const keyBuf = key instanceof Uint8Array ? key : str2arr(key);
    for (let i = 0; i < keyBuf.length; i++) {
        ipad[i] ^= keyBuf[i];
        opad[i] ^= keyBuf[i];
    }
    return (data) => underlyingHashFn(concat(opad, underlyingHashFn(concat(ipad, data))));
}

function kdf(key, path) {
    let fn = sha256;
    fn = createRecursiveHash(str2arr("VMess AEAD KDF"), fn);
    for (const p of path) fn = createRecursiveHash(p, fn);
    return fn(key);
}

function toBuffer(uuidStr) {
    const hex = uuidStr.replace(/-/g, '');
    const arr = new Uint8Array(16);
    for (let i = 0; i < 16; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
    return arr;
}

async function aesGcmDecrypt(key, iv, data, aad) {
    const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['decrypt']);
    const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad || new Uint8Array(0), tagLength: 128 }, cryptoKey, data);
    return new Uint8Array(decrypted);
}

async function aesGcmEncrypt(key, iv, data, aad) {
    const cryptoKey = await crypto.subtle.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt']);
    const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad || new Uint8Array(0), tagLength: 128 }, cryptoKey, data);
    return new Uint8Array(encrypted);
}

async function isVMess(buffer, uuidStr) {
    if (!uuidStr || buffer.length < 42) return false;
    try {
        const uuidBytes = toBuffer(uuidStr);
        const auth_id = buffer.subarray(0, 16);
        const len_encrypted = buffer.subarray(16, 34);
        const nonce = buffer.subarray(34, 42);
        const key = md5(uuidBytes, str2arr("c48619fe-8f02-49e0-b9e9-edf763e17e21"));
        const header_length_key = kdf(key, [KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, auth_id, nonce]).subarray(0, 16);
        const header_length_nonce = kdf(key, [KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, auth_id, nonce]).subarray(0, 12);
        const decryptedLen = await aesGcmDecrypt(header_length_key, header_length_nonce, len_encrypted, auth_id);
        const header_length = (decryptedLen[0] << 8) | decryptedLen[1];
        return header_length > 0 && header_length < 4096;
    } catch (e) {
        return false;
    }
}

async function parseP4Header(buffer, uuidStr) {
    const uuidBytes = toBuffer(uuidStr);
    if (buffer.length < 16) throw new Error("Data too short for VMess AuthID");
    const auth_id = buffer.subarray(0, 16);
    let remaining = buffer.subarray(16);
    const len_encrypted = remaining.subarray(0, 18);
    remaining = remaining.subarray(18);
    const nonce = remaining.subarray(0, 8);
    remaining = remaining.subarray(8);
    const key = md5(uuidBytes, str2arr("c48619fe-8f02-49e0-b9e9-edf763e17e21"));
    const mainKey = key;
    const header_length_key = kdf(key, [KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, auth_id, nonce]).subarray(0, 16);
    const header_length_nonce = kdf(key, [KDFSALT_CONST_VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, auth_id, nonce]).subarray(0, 12);
    const decryptedLen = await aesGcmDecrypt(header_length_key, header_length_nonce, len_encrypted, auth_id);
    const header_length = (decryptedLen[0] << 8) | decryptedLen[1];
    const cmd_encrypted = remaining.subarray(0, header_length + 16);
    const rawClientData = remaining.subarray(header_length + 16);
    const payload_key = kdf(mainKey, [KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_KEY, auth_id, nonce]).subarray(0, 16);
    const payload_nonce = kdf(mainKey, [KDFSALT_CONST_VMESS_HEADER_PAYLOAD_AEAD_IV, auth_id, nonce]).subarray(0, 12);
    const cmdBuf = await aesGcmDecrypt(payload_key, payload_nonce, cmd_encrypted, auth_id);
    if (cmdBuf[0] !== 1) throw new Error("Invalid VMess version");
    const iv = cmdBuf.subarray(1, 17);
    const keyResp = cmdBuf.subarray(17, 33);
    const responseAuth = cmdBuf[33];
    const portRemote = (cmdBuf[38] << 8) | cmdBuf[39];
    const addrType = cmdBuf[40];
    let addressRemote = "";
    if (addrType === 1) {
        addressRemote = cmdBuf[41] + '.' + cmdBuf[42] + '.' + cmdBuf[43] + '.' + cmdBuf[44];
    } else if (addrType === 2) {
        const len = cmdBuf[41];
        addressRemote = arr2str(cmdBuf.subarray(42, 42 + len));
    } else if (addrType === 3) {
        const parts = [];
        for (let i = 0; i < 8; i++) parts.push(((cmdBuf[41 + i * 2] << 8) | cmdBuf[41 + i * 2 + 1]).toString(16));
        addressRemote = parts.join(':');
    }
    const respKeyBase = sha256(keyResp).subarray(0, 16);
    const respIvBase = sha256(iv).subarray(0, 16);
    const length_key = kdf(respKeyBase, [KDFSALT_CONST_AEAD_RESP_HEADER_LEN_KEY]).subarray(0, 16);
    const length_iv = kdf(respIvBase, [KDFSALT_CONST_AEAD_RESP_HEADER_LEN_IV]).subarray(0, 12);
    const encryptedLength = await aesGcmEncrypt(length_key, length_iv, new Uint8Array([0, 4]));
    const payload_key_resp = kdf(respKeyBase, [KDFSALT_CONST_AEAD_RESP_HEADER_KEY]).subarray(0, 16);
    const payload_iv_resp = kdf(respIvBase, [KDFSALT_CONST_AEAD_RESP_HEADER_IV]).subarray(0, 12);
    const encryptedHeaderPayload = await aesGcmEncrypt(payload_key_resp, payload_iv_resp, new Uint8Array([responseAuth, 0, 0, 0]));
    return {
        hasError: false, addressRemote, portRemote, rawClientData,
        version: concat(encryptedLength, encryptedHeaderPayload), isUDP: portRemote === DNS_SERVER_PORT
    };
}

async function detectProtocol(buffer, uuidStr) {
    if (await isVMess(buffer, uuidStr)) return PROTOCOLS.P4;
    if (buffer.length >= 58 && buffer[56] === 13 && buffer[57] === 10) return PROTOCOLS.P1;
    if (buffer.length >= 24 && buffer[0] === 0) return PROTOCOLS.P2;
    return PROTOCOLS.P3;
}
// ===================================================================

async function getKVPrxList() {
  try {
    const res = await fetch(KV_PRX_URL, { cf: { cacheTtl: 300 } });
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {
      console.log('Error fetching proxy list', e);
  }
  return {};
}

async function getProxyFromPath(pathname) {
  if (!pathname || !pathname.startsWith('/Benxx-Project/')) {
    return null;
  }
  
  let proxyip = pathname.replace('/Benxx-Project/', '');
  if (!proxyip) return null;

  if (/^([A-Z]{2})/.test(proxyip)) {
    let kvidList = proxyip.split(',');
    let proxyKv = await getKVPrxList();
    
    // Safety fallback jika fetch gagal
    if (!proxyKv || Object.keys(proxyKv).length === 0) {
        return "104.18.7.81:443"; // Default fallback IP
    }

    // Menggunakan Math.random agar lebih aman dari crypto.getRandomValues bias
    const randomKvIndex = Math.floor(Math.random() * kvidList.length);
    const selectedKv = kvidList[randomKvIndex];
    
    if (proxyKv[selectedKv] && Array.isArray(proxyKv[selectedKv]) && proxyKv[selectedKv].length > 0) {
      const proxyipIndex = Math.floor(Math.random() * proxyKv[selectedKv].length);
      return proxyKv[selectedKv][proxyipIndex].replace(/:/g, "-");
    } else {
        // Fallback jika negara yang dipilih kosong tapi data ada
        const allProxies = Object.values(proxyKv).flat();
        if(allProxies.length > 0) {
            const fallbackIndex = Math.floor(Math.random() * allProxies.length);
            return allProxies[fallbackIndex].replace(/:/g, "-");
        }
    }
  }
  
  const ipPortMatch = proxyip.match(/^([\d\.]+)[:=:-](\d+)$/);
  if (ipPortMatch) {
    return ipPortMatch[1] + ':' + ipPortMatch[2];
  }
  
  return "104.18.7.81:443"; // Fallback akhir jika pattern tidak cocok
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      APP_DOMAIN = url.hostname;
      serviceName = APP_DOMAIN.split(".")[0];
      const uuid = env.UUID || "2bcfbfba-b446-4ad5-93ad-72af9e008f61"; 

      const upgradeHeader = request.headers.get("Upgrade");
      if (upgradeHeader === "websocket") {
        if (!url.pathname.startsWith('/Benxx-Project/')) {
          return new Response("Unauthorized Path", { status: 403 });
        }

        const resolvedProxy = await getProxyFromPath(url.pathname);
        const prx = resolvedProxy
          ? resolvedProxy.replace(/:/g, "-")
          : "104.18.7.81:443"; // Fallback aman

        return await websocketHandler(request, uuid, prx);
      }

      return new Response("hi from wasm!", { status: 200, headers: CORS_HEADER_OPTIONS });
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: { ...CORS_HEADER_OPTIONS },
      });
    }
  },
};

async function websocketHandler(request, uuid, prx) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

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
          // Seluruh isi handler dibungkus try/catch: setelah response 101 dikirim,
          // exception apa pun yang lolos dari sini tidak lagi tertangkap oleh try/catch
          // di handler fetch() dan akan tampil sebagai Error 1101. Dengan dibungkus,
          // kesalahan cukup menutup soket dengan rapi.
          try {
            if (isDNS) {
              return await handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log, RELAY_SERVER_UDP);
            }
            if (remoteSocketWrapper.value) {
              const writer = remoteSocketWrapper.value.writable.getWriter();
              try {
                await writer.write(chunk);
              } finally {
                writer.releaseLock();
              }
              return;
            }

            const bufferChunk = new Uint8Array(chunk);
            const protocol = await detectProtocol(bufferChunk, uuid);
            let protocolHeader;

            if (protocol === PROTOCOLS.P1) {
              protocolHeader = readHorseHeader(bufferChunk);
            } else if (protocol === PROTOCOLS.P2) {
              protocolHeader = readP2Header(bufferChunk);
            } else if (protocol === PROTOCOLS.P4) {
              protocolHeader = await parseP4Header(bufferChunk, uuid);
            } else {
              protocolHeader = readSsHeader(bufferChunk);
            }

            addressLog = protocolHeader.addressRemote || "";
            portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

            if (protocolHeader.hasError) {
              // Dulu: throw new Error(...) -> memicu 1101. Sekarang cukup tutup soket.
              log("header parse error", protocolHeader.message);
              safeCloseWebSocket(webSocket);
              return;
            }

            if (protocolHeader.isUDP) {
              if (protocolHeader.portRemote === 53) {
                isDNS = true;
                return await handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, protocolHeader.version, log, RELAY_SERVER_UDP);
              }
              return await handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, chunk, webSocket, protocolHeader.version, log, RELAY_SERVER_UDP);
            }

            await handleTCPOutBound(remoteSocketWrapper, protocolHeader.addressRemote, protocolHeader.portRemote, protocolHeader.rawClientData, webSocket, protocolHeader.version, log, prx);
          } catch (err) {
            log("websocket write handler error", err && err.message ? err.message : err);
            safeCloseWebSocket(webSocket);
          }
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, { status: 101, webSocket: client });
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log, prx) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port: port });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    try {
      await writer.write(rawClientData);
    } finally {
      writer.releaseLock();
    }
    return tcpSocket;
  }

  async function retry() {
    
    try {
      const targetHost = prx ? prx.split(/[:=-]/)[0] : addressRemote;
      const targetPort = prx ? parseInt(prx.split(/[:=-]/)[1]) : portRemote;
      const tcpSocket = await connectAndWrite(targetHost, targetPort);
      tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(webSocket));
      remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log).catch((err) => {
        log("retry stream error", err && err.message ? err.message : err);
        safeCloseWebSocket(webSocket);
      });
    } catch (e) {
      log("retry to fallback proxy failed", e && e.message ? e.message : e);
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log).catch((err) => {
      log("target stream error", err && err.message ? err.message : err);
      safeCloseWebSocket(webSocket);
    });
  } catch (e) {
    log("connect to target failed, trying fallback", e && e.message ? e.message : e);
    retry();
  }
}

async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, log, relay) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({ hostname: relay.host, port: relay.port });
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
      })
    );
  } catch (e) {}
}

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
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (earlyData) controller.enqueue(earlyData);
    },
    cancel() {
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

function readSsHeader(ssBuffer) {
  const view = new DataView(ssBuffer.buffer, ssBuffer.byteOffset, ssBuffer.byteLength);
  const addressType = view.getUint8(0);
  let addressLength = 0, addressValueIndex = 1, addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 4)).join(".");
      break;
    case 3:
      addressLength = ssBuffer[addressValueIndex];
      addressValueIndex += 1;
      addressValue = arr2str(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength).buffer);
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(":");
      break;
    default:
      return { hasError: true, message: "Invalid addressType" };
  }
  const portIndex = addressValueIndex + addressLength;
  const portRemote = new DataView(ssBuffer.slice(portIndex, portIndex + 2).buffer).getUint16(0);
  return {
    hasError: false, addressRemote: addressValue, addressType, portRemote,
    rawDataIndex: portIndex + 2, rawClientData: ssBuffer.slice(portIndex + 2), version: null, isUDP: portRemote == 53
  };
}

function readP2Header(buffer) {
  const version = buffer[0];
  let isUDP = false;
  const optLength = buffer[17];
  const cmd = buffer[18 + optLength];
  if (cmd === 2) isUDP = true;
  const portIndex = 18 + optLength + 1;
  const portRemote = (buffer[portIndex] << 8) | buffer[portIndex + 1];
  let addressIndex = portIndex + 2;
  const addressType = buffer[addressIndex];
  let addressLength = 0, addressValueIndex = addressIndex + 1, addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(buffer.subarray(addressValueIndex, addressValueIndex + 4)).join(".");
      break;
    case 2:
      addressLength = buffer[addressValueIndex];
      addressValueIndex += 1;
      addressValue = arr2str(buffer.subarray(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 3:
      addressLength = 16;
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(((buffer[addressValueIndex + i * 2] << 8) | buffer[addressValueIndex + i * 2 + 1]).toString(16));
      addressValue = ipv6.join(":");
      break;
    default:
      return { hasError: true, message: 'Invalid addressType for VLESS' };
  }
  return {
    hasError: false, addressRemote: addressValue, addressType, portRemote,
    rawDataIndex: addressValueIndex + addressLength, rawClientData: buffer.subarray(addressValueIndex + addressLength),
    version: new Uint8Array([version, 0]), isUDP
  };
}

function readHorseHeader(buffer) {
  const dataBuffer = buffer.subarray(58);
  if (dataBuffer.length < 6) return { hasError: true, message: "invalid request data" };
  const view = new DataView(dataBuffer.buffer, dataBuffer.byteOffset, dataBuffer.byteLength);
  const cmd = view.getUint8(0);
  const isUDP = (cmd == 3);
  const addressType = view.getUint8(1);
  let addressLength = 0, addressValueIndex = 2, addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(dataBuffer.subarray(addressValueIndex, addressValueIndex + 4)).join(".");
      break;
    case 3:
      addressLength = dataBuffer[addressValueIndex];
      addressValueIndex += 1;
      addressValue = arr2str(dataBuffer.subarray(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(((dataBuffer[addressValueIndex + i * 2] << 8) | dataBuffer[addressValueIndex + i * 2 + 1]).toString(16));
      addressValue = ipv6.join(":");
      break;
    default:
      return { hasError: true, message: "invalid addressType" };
  }
  const portIndex = addressValueIndex + addressLength;
  const portRemote = (dataBuffer[portIndex] << 8) | dataBuffer[portIndex + 1];
  return {
    hasError: false, addressRemote: addressValue, addressType, portRemote,
    rawDataIndex: portIndex + 4, rawClientData: dataBuffer.subarray(portIndex + 4), version: null, isUDP
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) controller.error("closed");
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
      })
    )
    .catch(() => {
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) retry();
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {}
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}
