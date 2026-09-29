import { connect } from "cloudflare:sockets";

const CONFIG = {
    cacheTTL: 300000, 
};

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

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const DNS_PORT = 53;

const PROTOCOLS = {
    P1: atob('VHJvamFu'),
    P2: atob('VkxFU1M='),
    P3: atob('U2hhZG93c29ja3M='),
    P4: atob('Vk1lc3M=')
};

let prxIP = "";
let cachedProxyList = null;
let cacheTime = 0;

async function fetchProxyList() {
    const now = Date.now();
    if (cachedProxyList && (now - cacheTime) < CONFIG.cacheTTL) return cachedProxyList;
    try {
        const response = await fetch("https://raw.githubusercontent.com/ziyosen/tunel-worker/refs/heads/main/proxy.json");
        const text = await response.text();
        const proxyKv = JSON.parse(text);
        cachedProxyList = proxyKv;
        cacheTime = now;
        return proxyKv;
    } catch (error) {
        return cachedProxyList || {};
    }
}

async function getProxyFromPath(pathname) {
    if (!pathname || pathname === '/') return null;
    let proxyip = pathname.startsWith('/Benxx-Project/') ? pathname.replace('/Benxx-Project/', '') : pathname.substring(1);
    
    if (/^([A-Z]{2})/.test(proxyip)) {
        let kvidList = proxyip.split(',');
        let proxyKv = await fetchProxyList();
        const randomByte = crypto.getRandomValues(new Uint8Array(1))[0];
        const kvIndex = randomByte % kvidList.length;
        const selectedKv = kvidList[kvIndex];
        
        if (proxyKv[selectedKv] && proxyKv[selectedKv].length > 0) {
            const proxyipIndex = randomByte % proxyKv[selectedKv].length;
            return proxyKv[selectedKv][proxyipIndex].replace(/:/g, "-");
        }
    }
    
    const ipPortMatch = proxyip.match(/^([\d\.]+)[:=:-](\d+)$/);
    if (ipPortMatch) return ipPortMatch[1] + ':' + ipPortMatch[2];
    return null;
}

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

// DETEKSI PROTOKOL PRESISI
async function detectProtocol(buffer, uuidStr) {
    // 1. Cek VMess terlebih dahulu
    if (await isVMess(buffer, uuidStr)) return PROTOCOLS.P4;
    
    // 2. Cek Trojan (\r\n pada byte 56, 57)
    if (buffer.length >= 58 && buffer[56] === 13 && buffer[57] === 10) {
        return PROTOCOLS.P1;
    }

    // 3. Cek VLESS (Version 0x00 & panjang paket >= 24)
    if (buffer.length >= 24 && buffer[0] === 0) {
        return PROTOCOLS.P2;
    }

    // 4. Fallback ke Shadowsocks / Unknown
    return PROTOCOLS.P3;
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
        version: concat(encryptedLength, encryptedHeaderPayload), isUDP: portRemote === DNS_PORT
    };
}

function parseP3Header(buffer) {
    const addressType = buffer[0];
    let addressLength = 0, addressValueIndex = 1, addressValue = "";
    switch (addressType) {
        case 1:
            addressLength = 4;
            addressValue = new Uint8Array(buffer.subarray(addressValueIndex, addressValueIndex + 4)).join(".");
            break;
        case 3:
            addressLength = buffer[addressValueIndex];
            addressValueIndex += 1;
            addressValue = arr2str(buffer.subarray(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 4:
            addressLength = 16;
            const ipv6 = [];
            for (let i = 0; i < 8; i++) ipv6.push(((buffer[addressValueIndex + i * 2] << 8) | buffer[addressValueIndex + i * 2 + 1]).toString(16));
            addressValue = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: 'Invalid addressType for P3: ' + addressType };
    }
    const portIndex = addressValueIndex + addressLength;
    const portRemote = (buffer[portIndex] << 8) | buffer[portIndex + 1];
    return {
        hasError: false, addressRemote: addressValue, addressType, portRemote,
        rawDataIndex: portIndex + 2, rawClientData: buffer.subarray(portIndex + 2), version: null, isUDP: portRemote === DNS_PORT
    };
}

function parseP2Header(buffer) {
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
        case 1: // IPv4
            addressLength = 4;
            addressValue = new Uint8Array(buffer.subarray(addressValueIndex, addressValueIndex + 4)).join(".");
            break;
        case 2: // Domain
            addressLength = buffer[addressValueIndex];
            addressValueIndex += 1;
            addressValue = arr2str(buffer.subarray(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3: // IPv6
            addressLength = 16;
            const ipv6 = [];
            for (let i = 0; i < 8; i++) ipv6.push(((buffer[addressValueIndex + i * 2] << 8) | buffer[addressValueIndex + i * 2 + 1]).toString(16));
            addressValue = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: 'Invalid addressType for VLESS: ' + addressType };
    }
    return {
        hasError: false, addressRemote: addressValue, addressType, portRemote,
        rawDataIndex: addressValueIndex + addressLength, rawClientData: buffer.subarray(addressValueIndex + addressLength),
        version: new Uint8Array([version, 0]), isUDP
    };
}

function parseP1Header(buffer) {
    const dataBuffer = buffer.subarray(58);
    if (dataBuffer.length < 6) return { hasError: true, message: "Invalid request data for Trojan" };
    let isUDP = false;
    const cmd = dataBuffer[0];
    if (cmd === 3) isUDP = true;
    let addressType = dataBuffer[1];
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
            return { hasError: true, message: 'Invalid addressType for Trojan: ' + addressType };
    }
    const portIndex = addressValueIndex + addressLength;
    const portRemote = (dataBuffer[portIndex] << 8) | dataBuffer[portIndex + 1];
    return {
        hasError: false, addressRemote: addressValue, addressType, portRemote,
        rawDataIndex: portIndex + 4, rawClientData: dataBuffer.subarray(portIndex + 4), version: null, isUDP
    };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader) {
    let header = responseHeader, hasIncomingData = false;
    await remoteSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            hasIncomingData = true;
            if (webSocket.readyState !== WS_READY_STATE_OPEN) controller.error("webSocket closed");
            if (header) {
                webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                header = null;
            } else webSocket.send(chunk);
        },
        close() {},
        abort() {},
    })).catch(() => {
        safeCloseWebSocket(webSocket);
    });
}

async function handleTCPOutbound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader) {
    async function connectAndWrite(address, port) {
        const tcpSocket = connect({ hostname: address, port });
        remoteSocket.value = tcpSocket;
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }
    async function retry() {
        const targetHost = (prxIP ? prxIP.split(/[:=-]/)[0] : addressRemote);
        const targetPort = (prxIP ? parseInt(prxIP.split(/[:=-]/)[1]) : portRemote);
        try {
            const tcpSocket = await connectAndWrite(targetHost, targetPort);
            tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(webSocket));
            remoteSocketToWS(tcpSocket, webSocket, responseHeader);
        } catch (e) {
            safeCloseWebSocket(webSocket);
        }
    }
    try {
        const tcpSocket = await connectAndWrite(addressRemote, portRemote);
        remoteSocketToWS(tcpSocket, webSocket, responseHeader);
    } catch (e) {
        retry();
    }
}

function createReadableWebSocketStream(webSocketServer, earlyDataHeader) {
    let readableStreamCancel = false;
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener("message", (e) => {
                if (!readableStreamCancel) controller.enqueue(e.data);
            });
            webSocketServer.addEventListener("close", () => {
                safeCloseWebSocket(webSocketServer);
                if (!readableStreamCancel) controller.close();
            });
            webSocketServer.addEventListener("error", (err) => {
                controller.error(err);
            });
            if (earlyDataHeader) {
                try {
                    const decode = atob(earlyDataHeader.replace(/-/g, "+").replace(/_/g, "/"));
                    controller.enqueue(Uint8Array.from(decode, c => c.charCodeAt(0)).buffer);
                } catch (e) {}
            }
        },
        cancel() {
            readableStreamCancel = true;
            safeCloseWebSocket(webSocketServer);
        },
    });
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) socket.close();
    } catch (e) {}
}

async function websocketHandler(request, uuid) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
    const readableWebSocketStream = createReadableWebSocketStream(webSocket, earlyDataHeader);

    let remoteSocketWrapper = { value: null };

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk) {
            if (remoteSocketWrapper.value) {
                const writer = remoteSocketWrapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            const bufferChunk = new Uint8Array(chunk);
            let protocol = await detectProtocol(bufferChunk, uuid);
            let protocolHeader;

            if (protocol === PROTOCOLS.P1) protocolHeader = parseP1Header(bufferChunk);
            else if (protocol === PROTOCOLS.P2) protocolHeader = parseP2Header(bufferChunk);
            else if (protocol === PROTOCOLS.P4) protocolHeader = await parseP4Header(bufferChunk, uuid);
            else protocolHeader = parseP3Header(bufferChunk);

            if (protocolHeader.hasError) {
                throw new Error(protocolHeader.message);
            }

            handleTCPOutbound(remoteSocketWrapper, protocolHeader.addressRemote, protocolHeader.portRemote,
                protocolHeader.rawClientData, webSocket, protocolHeader.version);
        },
    })).catch(() => {
        safeCloseWebSocket(webSocket);
    });

    return new Response(null, { status: 101, webSocket: client });
}

function generateLinks(host, uuid) {
    const vmessConfig = {
        ps: "Changli vmess", v: "2", add: host, port: "80", id: uuid, aid: "0",
        scy: "zero", net: "ws", type: "none", host: host, path: "/ID", tls: "", sni: host, alpn: ""
    };
    const base64Vmess = btoa(JSON.stringify(vmessConfig)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const vmessLink = `vmess://${base64Vmess}`;
    const vlessLink = `vless://${uuid}@${host}:443?encryption=none&type=ws&host=${host}&path=%2FID&security=tls&sni=${host}#Changli vless`;
    const trojanLink = `trojan://${uuid}@${host}:443?encryption=none&type=ws&host=${host}&path=%2FID&security=tls&sni=${host}#Changli trojan`;

    return new Response(`${vmessLink}\n${vlessLink}\n${trojanLink}`, {
        status: 200,
        headers: { "Content-Type": "text/plain;charset=utf-8" }
    });
}

export default {
    async fetch(request, env) {
        try {
            const url = new URL(request.url);
            const host = url.host;
            const path = url.pathname;
            const uuid = env.UUID || "2bcfbfba-b446-4ad5-93ad-72af9e008f61"; 

            if (path === '/link') return generateLinks(host, uuid);

            let proxyip = path.startsWith('/Benxx-Project/') ? path.replace('/Benxx-Project/', '') : (path !== '/' ? path.substring(1) : '');

            if (proxyip) {
                const resolvedProxy = await getProxyFromPath('/' + proxyip);
                if (resolvedProxy) prxIP = resolvedProxy;
            }

            if (request.headers.get("Upgrade") === "websocket") {
                return websocketHandler(request, uuid);
            }

            return new Response("hi from wasm!", { status: 200 });
        } catch (err) {
            return new Response(`Worker Error: ${err.message}`, { status: 500 });
        }
    }
};
