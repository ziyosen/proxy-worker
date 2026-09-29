import { connect } from 'cloudflare:sockets';
import md5 from 'md5';
import { kdf, sha256 } from '../utils/hash.js';
import { KDFSALT, parseAddr, parsePort } from '../utils/common.js';

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {}
}

// Mengadaptasi logika pengaliran data yang tahan putus dari geo-mod
async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry) {
    let header = responseHeader;
    let hasIncomingData = false;
    
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            start() {},
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error("webSocket is not open");
                }
                if (header) {
                    // Header balasan digabung dengan chunk pertama agar stabil
                    webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            close() {},
            abort() {},
        })
    ).catch(() => {
        safeCloseWebSocket(webSocket);
    });

    if (hasIncomingData === false && retry) {
        retry();
    }
}

export async function handleVmess(server, buffer, uuidStr, wsReadable, proxyHost, proxyPort) {
    try {
        if (buffer.length < 42) throw new Error("Packet too short for VMess AEAD");

        const uuidBytes = hexToBytes(uuidStr.replace(/-/g, ''));
        const constantKey = new TextEncoder().encode("c48619fe-8f02-49e0-b9e9-edf763e17e21");
        const combinedKey = new Uint8Array(uuidBytes.length + constantKey.length);
        combinedKey.set(uuidBytes);
        combinedKey.set(constantKey, uuidBytes.length);
        
        const baseKeyHex = md5(combinedKey);
        const baseKey = hexToBytes(baseKeyHex);

        let cursor = 0;
        const authId = buffer.subarray(cursor, cursor + 16);
        cursor += 16;
        const lenEnc = buffer.subarray(cursor, cursor + 18);
        cursor += 18;
        const nonce = buffer.subarray(cursor, cursor + 8);
        cursor += 8;

        const lenKey = (await kdf(baseKey, [KDFSALT.VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY, authId, nonce])).subarray(0, 16);
        const lenIv = (await kdf(baseKey, [KDFSALT.VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV, authId, nonce])).subarray(0, 12);

        const decryptedLenBuf = await aesGcmDecrypt(lenKey, lenIv, lenEnc, authId);
        const headerLength = (decryptedLenBuf[0] << 8) | decryptedLenBuf[1];

        const cmdEncLen = headerLength + 16;
        const cmdEnc = buffer.subarray(cursor, cursor + cmdEncLen);
        cursor += cmdEncLen;

        const payloadKey = (await kdf(baseKey, [KDFSALT.VMESS_HEADER_PAYLOAD_AEAD_KEY, authId, nonce])).subarray(0, 16);
        const payloadIv = (await kdf(baseKey, [KDFSALT.VMESS_HEADER_PAYLOAD_AEAD_IV, authId, nonce])).subarray(0, 12);

        const headerPayload = await aesGcmDecrypt(payloadKey, payloadIv, cmdEnc, authId);

        let pCursor = 0;
        const version = headerPayload[pCursor];
        pCursor += 1;
        if (version !== 1) throw new Error("invalid vmess version");

        const iv = headerPayload.subarray(pCursor, pCursor + 16);
        pCursor += 16;
        const key = headerPayload.subarray(pCursor, pCursor + 16);
        pCursor += 16;

        // options
        const options = headerPayload.subarray(pCursor, pCursor + 4);
        pCursor += 4;

        const cmd = headerPayload[pCursor];
        pCursor += 1;
        const isTcp = cmd === 0x1;

        const portRes = parsePort(headerPayload, pCursor);
        const port = portRes.port;
        pCursor = portRes.cursor;

        const addrRes = parseAddr(headerPayload, pCursor);
        const address = addrRes.address;

        // --- TAMBAHAN KRUSIAL: Enkripsi Response Header VMess ---
        const derivedKey = (await sha256(key)).subarray(0, 16);
        const derivedIv = (await sha256(iv)).subarray(0, 16);

        const respLenKey = (await kdf(derivedKey, [KDFSALT.AEAD_RESP_HEADER_LEN_KEY])).subarray(0, 16);
        const respLenIv = (await kdf(derivedIv, [KDFSALT.AEAD_RESP_HEADER_LEN_IV])).subarray(0, 12);
        
        // Enkripsi panjang respons (4 bytes)
        const encryptedLength = await aesGcmEncrypt(respLenKey, respLenIv, new Uint8Array([0, 0, 0, 4]));

        const respKey = (await kdf(derivedKey, [KDFSALT.AEAD_RESP_HEADER_KEY])).subarray(0, 16);
        const respIv = (await kdf(derivedIv, [KDFSALT.AEAD_RESP_HEADER_IV])).subarray(0, 12);
        
        // Enkripsi isi header respons
        const headerData = new Uint8Array([options[0], 0, 0, 0]);
        const encryptedHeader = await aesGcmEncrypt(respKey, respIv, headerData);

        // Gabungkan ke dalam satu buffer, JANGAN langsung dikirim ke WebSocket!
        // Serahkan pada remoteSocketToWS untuk digabung dengan balasan server internet.
        const responseHeaderBuf = new Uint8Array(encryptedLength.length + encryptedHeader.length);
        responseHeaderBuf.set(encryptedLength, 0);
        responseHeaderBuf.set(encryptedHeader, encryptedLength.length);

        const rawData = buffer.subarray(cursor);

        if (isTcp) {
            let remoteSocketWrapper = { value: null };

            // Fungsi penjalin koneksi
            async function connectAndWrite(targetHost, targetPort) {
                if (!targetHost || !targetPort) throw new Error("Invalid target");
                const tcpSocket = connect({ hostname: targetHost, port: targetPort });
                remoteSocketWrapper.value = tcpSocket;
                
                const writer = tcpSocket.writable.getWriter();
                if (rawData.length > 0) {
                    await writer.write(rawData);
                }
                writer.releaseLock();
                
                return tcpSocket;
            }

            // Fungsi fallback
            async function retryFallback() {
                try {
                    const tcpSocket = await connectAndWrite(proxyHost, proxyPort);
                    tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(server));
                    remoteSocketToWS(tcpSocket, server, responseHeaderBuf, null);
                } catch (e) {
                    safeCloseWebSocket(server);
                }
            }

            try {
                // Percobaan koneksi pertama ke alamat asli klien
                const tcpSocket = await connectAndWrite(address, port);
                remoteSocketToWS(tcpSocket, server, responseHeaderBuf, retryFallback);
            } catch (e) {
                // Jika koneksi langsung ditolak, pindah ke fallback
                retryFallback();
            }

            // Pemipaan data dengan wrapper agar stabil dan tidak bocor memori
            wsReadable.pipeTo(new WritableStream({
                async write(chunk) {
                    if (remoteSocketWrapper.value) {
                        const writer = remoteSocketWrapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                    }
                },
                close() {}, abort() {}
            })).catch(() => {});
            
        } else {
            if (server.readyState === WS_READY_STATE_OPEN) {
                server.close(1003, "UDP over VMess not supported yet");
            }
        }
    } catch (err) {
        if (server.readyState === WS_READY_STATE_OPEN) {
            server.close(1011, `VMess Parsing Error: ${err.message}`);
        }
    }
}

async function aesGcmDecrypt(keyBytes, ivBytes, ciphertext, additionalData) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["decrypt"]
    );

    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: ivBytes,
            additionalData: additionalData,
        },
        cryptoKey,
        ciphertext
    );

    return new Uint8Array(decrypted);
}

async function aesGcmEncrypt(keyBytes, ivBytes, data) {
    const cryptoKey = await crypto.subtle.importKey(
        "raw",
        keyBytes,
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: ivBytes,
        },
        cryptoKey,
        data
    );

    return new Uint8Array(encrypted);
}

function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return new Uint8Array(bytes);
}
