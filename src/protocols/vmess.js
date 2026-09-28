import { connect } from 'cloudflare:sockets';
import md5 from 'md5';
import { kdf } from '../utils/hash.js';
import { KDFSALT, parseAddr, parsePort } from '../utils/common.js';

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

        pCursor += 32;
        
        pCursor += 4;

        const cmd = headerPayload[pCursor];
        pCursor += 1;
        const isTcp = cmd === 0x1;

        const portRes = parsePort(headerPayload, pCursor);
        const port = portRes.port;
        pCursor = portRes.cursor;

        const addrRes = parseAddr(headerPayload, pCursor);
        const address = addrRes.address;

        const rawData = buffer.subarray(cursor);
        const targetHost = proxyHost || address;
        const targetPort = proxyPort || port;

        if (isTcp) {
            const remoteSocket = connect({ hostname: targetHost, port: targetPort });
            const writer = remoteSocket.writable.getWriter();

            if (rawData.length > 0) {
                await writer.write(rawData);
            }
            writer.releaseLock();

            wsReadable.pipeTo(remoteSocket.writable).catch(() => {});

            remoteSocket.readable.pipeTo(new WritableStream({
                write(data) {
                    if (server.readyState === 1) {
                        server.send(data);
                    }
                }
            })).catch(() => {});
        } else {
            server.close(1003, "UDP over VMess not supported yet");
        }
    } catch (err) {
        server.close(1011, `VMess Parsing Error: ${err.message}`);
    }
}

// Helper pendukung AES-GCM Decrypt menggunakan Web Crypto API
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

function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2) {
        bytes.push(parseInt(hex.substr(c, 2), 16));
    }
    return new Uint8Array(bytes);
}
