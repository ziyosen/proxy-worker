import { connect } from 'cloudflare:sockets';
import md5 from 'md5';

const KDF_SALT = {
    LEN_KEY: "VMess Header AEAD Key_Length",
    LEN_IV: "VMess Header AEAD Nonce_Length",
    PAYLOAD_KEY: "VMess Header AEAD Key",
    PAYLOAD_IV: "VMess Header AEAD Nonce",
    RESP_LEN_KEY: "AEAD Resp Header Len Key",
    RESP_LEN_IV: "AEAD Resp Header Len IV",
    RESP_KEY: "AEAD Resp Header Key",
    RESP_IV: "AEAD Resp Header IV"
};

export async function handleVmess(server, buffer, uuidStr, proxyHost, proxyPort) {
    try {
        if (buffer.length < 42) throw new Error("Packet too short for VMess AEAD");

        const uuidBytes = hexToBytes(uuidStr.replace(/-/g, ''));
        const keyString = "c48619fe-8f02-49e0-b9e9-edf763e17e21"; 
        
        const baseKeyStr = md5(new Uint8Array([...uuidBytes, ...new TextEncoder().encode(keyString)]));
        const baseKey = hexToBytes(baseKeyStr);

        const authId = buffer.slice(0, 16);
        const headerLenEnc = buffer.slice(16, 34);
        const nonce = buffer.slice(34, 42);

        const lenKey = (await kdf(baseKey, [KDF_SALT.LEN_KEY, authId, nonce])).slice(0, 16);
        const lenIv = (await kdf(baseKey, [KDF_SALT.LEN_IV, authId, nonce])).slice(0, 12);
        
        const cryptoLenKey = await crypto.subtle.importKey("raw", lenKey, { name: "AES-GCM" }, false, ["decrypt"]);
        const decryptedLenBuf = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: lenIv, additionalData: authId }, 
            cryptoLenKey, 
            headerLenEnc
        );
        const headerLength = new DataView(decryptedLenBuf).getUint16(0, false);

        const expectedTotalLen = 42 + headerLength + 16; 
        if (buffer.length < expectedTotalLen) throw new Error("Incomplete VMess Payload");

        const payloadEnc = buffer.slice(42, expectedTotalLen);
        const payloadKey = (await kdf(baseKey, [KDF_SALT.PAYLOAD_KEY, authId, nonce])).slice(0, 16);
        const payloadIv = (await kdf(baseKey, [KDF_SALT.PAYLOAD_IV, authId, nonce])).slice(0, 12);

        const cryptoPayloadKey = await crypto.subtle.importKey("raw", payloadKey, { name: "AES-GCM" }, false, ["decrypt"]);
        const headerPayload = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: payloadIv, additionalData: authId }, 
            cryptoPayloadKey, 
            payloadEnc
        );

        const headerView = new Uint8Array(headerPayload);
        
        if (headerView[0] !== 1) throw new Error("Invalid VMess version");

        const resIv = headerView.slice(1, 17);
        const resKey = headerView.slice(17, 33);
        const cmd = headerView[38]; 
        
        const port = (headerView[39] << 8) | headerView[40];
        const addrType = headerView[41];
        let cursor = 42;
        let address = '';

        if (addrType === 1) { 
            address = `${headerView[cursor]}.${headerView[cursor+1]}.${headerView[cursor+2]}.${headerView[cursor+3]}`;
            cursor += 4;
        } else if (addrType === 2) { 
            const domainLen = headerView[cursor];
            cursor += 1;
            address = new TextDecoder().decode(headerView.slice(cursor, cursor + domainLen));
            cursor += domainLen;
        }

        const isTcp = cmd === 1;
        const targetHost = proxyHost || address;
        const targetPort = proxyPort || port;

        if (isTcp) {
            const remoteSocket = connect({ hostname: targetHost, port: targetPort });
            const writer = remoteSocket.writable.getWriter();
            
            const rawData = buffer.slice(expectedTotalLen);
            if (rawData.length > 0) {
                await writer.write(rawData);
            }
            writer.releaseLock();

            remoteSocket.readable.pipeTo(new WritableStream({
                write(data) { if (server.readyState === 1) server.send(data); }
            })).catch(() => {});
        } else {
            server.close(1003, "UDP Not Supported");
        }
    } catch (err) {
        server.close(1011, `VMess Error: ${err.message}`);
    }
}

async function kdf(key, paths) {
    let current = await crypto.subtle.importKey(
        "raw", new TextEncoder().encode("VMess AEAD KDF"),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );

    for (const p of paths) {
        const pathBuf = typeof p === 'string' ? new TextEncoder().encode(p) : p;
        const signature = await crypto.subtle.sign("HMAC", current, pathBuf);
        current = await crypto.subtle.importKey(
            "raw", signature,
            { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        );
    }
    const keyBuf = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    const finalHash = await crypto.subtle.sign("HMAC", current, keyBuf);
    return new Uint8Array(finalHash);
}

function hexToBytes(hex) {
    let bytes = [];
    for (let c = 0; c < hex.length; c += 2) bytes.push(parseInt(hex.substr(c, 2), 16));
    return new Uint8Array(bytes);
}
