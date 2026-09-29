import { handleVless } from './vless.js';
import { handleTrojan } from './trojan.js';
import { handleVmess } from './vmess.js';

export async function sniffAndRoute(server, wsReadable, initialChunk, uuid, proxyHost, proxyPort) {
    
    if (isTrojan(initialChunk)) {
        console.log("Trojan detected!");
        return handleTrojan(server, initialChunk, wsReadable, proxyHost, proxyPort);
        
    } else if (isVless(initialChunk)) {
        console.log("VLESS detected!");
        return handleVless(server, initialChunk, wsReadable, proxyHost, proxyPort);
        
    } else if (isShadowsocks(initialChunk)) {
        console.log("Shadowsocks detected!");
        // return handleShadowsocks(server, initialChunk, wsReadable, proxyHost, proxyPort);
        
    } else {
        console.log("VMess detected (fallback)!");
        // VMess AEAD sangat bergantung pada UUID untuk membuat kunci dekripsi
        return handleVmess(server, initialChunk, uuid, wsReadable, proxyHost, proxyPort);
    }
}

function isTrojan(buffer) {
    // Trojan selalu diawali 56 byte hash, diikuti CRLF (13, 10), lalu byte Command (1 = TCP, 3 = UDP)
    return buffer.length >= 59 && buffer[56] === 13 && buffer[57] === 10 && (buffer[58] === 1 || buffer[58] === 3);
}

function isVless(buffer) {
    // VLESS versi 0 selalu dimulai dengan byte 0. Kita tambah syarat panjang minimal agar tidak salah deteksi.
    return buffer.length > 24 && buffer[0] === 0;
}

function isShadowsocks(buffer) {
    if (buffer.length === 0) return false;
    const type = buffer[0];
    
    if (type === 1) { // IPv4
        if (buffer.length < 7) return false;
        const port = (buffer[5] << 8) | buffer[6];
        return port !== 0;
    } else if (type === 3) { // Domain
        if (buffer.length < 2) return false;
        const domainLen = buffer[1];
        if (buffer.length < 2 + domainLen + 2) return false;
        const port = (buffer[2 + domainLen] << 8) | buffer[2 + domainLen + 1];
        return port !== 0;
    } else if (type === 4) { // IPv6
        if (buffer.length < 19) return false;
        const port = (buffer[17] << 8) | buffer[18];
        return port !== 0;
    }
    
    return false;
}

function isVmess(buffer) {
    
    return buffer.length > 0;
}
