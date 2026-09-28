export async function sniffAndRoute(server, wsReadable, initialChunk, uuid, proxyHost, proxyPort) {
    
    if (isVless(initialChunk)) {
        console.log("vless detected!");
        
    } else if (isShadowsocks(initialChunk)) {
        console.log("shadowsocks detected!");
        
    } else if (isTrojan(initialChunk)) {
        console.log("trojan detected!");
        
    } else {
        console.log("vmess detected (fallback)!");
      
    }
}
function isVless(buffer) {
    return buffer.length > 0 && buffer[0] === 0;
}
function isShadowsocks(buffer) {
    if (buffer.length === 0) return false;
    const type = buffer[0];
    if (type === 1) { 
        if (buffer.length < 7) return false;
        const port = (buffer[5] << 8) | buffer[6];
        return port !== 0;
    } else if (type === 3) { 
        if (buffer.length < 2) return false;
        const domainLen = buffer[1];
        if (buffer.length < 2 + domainLen + 2) return false;
        const port = (buffer[2 + domainLen] << 8) | buffer[2 + domainLen + 1];
        return port !== 0;
    } else if (type === 4) { 
        if (buffer.length < 19) return false;
        const port = (buffer[17] << 8) | buffer[18];
        return port !== 0;
    }
    return false;
}

function isTrojan(buffer) {
    return buffer.length > 57 && buffer[56] === 13 && buffer[57] === 10;
}

function isVmess(buffer) {
    return buffer.length > 0;
}
