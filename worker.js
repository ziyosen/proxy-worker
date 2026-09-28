import { connect } from 'cloudflare:sockets';

const PROXYIP_PATTERN = /^.+-\d+$/;
const PROXYKV_PATTERN = /^([A-Z]{2})/;

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const host = url.host;
            const path = url.pathname;
            
            const uuid = env.UUID || "2bcfbfba-b446-4ad5-93ad-72af9e008f61"; 

            // Endpoint Generator Link
            if (path === '/link') {
                return generateLinks(host, uuid);
            }

            // Routing path
            let proxyip = "";
            if (path.startsWith('/Benxx-Project/')) {
                proxyip = path.replace('/Benxx-Project/', '');
            } else {
                proxyip = path.substring(1); 
            }

            if (!proxyip) {
                return new Response("hi from js!", { status: 200 });
            }

            // Logika KV YUMI
            if (PROXYKV_PATTERN.test(proxyip)) {
                proxyip = await getProxyIPFromKV(env.YUMI, proxyip);
            }

            // Upgrade WebSocket & eksekusi Tunnel
            if (request.headers.get("Upgrade") === "websocket" && PROXYIP_PATTERN.test(proxyip)) {
                let [proxyHost, proxyPort] = proxyip.split('-');
                proxyPort = parseInt(proxyPort) || 443;

                return handleWebSocket(request, proxyHost, proxyPort, uuid);
            }

            return new Response("hi from js!", { status: 200 });
        } catch (err) {
            return new Response(`Worker Error: ${err.message}`, { status: 500 });
        }
    }
};

async function getProxyIPFromKV(kv, proxyipParam) {
    if (!kv) return proxyipParam; 
    
    const kvidList = proxyipParam.split(',');
    let proxyKvStr = await kv.get("proxy_kv");

    if (!proxyKvStr) {
        const ghUrl = "https://raw.githubusercontent.com/ziyosen/tunel-worker/refs/heads/main/proxy.json";
        const res = await fetch(ghUrl);
        
        if (res.ok) {
            proxyKvStr = await res.text();
            await kv.put("proxy_kv", proxyKvStr, { expirationTtl: 43200 });
        } else {
            throw new Error(`error getting proxy kv: ${res.status}`);
        }
    }

    const proxyKv = JSON.parse(proxyKvStr);
    const randomByte = crypto.getRandomValues(new Uint8Array(1))[0];
    const kvIndex = randomByte % kvidList.length;
    const selectedKv = kvidList[kvIndex];
    
    if (!proxyKv[selectedKv] || proxyKv[selectedKv].length === 0) {
        return proxyipParam; 
    }

    const proxyipIndex = randomByte % proxyKv[selectedKv].length;
    return proxyKv[selectedKv][proxyipIndex].replace(/:/g, "-");
}

function generateLinks(host, uuid) {
    const vmessConfig = {
        ps: "Changli vmess",
        v: "2",
        add: host,
        port: "80",
        id: uuid,
        aid: "0",
        scy: "zero",
        net: "ws",
        type: "none",
        host: host,
        path: "/ID",
        tls: "",
        sni: host,
        alpn: ""
    };
    
    const vmessLink = `vmess://${btoa(JSON.stringify(vmessConfig))}`;
    const vlessLink = `vless://${uuid}@${host}:443?encryption=none&type=ws&host=${host}&path=%2FID&security=tls&sni=${host}#Changli vless`;
    const trojanLink = `trojan://${uuid}@${host}:443?encryption=none&type=ws&host=${host}&path=%2FID&security=tls&sni=${host}#Changli trojan`;
    const ssLink = `ss://${btoa(`none:${uuid}`)}@${host}:443?plugin=v2ray-plugin%3Btls%3Bmux%3D0%3Bmode%3Dwebsocket%3Bpath%3D%2FID%3Bhost%3D${host}#Changli ss`;

    return new Response(`${vmessLink}\n${vlessLink}\n${trojanLink}\n${ssLink}`, {
        status: 200,
        headers: { "Content-Type": "text/plain;charset=utf-8" }
    });
}

function handleWebSocket(request, proxyHost, proxyPort, rawUuid) {
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    
    server.accept();
    
    let remoteSocket = null;

    // Membaca stream WebSocket dari client
    const wsReadable = new ReadableStream({
        start(controller) {
            server.addEventListener('message', (event) => {
                if (typeof event.data !== 'string') {
                    controller.enqueue(new Uint8Array(event.data));
                }
            });
            server.addEventListener('close', () => controller.close());
            server.addEventListener('error', (e) => controller.error(e));
        }
    });

    const reader = wsReadable.getReader();

    // Pemrosesan paket
    (async () => {
        try {
            const { value: chunk, done } = await reader.read();
            if (done || !chunk) return;

            // Parsing Header Protokol (VLESS / Trojan / SS / VMess)
            const parsed = parseProtocolHeader(chunk);
            if (!parsed) {
                server.close(1003, "Unsupported or Invalid Protocol Header");
                return;
            }

            // Gunakan Proxy IP/Port dari KV jika tersedia, atau target langsung
            const targetHost = proxyHost || parsed.address;
            const targetPort = proxyPort || parsed.port;

            // Membuka Socket TCP Native V8 (Mencegah Error 1101 WASM)
            remoteSocket = connect({
                hostname: targetHost,
                port: targetPort
            });

            const writer = remoteSocket.writable.getWriter();

            // Balasan khusus VLESS header (2 byte response header)
            if (parsed.protocol === 'VLESS') {
                server.send(new Uint8Array([0, 0]));
            }

            // Tulis data awal yang tersisa ke remote socket
            if (parsed.rawData && parsed.rawData.length > 0) {
                await writer.write(parsed.rawData);
            }
            writer.releaseLock();

            // Piping Bidireksional (Pipa Dua Arah)
            // WebSocket -> Remote TCP Socket
            wsReadable.pipeTo(remoteSocket.writable).catch(() => {});

            // Remote TCP Socket -> WebSocket
            remoteSocket.readable.pipeTo(new WritableStream({
                write(data) {
                    if (server.readyState === 1) { // 1 = OPEN
                        server.send(data);
                    }
                },
                close() {
                    if (server.readyState === 1) server.close(1000, "Normal Closure");
                },
                abort() {
                    if (server.readyState === 1) server.close(1006, "Abnormal Closure");
                }
            })).catch(() => {});

        } catch (err) {
            if (server.readyState === 1) {
                server.close(1011, `Internal Error: ${err.message}`);
            }
        }
    })();

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

function parseProtocolHeader(buffer) {
    if (!buffer || buffer.length < 10) return null;

    // 1. Sniffing VLESS (Byte pertama 0)
    if (buffer[0] === 0) {
        let cursor = 1; // skip version
        cursor += 16;   // skip UUID (16 bytes)
        
        const optLen = buffer[cursor];
        cursor += 1 + optLen; // skip option protobuf length

        const command = buffer[cursor]; // 1 = TCP, 2 = UDP
        cursor += 1;

        const port = (buffer[cursor] << 8) | buffer[cursor + 1];
        cursor += 2;

        const addrType = buffer[cursor];
        cursor += 1;

        let address = '';
        if (addrType === 1) { // IPv4
            address = `${buffer[cursor]}.${buffer[cursor+1]}.${buffer[cursor+2]}.${buffer[cursor+3]}`;
            cursor += 4;
        } else if (addrType === 2 || addrType === 3) { // Domain
            const domainLen = buffer[cursor];
            cursor += 1;
            address = new TextDecoder().decode(buffer.subarray(cursor, cursor + domainLen));
            cursor += domainLen;
        } else if (addrType === 4) { // IPv6
            address = Array.from(buffer.subarray(cursor, cursor + 16))
                .map((b, i) => (i % 2 === 0 ? ((b << 8) | buffer[cursor + i + 1]).toString(16) : null))
                .filter(Boolean).join(':');
            cursor += 16;
        }

        return {
            protocol: 'VLESS',
            address,
            port,
            isTcp: command === 1,
            rawData: buffer.subarray(cursor)
        };
    }

    // 2. Sniffing Trojan (Hex CRLF 0x0D 0x0A pada byte ke-56 dan 57)
    if (buffer.length > 58 && buffer[56] === 13 && buffer[57] === 10) {
        let cursor = 56 + 2; // Skip hash + CRLF
        const command = buffer[cursor]; // 1 = TCP
        cursor += 1;

        const addrType = buffer[cursor];
        cursor += 1;

        let address = '';
        if (addrType === 1) {
            address = `${buffer[cursor]}.${buffer[cursor+1]}.${buffer[cursor+2]}.${buffer[cursor+3]}`;
            cursor += 4;
        } else if (addrType === 3) {
            const domainLen = buffer[cursor];
            cursor += 1;
            address = new TextDecoder().decode(buffer.subarray(cursor, cursor + domainLen));
            cursor += domainLen;
        }

        const port = (buffer[cursor] << 8) | buffer[cursor + 1];
        cursor += 2;
        cursor += 2; // Skip CRLF penutup header

        return {
            protocol: 'Trojan',
            address,
            port,
            isTcp: command === 1,
            rawData: buffer.subarray(cursor)
        };
    }

    // Fallback passthrough
    return null;
}
