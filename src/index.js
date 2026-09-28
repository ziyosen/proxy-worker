import { handleVless } from './protocols/vless.js';
import { handleTrojan } from './protocols/trojan.js';
import { handleVmess } from './protocols/vmess.js';

const PROXYIP_PATTERN = /^.+-\d+$/;
const PROXYKV_PATTERN = /^([A-Z]{2})/;

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const host = url.host;
            const path = url.pathname;
            
            const uuid = env.UUID || "2bcfbfba-b446-4ad5-93ad-72af9e008f61"; 

            if (path === '/link') {
                return generateLinks(host, uuid);
            }

            let proxyip = "";
            if (path.startsWith('/Benxx-Project/')) {
                proxyip = path.replace('/Benxx-Project/', '');
            } else if (path !== '/' && path !== '') {
                proxyip = path.substring(1); 
            }

            // Jika tidak ada proxyip atau hanya root, kembalikan respon standar seperti "hi from wasm!"
            if (!proxyip) {
                return new Response("hi from wasm!", { status: 200 });
            }

            if (PROXYKV_PATTERN.test(proxyip)) {
                proxyip = await getProxyIPFromKV(env.YUMI, proxyip);
            }

            // Validasi persis seperti logika Rust: pastikan request websocket dan format proxyip valid (IP-Port)
            if (request.headers.get("Upgrade") === "websocket" && PROXYIP_PATTERN.test(proxyip)) {
                let [proxyHost, proxyPort] = proxyip.split('-');
                proxyPort = parseInt(proxyPort) || 443;

                return handleWebSocket(request, proxyHost, proxyPort, uuid);
            }

            return new Response("hi from wasm!", { status: 200 });
        } catch (err) {
            return new Response(`Worker Error: ${err.message}`, { status: 500 });
        }
    }
};

async function getProxyIPFromKV(kv, proxyipParam) {
    if (!kv) return proxyipParam; 
    
    let kvidList = proxyipParam.split(',');
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
    
    const base64Vmess = btoa(JSON.stringify(vmessConfig)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    const vmessLink = `vmess://${base64Vmess}`;
    
    const vlessLink = `vless://${uuid}@${host}:443?encryption=none&type=ws&host=${host}&path=%2FID&security=tls&sni=${host}#Changli vless`;
    const trojanLink = `trojan://${uuid}@${host}:443?encryption=none&type=ws&host=${host}&path=%2FID&security=tls&sni=${host}#Changli trojan`;

    const bodyContent = `${vmessLink}\n${vlessLink}\n${trojanLink}`;
    return new Response(bodyContent, {
        status: 200,
        headers: { "Content-Type": "text/plain;charset=utf-8" }
    });
}

function handleWebSocket(request, proxyHost, proxyPort, uuid) {
    let released = false;
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    
    server.accept();

    const wsReadable = new ReadableStream({
        start(controller) {
            server.addEventListener('message', (event) => {
                if (typeof event.data !== 'string') {
                    try {
                        controller.enqueue(new Uint8Array(event.data));
                    } catch (e) {}
                }
            });
            server.addEventListener('close', () => {
                try { controller.close(); } catch {}
            });
            server.addEventListener('error', (e) => {
                try { controller.error(e); } catch {}
            });
        }
    });

    const reader = wsReadable.getReader();

    (async () => {
        try {
            const { value: chunk, done } = await reader.read();
            if (done || !chunk) return;

            if (!released) {
                reader.releaseLock();
                released = true;
            }

            const combinedStream = new ReadableStream({
                start(controller) {
                    controller.enqueue(chunk);
                    (async () => {
                        try {
                            while (true) {
                                const { value, done } = await reader.read();
                                if (done) break;
                                controller.enqueue(value);
                            }
                        } catch (err) {
                            controller.error(err);
                        } finally {
                            controller.close();
                        }
                    })();
                }
            });

            if (chunk[0] === 0) {
                await handleVless(server, chunk, combinedStream, proxyHost, proxyPort);
            } else if (chunk.length > 57 && chunk[56] === 13 && chunk[57] === 10) {
                await handleTrojan(server, chunk, combinedStream, proxyHost, proxyPort);
            } else {
                await handleVmess(server, chunk, uuid, combinedStream, proxyHost, proxyPort);
            }
        } catch (err) {
            if (!released) {
                try { reader.releaseLock(); } catch {}
            }
            if (server.readyState === 1) {
                try { server.close(1011, err.message); } catch {}
            }
        }
    })();

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}
