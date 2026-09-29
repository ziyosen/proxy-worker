import { sniffAndRoute } from './utils/conn.js';

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

            if (!proxyip) {
                return new Response("hi from wasm!", { status: 200 });
            }

            if (PROXYKV_PATTERN.test(proxyip)) {
                proxyip = await getProxyIPFromKV(env.YUMI, proxyip);
            }

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
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    
    webSocket.accept();

    let readableStreamCancel = false;
    
    const wsReadable = new ReadableStream({
        start(controller) {
            webSocket.addEventListener('message', (event) => {
                if (!readableStreamCancel && typeof event.data !== 'string') {
                    controller.enqueue(new Uint8Array(event.data));
                }
            });
            webSocket.addEventListener('close', () => {
                if (!readableStreamCancel) {
                    readableStreamCancel = true;
                    try { controller.close(); } catch {}
                }
            });
            webSocket.addEventListener('error', (err) => {
                if (!readableStreamCancel) controller.error(err);
            });

            const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
            if (earlyDataHeader) {
                try {
                    const decode = atob(earlyDataHeader.replace(/-/g, "+").replace(/_/g, "/"));
                    const earlyData = Uint8Array.from(decode, c => c.charCodeAt(0));
                    controller.enqueue(earlyData);
                } catch (e) {}
            }
        },
        cancel(reason) {
            readableStreamCancel = true;
            try { webSocket.close(); } catch {}
        }
    });

    const reader = wsReadable.getReader();

    (async () => {
        try {
            const { value: initialChunk, done } = await reader.read();
            if (done || !initialChunk) return;

            reader.releaseLock();

            await sniffAndRoute(webSocket, wsReadable, initialChunk, uuid, proxyHost, proxyPort);

        } catch (err) {
            try { reader.releaseLock(); } catch {}
            if (webSocket.readyState === 1) {
                try { webSocket.close(1011, err.message); } catch {}
            }
        }
    })();

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}
