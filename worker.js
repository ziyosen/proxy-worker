// Konstanta RegEx
const PROXYIP_PATTERN = /^.+-\d+$/;
const PROXYKV_PATTERN = /^([A-Z]{2})/;

export default {
    async fetch(request, env, ctx) {
        try {
            const url = new URL(request.url);
            const host = url.host;
            const path = url.pathname;
            
            // UUID dari env vars wrangler.toml, dengan fallback jika kosong
            const uuid = env.UUID || "2bcfbfba-b446-4ad5-93ad-72af9e008f61"; 

            
            if (path === '/link') {
                return generateLinks(host, uuid);
            }

            
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

            // Upgrade WebSocket
            if (request.headers.get("Upgrade") === "websocket" && PROXYIP_PATTERN.test(proxyip)) {
                let [proxyHost, proxyPort] = proxyip.split('-');
                proxyPort = parseInt(proxyPort) || 443;

                return handleWebSocket(request, proxyHost, proxyPort, uuid);
            }

            return new Response("hi from js!", { status: 200 });
        } catch (err) {
            // Menghindari error 1101 (unhandled exception) dengan mengembalikan HTTP 500
            return new Response(`Worker Error: ${err.message}`, { status: 500 });
        }
    }
};

async function getProxyIPFromKV(kv, proxyipParam) {
    if (!kv) return proxyipParam; 
    
    const kvidList = proxyipParam.split(',');
    let proxyKvStr = await kv.get("proxy_kv");

    if (!proxyKvStr) {
        console.log("getting proxy kv from github...");
        // URL raw github
        const ghUrl = "https://raw.githubusercontent.com/ziyosen/tunel-worker/refs/heads/main/proxy.json";
        const res = await fetch(ghUrl);
        
        if (res.ok) {
            proxyKvStr = await res.text();
            // Simpan ke KV dengan TTL 12 jam (43200 detik)
            await kv.put("proxy_kv", proxyKvStr, { expirationTtl: 43200 });
        } else {
            throw new Error(`error getting proxy kv: ${res.status}`);
        }
    }

    const proxyKv = JSON.parse(proxyKvStr);
    
    // Randomize pemilihan indeks
    const randomByte = crypto.getRandomValues(new Uint8Array(1))[0];
    const kvIndex = randomByte % kvidList.length;
    const selectedKv = kvidList[kvIndex];
    
    if (!proxyKv[selectedKv] || proxyKv[selectedKv].length === 0) {
        return proxyipParam; 
    }

    const proxyipIndex = randomByte % proxyKv[selectedKv].length;
    // Format IP/Domain diubah dengan mengganti ":" menjadi "-"
    return proxyKv[selectedKv][proxyipIndex].replace(/:/g, "-");
}

function generateLinks(host, uuid) {
    // Pembuatan string konfigurasi Vmess, Vless, Trojan, Shadowsocks
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

function handleWebSocket(request, proxyHost, proxyPort, uuid) {
    const webSocketPair = new WebSocketPair();
    const [client, server] = Object.values(webSocketPair);
    
    server.accept();
    
    // Logika proxy akan ditambahkan di sini pada Fase 2
    server.addEventListener('message', async (event) => {
        // Blok ini masih kosong, kita isi di langkah selanjutnya
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}
