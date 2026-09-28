import { connect } from 'cloudflare:sockets';
import { parseAddr, parsePort } from '../utils/common.js';

export async function handleVless(server, buffer, wsReadable, proxyHost, proxyPort) {
    try {
        let cursor = 0;

        // 1. Lewati 1 versi byte
        cursor += 1;

        // 2. Lewati 16 byte UUID
        cursor += 16;

        // 3. Baca panjang protobuf lalu lewati
        const mLen = buffer[cursor];
        cursor += 1 + mLen;

        // 4. Baca tipe jaringan (1 = TCP)
        const networkType = buffer[cursor];
        cursor += 1;
        const isTcp = networkType === 1;

        // 5. Baca Port dan Alamat dari client
        const portRes = parsePort(buffer, cursor);
        const clientPort = portRes.port;
        cursor = portRes.cursor;

        const addrRes = parseAddr(buffer, cursor);
        const clientAddr = addrRes.address;
        cursor = addrRes.cursor;

        const rawData = buffer.subarray(cursor);

        if (isTcp) {
            // Terapkan addr_pool persis seperti di vless.rs: utamakan tujuan asli, lalu fallback ke proxy IP worker
            const addrPool = [
                { host: clientAddr, port: clientPort },
                { host: proxyHost, port: proxyPort }
            ];

            let remoteSocket = null;
            let connected = false;

            // Coba sambungkan secara berurutan sesuai pool
            for (const target of addrPool) {
                try {
                    if (!target.host || !target.port) continue;
                    const socket = connect({ hostname: target.host, port: target.port });
                    // Tes buka writer untuk memastikan socket benar-benar merespons
                    await socket.opened;
                    remoteSocket = socket;
                    connected = true;
                    break;
                } catch (e) {
                    // Lanjut ke target berikutnya di addr_pool jika gagal
                }
            }

            if (!connected || !remoteSocket) {
                throw new Error("All TCP outbound connections failed");
            }

            const writer = remoteSocket.writable.getWriter();

            // Kirim balasan header VLESS ke klien (2 byte kosong [0, 0])
            if (server.readyState === 1) {
                server.send(new Uint8Array([0, 0]));
            }

            if (rawData.length > 0) {
                await writer.write(rawData);
            }

            // Alirkan data dari WebSocket ke TCP remote secara aman
            (async () => {
                try {
                    const reader = wsReadable.getReader();
                    while (true) {
                        const { value, done } = await reader.read();
                        if (done) break;
                        if (value) {
                            await writer.write(value);
                        }
                    }
                } catch (e) {
                } finally {
                    try { writer.releaseLock(); } catch {}
                }
            })();

            // Alirkan data balik dari TCP remote ke WebSocket menggunakan getReader()
            (async () => {
                try {
                    const readerRemote = remoteSocket.readable.getReader();
                    while (true) {
                        const { value, done } = await readerRemote.read();
                        if (done) break;
                        if (value && server.readyState === 1) {
                            server.send(value);
                        }
                    }
                } catch (e) {
                }
            })();

        } else {
            if (server.readyState === 1) {
                server.close(1003, "UDP over VLESS not supported yet");
            }
        }
    } catch (err) {
        if (server.readyState === 1) {
            server.close(1011, "VLESS Parsing Error");
        }
    }
}
