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

        // 5. Baca Port dan Alamat
        const portRes = parsePort(buffer, cursor);
        const port = portRes.port;
        cursor = portRes.cursor;

        const addrRes = parseAddr(buffer, cursor);
        const address = addrRes.address;
        cursor = addrRes.cursor;

        const rawData = buffer.subarray(cursor);
        const targetHost = proxyHost || address;
        const targetPort = proxyPort || port;

        if (isTcp) {
            const remoteSocket = connect({ hostname: targetHost, port: targetPort });
            const writer = remoteSocket.writable.getWriter();

            // Kirim balasan header VLESS ke klien
            if (server.readyState === 1) {
                server.send(new Uint8Array([0, 0]));
            }

            if (rawData.length > 0) {
                await writer.write(rawData);
            }
            writer.releaseLock();

            // Alirkan data dari WebSocket ke TCP remote secara aman
            wsReadable.pipeTo(new WritableStream({
                async write(chunk) {
                    const w = remoteSocket.writable.getWriter();
                    await w.write(chunk);
                    w.releaseLock();
                },
                abort(err) {
                    try { remoteSocket.close(); } catch {}
                }
            })).catch(() => {});

            // Alirkan data balik dari TCP remote ke WebSocket
            remoteSocket.readable.pipeTo(new WritableStream({
                write(data) {
                    if (server.readyState === 1) {
                        try {
                            server.send(data);
                        } catch (e) {}
                    }
                }
            })).catch(() => {});
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
