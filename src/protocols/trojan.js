import { connect } from 'cloudflare:sockets';
import { parseAddr, parsePort } from '../utils/common.js';

export async function handleTrojan(server, buffer, wsReadable, proxyHost, proxyPort) {
    try {
        let cursor = 0;
        
        // Lewati 56 byte hash user ID Trojan[span_0](start_span)[span_0](end_span)
        cursor += 56;
        
        // Lewati 2 byte CRLF pertama (\r\n)[span_1](start_span)[span_1](end_span)
        cursor += 2;

        // Baca tipe jaringan (1 = TCP)[span_2](start_span)[span_2](end_span)
        const networkType = buffer[cursor];
        cursor += 1;
        const isTcp = networkType === 1;

        // Baca Alamat terlebih dahulu sesuai urutan trojan.rs[span_3](start_span)[span_3](end_span)
        const addrResult = parseAddr(buffer, cursor);
        const address = addrResult.address;
        cursor = addrResult.cursor;

        // Baca Port setelah alamat[span_4](start_span)[span_4](end_span)
        const portResult = parsePort(buffer, cursor);
        const port = portResult.port;
        cursor = portResult.cursor; 
        
        // Lewati 2 byte CRLF penutup header (\r\n)[span_5](start_span)[span_5](end_span)
        cursor += 2;

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

            // Alirkan data dari WebSocket ke TCP remote secara aman per chunk
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

            // Alirkan data balik dari TCP remote ke WebSocket dengan pengecekan state
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
                server.close(1003, "UDP over Trojan not supported yet");
            }
        }
    } catch (err) {
        if (server.readyState === 1) {
            server.close(1011, "Trojan Parsing Error");
        }
    }
}
