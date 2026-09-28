
import { connect } from 'cloudflare:sockets';

export async function handleTrojan(server, buffer, proxyHost, proxyPort) {
    try {
        let cursor = 58; 
        const isTcp = buffer[cursor] === 1; 
        cursor += 1;

        // Tipe alamat[span_15](start_span)[span_15](end_span)
        const addrType = buffer[cursor];
        cursor += 1;

        let address = '';
        if (addrType === 1) { // IPv4
            address = `${buffer[cursor]}.${buffer[cursor+1]}.${buffer[cursor+2]}.${buffer[cursor+3]}`;
            cursor += 4;
        } else if (addrType === 3) { // Domain
            const domainLen = buffer[cursor];
            cursor += 1;
            address = new TextDecoder().decode(buffer.subarray(cursor, cursor + domainLen));
            cursor += domainLen;
        }

        // Membaca port jarak jauh[span_16](start_span)[span_16](end_span)
        const port = (buffer[cursor] << 8) | buffer[cursor + 1];
        cursor += 2;
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
            remoteSocket.readable.pipeTo(new WritableStream({
                write(data) { if (server.readyState === 1) server.send(data); }
            })).catch(() => {});
        } else {
            server.close(1003, "UDP over Trojan not fully implemented in JS yet");
        }
    } catch (err) {
        server.close(1011, "Trojan Parsing Error");
    }
}
