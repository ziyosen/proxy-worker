import { connect } from 'cloudflare:sockets';

export async function handleVless(server, buffer, wsReadable, proxyHost, proxyPort) {
    try {
        let cursor = 1; 
        cursor += 16;   
        
        const optLen = buffer[cursor];
        cursor += 1 + optLen; 

        const isTcp = buffer[cursor] === 1; 
        cursor += 1;

        const port = (buffer[cursor] << 8) | buffer[cursor + 1];
        cursor += 2;

        const addrType = buffer[cursor];
        cursor += 1;

        let address = '';
        if (addrType === 1) { 
            address = `${buffer[cursor]}.${buffer[cursor+1]}.${buffer[cursor+2]}.${buffer[cursor+3]}`;
            cursor += 4;
        } else if (addrType === 2 || addrType === 3) { 
            const domainLen = buffer[cursor];
            cursor += 1;
            address = new TextDecoder().decode(buffer.subarray(cursor, cursor + domainLen));
            cursor += domainLen;
        } else if (addrType === 4) { 
            address = Array.from(buffer.subarray(cursor, cursor + 16))
                .map((b, i) => (i % 2 === 0 ? ((b << 8) | buffer[cursor + i + 1]).toString(16) : null))
                .filter(Boolean).join(':');
            cursor += 16;
        }

        const rawData = buffer.subarray(cursor);
        const targetHost = proxyHost || address;
        const targetPort = proxyPort || port;

        if (isTcp) {
            const remoteSocket = connect({ hostname: targetHost, port: targetPort });
            const writer = remoteSocket.writable.getWriter();
            
            server.send(new Uint8Array([0, 0]));

            if (rawData.length > 0) {
                await writer.write(rawData);
            }
            writer.releaseLock();

            // Pipa WebSocket -> Remote
            wsReadable.pipeTo(remoteSocket.writable).catch(() => {});

            // Pipa Remote -> WebSocket
            remoteSocket.readable.pipeTo(new WritableStream({
                write(data) { if (server.readyState === 1) server.send(data); }
            })).catch(() => {});
        } else {
            server.close(1003, "UDP Not Supported");
        }
    } catch (err) {
        server.close(1011, "VLESS Parsing Error");
    }
}
