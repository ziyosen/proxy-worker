import { connect } from 'cloudflare:sockets';
import { parseAddr, parsePort } from '../utils/common.js';

export async function handleVless(server, buffer, wsReadable, proxyHost, proxyPort) {
    try {
        let cursor = 0;

        
        cursor += 1;

        cursor += 16;

    
        const mLen = buffer[cursor];
        cursor += 1 + mLen;

        
        const networkType = buffer[cursor];
        cursor += 1;
        const isTcp = networkType === 1;

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

            server.send(new Uint8Array([0, 0]));

            if (rawData.length > 0) {
                await writer.write(rawData);
            }
            writer.releaseLock();

            
            wsReadable.pipeTo(remoteSocket.writable).catch(() => {});

            remoteSocket.readable.pipeTo(new WritableStream({
                write(data) {
                    if (server.readyState === 1) {
                        server.send(data);
                    }
                }
            })).catch(() => {});
        } else {
            server.close(1003, "UDP over VLESS not supported yet");
        }
    } catch (err) {
        server.close(1011, "VLESS Parsing Error");
    }
}
