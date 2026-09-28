import { connect } from 'cloudflare:sockets';
import { parseAddr, parsePort } from '../utils/common.js';

export async function handleTrojan(server, buffer, wsReadable, proxyHost, proxyPort) {
    try {
        let cursor = 0;
        
        cursor += 56;
        cursor += 2;

        const networkType = buffer[cursor];
        cursor += 1;
        const isTcp = networkType === 1;

        const addrResult = parseAddr(buffer, cursor);
        const address = addrResult.address;
        cursor = addrResult.cursor;

        const portResult = parsePort(buffer, cursor);
        const port = portResult.port;
        cursor = portResult.portCursor || portResult.cursor; 
        
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
            wsReadable.pipeTo(remoteSocket.writable).catch(() => {});

            remoteSocket.readable.pipeTo(new WritableStream({
                write(data) {
                    if (server.readyState === 1) {
                        server.send(data);
                    }
                }
            })).catch(() => {});
        } else {
            server.close(1003, "UDP over Trojan not supported yet");
        }
    } catch (err) {
        server.close(1011, "Trojan Parsing Error");
    }
}
