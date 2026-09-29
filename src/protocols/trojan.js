import { connect } from 'cloudflare:sockets';
import { parseAddr, parsePort } from '../utils/common.js';

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
            socket.close();
        }
    } catch (error) {}
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry) {
    let header = responseHeader;
    let hasIncomingData = false;
    
    await remoteSocket.readable.pipeTo(
        new WritableStream({
            start() {},
            async write(chunk, controller) {
                hasIncomingData = true;
                if (webSocket.readyState !== WS_READY_STATE_OPEN) {
                    controller.error("webSocket is not open");
                }
                if (header) {
                    webSocket.send(await new Blob([header, chunk]).arrayBuffer());
                    header = null;
                } else {
                    webSocket.send(chunk);
                }
            },
            close() {},
            abort() {},
        })
    ).catch(() => {
        safeCloseWebSocket(webSocket);
    });

    if (hasIncomingData === false && retry) {
        retry();
    }
}

export async function handleTrojan(server, buffer, wsReadable, proxyHost, proxyPort) {
    try {
        let cursor = 0;
        
        // Lewati 56 byte hash user ID Trojan
        cursor += 56;
        
        // Lewati 2 byte CRLF pertama (\r\n)
        cursor += 2;

        // Baca tipe jaringan (1 = TCP)
        const networkType = buffer[cursor];
        cursor += 1;
        const isTcp = networkType === 1;

        // Baca Alamat terlebih dahulu
        const addrResult = parseAddr(buffer, cursor);
        const address = addrResult.address;
        cursor = addrResult.cursor;

        // Baca Port setelah alamat
        const portResult = parsePort(buffer, cursor);
        const port = portResult.port;
        cursor = portResult.cursor; 
        
        // Lewati 2 byte CRLF penutup header (\r\n)
        cursor += 2;

        const rawData = buffer.subarray(cursor);

        if (isTcp) {
            // Trojan tidak memerlukan header balasan seperti VLESS, jadi dikosongkan (null)
            const responseHeader = null;
            let remoteSocketWrapper = { value: null };

            // Fungsi pembuka soket 
            async function connectAndWrite(targetAddress, targetPort) {
                if (!targetAddress || !targetPort) throw new Error("Invalid target");
                const tcpSocket = connect({ hostname: targetAddress, port: targetPort });
                remoteSocketWrapper.value = tcpSocket;
                
                const writer = tcpSocket.writable.getWriter();
                if (rawData.length > 0) {
                    await writer.write(rawData);
                }
                writer.releaseLock();
                
                return tcpSocket;
            }

            // Fungsi fallback ke proxy worker jika target pertama gagal atau timeout
            async function retryFallback() {
                try {
                    const tcpSocket = await connectAndWrite(proxyHost, proxyPort);
                    tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(server));
                    remoteSocketToWS(tcpSocket, server, responseHeader, null);
                } catch (e) {
                    safeCloseWebSocket(server);
                }
            }

            try {
                // Percobaan pertama ke alamat asli klien
                const tcpSocket = await connectAndWrite(address, port);
                remoteSocketToWS(tcpSocket, server, responseHeader, retryFallback);
            } catch (e) {
                // Jika langsung error, lempar ke proxy cadangan
                retryFallback();
            }

            // Alirkan data dari WebSocket ke TCP remote
            wsReadable.pipeTo(new WritableStream({
                async write(chunk) {
                    if (remoteSocketWrapper.value) {
                        const writer = remoteSocketWrapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                    }
                },
                close() {}, abort() {}
            })).catch(() => {});

        } else {
            if (server.readyState === WS_READY_STATE_OPEN) {
                server.close(1003, "UDP over Trojan not supported yet");
            }
        }
    } catch (err) {
        if (server.readyState === WS_READY_STATE_OPEN) {
            server.close(1011, "Trojan Parsing Error");
        }
    }
}
