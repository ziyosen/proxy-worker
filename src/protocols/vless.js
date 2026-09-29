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
                    // Gabungkan header 2 byte dengan chunk pertama agar aman
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

    // Jika tidak ada data masuk, picu fungsi retry ke proxy cadangan
    if (hasIncomingData === false && retry) {
        retry();
    }
}

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
            const responseHeader = new Uint8Array([0, 0]);
            let remoteSocketWrapper = { value: null };

            // Fungsi pembuka soket (meniru handleTCPOutBound)
            async function connectAndWrite(address, port) {
                if (!address || !port) throw new Error("Invalid target");
                const tcpSocket = connect({ hostname: address, port: port });
                remoteSocketWrapper.value = tcpSocket;
                
                const writer = tcpSocket.writable.getWriter();
                if (rawData.length > 0) {
                    await writer.write(rawData);
                }
                writer.releaseLock();
                
                return tcpSocket;
            }

            // Fungsi fallback ke proxy worker jika target pertama gagal
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
                const tcpSocket = await connectAndWrite(clientAddr, clientPort);
                remoteSocketToWS(tcpSocket, server, responseHeader, retryFallback);
            } catch (e) {
                // Jika langsung error, lempar ke proxy cadangan
                retryFallback();
            }

            // Alirkan data dari WebSocket ke TCP remote menggunakan pipeTo agar tidak memory leak
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
                server.close(1003, "UDP over VLESS not supported yet");
            }
        }
    } catch (err) {
        if (server.readyState === WS_READY_STATE_OPEN) {
            server.close(1011, "VLESS Parsing Error");
        }
    }
}
