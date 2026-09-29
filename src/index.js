import { connect } from "cloudflare:sockets";

let serviceName = "";
let APP_DOMAIN = "";
let prxIP = "";

const horse = "dHJvamFu";
const flash = "dm1lc3M=";

const KV_PRX_URL = "https://raw.githubusercontent.com/ziyosen/tunel-worker/refs/heads/main/proxy.json";
const DNS_SERVER_ADDRESS = "8.8.8.8";
const DNS_SERVER_PORT = 53;
const RELAY_SERVER_UDP = {
  host: "udp-relay.hobihaus.space",
  port: 7300,
};

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
const CORS_HEADER_OPTIONS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET,HEAD,POST,OPTIONS",
  "Access-Control-Max-Age": "86400",
};

async function getKVPrxList() {
  try {
    const res = await fetch(KV_PRX_URL);
    if (res.ok) {
      return await res.json();
    }
  } catch (e) {}
  return {};
}

async function getProxyFromPath(pathname) {
  if (!pathname || !pathname.startsWith('/Benxx-Project/')) {
    return null;
  }
  
  let proxyip = pathname.replace('/Benxx-Project/', '');
  if (!proxyip) return null;

  if (/^([A-Z]{2})/.test(proxyip)) {
    let kvidList = proxyip.split(',');
    let proxyKv = await getKVPrxList();
    const randomByte = crypto.getRandomValues(new Uint8Array(1))[0];
    const kvIndex = randomByte % kvidList.length;
    const selectedKv = kvidList[kvIndex];
    
    if (proxyKv[selectedKv] && proxyKv[selectedKv].length > 0) {
      const proxyipIndex = randomByte % proxyKv[selectedKv].length;
      return proxyKv[selectedKv][proxyipIndex].replace(/:/g, "-");
    }
  }
  
  const ipPortMatch = proxyip.match(/^([\d\.]+)[:=:-](\d+)$/);
  if (ipPortMatch) {
    return ipPortMatch[1] + ':' + ipPortMatch[2];
  }
  
  return null;
}

function generateLinks(host, uuid) {
  const samplePath = "/Benxx-Project/ID";
  
  const vmessConfig = {
    ps: "Benxx vmess", v: "2", add: host, port: "80", id: uuid, aid: "0",
    scy: "zero", net: "ws", type: "none", host: host, path: samplePath, tls: "", sni: host, alpn: ""
  };
  const base64Vmess = btoa(JSON.stringify(vmessConfig)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const vmessLink = `vmess://${base64Vmess}`;
  const vlessLink = `vless://${uuid}@${host}:443?encryption=none&type=ws&host=${host}&path=${encodeURIComponent(samplePath)}&security=tls&sni=${host}#Benxx vless`;
  const trojanLink = `trojan://${uuid}@${host}:443?security=tls&type=ws&host=${host}&path=${encodeURIComponent(samplePath)}&sni=${host}#Benxx trojan`;

  return new Response(`${vmessLink}\n${vlessLink}\n${trojanLink}`, {
    status: 200,
    headers: { "Content-Type": "text/plain;charset=utf-8", ...CORS_HEADER_OPTIONS }
  });
}

export default {
  async fetch(request, env, ctx) {
    try {
      const url = new URL(request.url);
      APP_DOMAIN = url.hostname;
      serviceName = APP_DOMAIN.split(".")[0];
      const uuid = env.UUID || "2bcfbfba-b446-4ad5-93ad-72af9e008f61"; 

      if (url.pathname === '/link') {
        return generateLinks(APP_DOMAIN, uuid);
      }

      const upgradeHeader = request.headers.get("Upgrade");
      if (upgradeHeader === "websocket") {
        if (!url.pathname.startsWith('/Benxx-Project/')) {
          return new Response("Unauthorized Path", { status: 403 });
        }

        const resolvedProxy = await getProxyFromPath(url.pathname);
        if (resolvedProxy) {
          prxIP = resolvedProxy.replace(/:/g, "-");
        } else {
          return new Response("Invalid Proxy Target in Path", { status: 400 });
        }

        return await websocketHandler(request);
      }

      return new Response("hi from wasm!", { status: 200, headers: CORS_HEADER_OPTIONS });
    } catch (err) {
      return new Response(`An error occurred: ${err.toString()}`, {
        status: 500,
        headers: { ...CORS_HEADER_OPTIONS },
      });
    }
  },
};

async function websocketHandler(request) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  let addressLog = "";
  let portLog = "";
  const log = (info, event) => {
    console.log(`[${addressLog}:${portLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";
  const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

  let remoteSocketWrapper = { value: null };
  let isDNS = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDNS) {
            return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, null, log, RELAY_SERVER_UDP);
          }
          if (remoteSocketWrapper.value) {
            const writer = remoteSocketWrapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const protocol = await protocolSniffer(chunk);
          let protocolHeader;

          if (protocol === atob(horse)) {
            protocolHeader = readHorseHeader(chunk);
          } else if (protocol === atob(flash)) {
            protocolHeader = readFlashHeader(chunk);
          } else {
            protocolHeader = readSsHeader(chunk);
          }

          addressLog = protocolHeader.addressRemote;
          portLog = `${protocolHeader.portRemote} -> ${protocolHeader.isUDP ? "UDP" : "TCP"}`;

          if (protocolHeader.hasError) {
            throw new Error(protocolHeader.message);
          }

          if (protocolHeader.isUDP) {
            if (protocolHeader.portRemote === 53) {
              isDNS = true;
              return handleUDPOutbound(DNS_SERVER_ADDRESS, DNS_SERVER_PORT, chunk, webSocket, protocolHeader.version, log, RELAY_SERVER_UDP);
            }
            return handleUDPOutbound(protocolHeader.addressRemote, protocolHeader.portRemote, chunk, webSocket, protocolHeader.version, log, RELAY_SERVER_UDP);
          }

          handleTCPOutBound(remoteSocketWrapper, protocolHeader.addressRemote, protocolHeader.portRemote, protocolHeader.rawClientData, webSocket, protocolHeader.version, log);
        },
      })
    )
    .catch((err) => {
      log("readableWebSocketStream pipeTo error", err);
    });

  return new Response(null, { status: 101, webSocket: client });
}

async function protocolSniffer(buffer) {
  if (buffer.byteLength >= 62) {
    const horseDelimiter = new Uint8Array(buffer.slice(56, 60));
    if (horseDelimiter[0] === 0x0d && horseDelimiter[1] === 0x0a) {
      return atob(horse);
    }
  }
  // Jika tidak memenuhi syarat Trojan, arahkan ke Flash (VMess) atau Shadowsocks/VLESS
  return atob(flash);
}

async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, responseHeader, log) {
  async function connectAndWrite(address, port) {
    const tcpSocket = connect({ hostname: address, port: port });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const targetHost = prxIP ? prxIP.split(/[:=-]/)[0] : addressRemote;
    const targetPort = prxIP ? parseInt(prxIP.split(/[:=-]/)[1]) : portRemote;
    const tcpSocket = await connectAndWrite(targetHost, targetPort);
    tcpSocket.closed.catch(() => {}).finally(() => safeCloseWebSocket(webSocket));
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, null, log);
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    remoteSocketToWS(tcpSocket, webSocket, responseHeader, retry, log);
  } catch (e) {
    retry();
  }
}

async function handleUDPOutbound(targetAddress, targetPort, dataChunk, webSocket, responseHeader, log, relay) {
  try {
    let protocolHeader = responseHeader;
    const tcpSocket = connect({ hostname: relay.host, port: relay.port });
    const header = `udp:${targetAddress}:${targetPort}`;
    const headerBuffer = new TextEncoder().encode(header);
    const separator = new Uint8Array([0x7c]);
    const relayMessage = new Uint8Array(headerBuffer.length + separator.length + dataChunk.byteLength);
    relayMessage.set(headerBuffer, 0);
    relayMessage.set(separator, headerBuffer.length);
    relayMessage.set(new Uint8Array(dataChunk), headerBuffer.length + separator.length);

    const writer = tcpSocket.writable.getWriter();
    await writer.write(relayMessage);
    writer.releaseLock();

    await tcpSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            if (protocolHeader) {
              webSocket.send(await new Blob([protocolHeader, chunk]).arrayBuffer());
              protocolHeader = null;
            } else {
              webSocket.send(chunk);
            }
          }
        },
      })
    );
  } catch (e) {}
}

function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  let readableStreamCancel = false;
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (!readableStreamCancel) controller.enqueue(event.data);
      });
      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (!readableStreamCancel) controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (earlyData) controller.enqueue(earlyData);
    },
    cancel() {
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });
}

function readSsHeader(ssBuffer) {
  const view = new DataView(ssBuffer);
  const addressType = view.getUint8(0);
  let addressLength = 0, addressValueIndex = 1, addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 4)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(ssBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(ssBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(":");
      break;
    default:
      return { hasError: true, message: "Invalid addressType" };
  }
  const portIndex = addressValueIndex + addressLength;
  const portRemote = new DataView(ssBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
  return {
    hasError: false, addressRemote: addressValue, addressType, portRemote,
    rawDataIndex: portIndex + 2, rawClientData: ssBuffer.slice(portIndex + 2), version: null, isUDP: portRemote == 53
  };
}

function readFlashHeader(buffer) {
  // Parser universal yang kompatibel untuk VMess / VLESS / Shadowsocks non-Trojan
  if (buffer.byteLength < 20) {
    return readSsHeader(buffer);
  }
  try {
    const version = new Uint8Array(buffer.slice(0, 1));
    const optLength = new Uint8Array(buffer.slice(17, 18))[0];
    const cmdIndex = 18 + optLength;
    const cmd = new Uint8Array(buffer.slice(cmdIndex, cmdIndex + 1))[0];
    const isUDP = (cmd === 2);
    
    const portIndex = cmdIndex + 1;
    const portRemote = new DataView(buffer.slice(portIndex, portIndex + 2)).getUint16(0);
    const addressIndex = portIndex + 2;
    const addressType = new Uint8Array(buffer.slice(addressIndex, addressIndex + 1))[0];
    
    let addressLength = 0, addressValueIndex = addressIndex + 1, addressValue = "";
    switch (addressType) {
      case 1:
        addressLength = 4;
        addressValue = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 4)).join(".");
        break;
      case 2:
      case 3:
        if (addressType === 2) {
          addressLength = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + 1))[0];
          addressValueIndex += 1;
        } else {
          addressLength = 16;
        }
        addressValue = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
      default:
        return readSsHeader(buffer);
    }
    
    const rawDataIndex = addressValueIndex + addressLength;
    return {
      hasError: false, addressRemote: addressValue, addressType, portRemote,
      rawDataIndex, rawClientData: buffer.slice(rawDataIndex), version: new Uint8Array([version[0], 0]), isUDP
    };
  } catch (e) {
    return readSsHeader(buffer);
  }
}

function readHorseHeader(buffer) {
  const dataBuffer = buffer.slice(58);
  if (dataBuffer.byteLength < 6) return { hasError: true, message: "invalid request data" };
  const view = new DataView(dataBuffer);
  const cmd = view.getUint8(0);
  const isUDP = (cmd == 3);
  const addressType = view.getUint8(1);
  let addressLength = 0, addressValueIndex = 2, addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 4)).join(".");
      break;
    case 3:
      addressLength = new Uint8Array(dataBuffer.slice(addressValueIndex, addressValueIndex + 1))[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      break;
    case 4:
      addressLength = 16;
      const dataView = new DataView(dataBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
      const ipv6 = [];
      for (let i = 0; i < 8; i++) ipv6.push(dataView.getUint16(i * 2).toString(16));
      addressValue = ipv6.join(":");
      break;
    default:
      return { hasError: true, message: "invalid addressType" };
  }
  const portIndex = addressValueIndex + addressLength;
  const portRemote = new DataView(dataBuffer.slice(portIndex, portIndex + 2)).getUint16(0);
  return {
    hasError: false, addressRemote: addressValue, addressType, portRemote,
    rawDataIndex: portIndex + 4, rawClientData: dataBuffer.slice(portIndex + 4), version: null, isUDP
  };
}

async function remoteSocketToWS(remoteSocket, webSocket, responseHeader, retry, log) {
  let header = responseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) controller.error("closed");
          if (header) {
            webSocket.send(await new Blob([header, chunk]).arrayBuffer());
            header = null;
          } else {
            webSocket.send(chunk);
          }
        },
      })
    )
    .catch(() => {
      safeCloseWebSocket(webSocket);
    });
  if (hasIncomingData === false && retry) retry();
}

function safeCloseWebSocket(socket) {
  try {
    if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
      socket.close();
    }
  } catch (error) {}
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { error: null };
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}
