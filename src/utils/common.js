
export const KDFSALT = {
    VMESS_HEADER_PAYLOAD_LENGTH_AEAD_KEY: new TextEncoder().encode("VMess Header AEAD Key_Length"),
    VMESS_HEADER_PAYLOAD_LENGTH_AEAD_IV: new TextEncoder().encode("VMess Header AEAD Nonce_Length"),
    VMESS_HEADER_PAYLOAD_AEAD_KEY: new TextEncoder().encode("VMess Header AEAD Key"),
    VMESS_HEADER_PAYLOAD_AEAD_IV: new TextEncoder().encode("VMess Header AEAD Nonce"),
    AEAD_RESP_HEADER_LEN_KEY: new TextEncoder().encode("AEAD Resp Header Len Key"),
    AEAD_RESP_HEADER_LEN_IV: new TextEncoder().encode("AEAD Resp Header Len IV"),
    AEAD_RESP_HEADER_KEY: new TextEncoder().encode("AEAD Resp Header Key"),
    AEAD_RESP_HEADER_IV: new TextEncoder().encode("AEAD Resp Header IV"),
};

export function parseAddr(view, cursor) {
    const addrType = view[cursor];
    cursor += 1;
    let address = "";

    if (addrType === 1) { 
        address = `${view[cursor]}.${view[cursor+1]}.${view[cursor+2]}.${view[cursor+3]}`;
        cursor += 4;
    } else if (addrType === 2 || addrType === 3) { 
        const domainLen = view[cursor];
        cursor += 1;
        address = new TextDecoder().decode(view.subarray(cursor, cursor + domainLen));
        cursor += domainLen;
    } else if (addrType === 4) { 
        const ipv6Bytes = view.subarray(cursor, cursor + 16);
        const segments = [];
        for (let i = 0; i < 16; i += 2) {
            segments.push(((ipv6Bytes[i] << 8) | ipv6Bytes[i + 1]).toString(16));
        }
        address = segments.join(":");
        cursor += 16;
    } else {
        throw new Error("invalid address type");
    }

    return { address, cursor };
}

export function parsePort(view, cursor) {
    const port = (view[cursor] << 8) | view[cursor + 1];
    return { port, cursor: cursor + 2 };
}
