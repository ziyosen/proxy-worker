
export async function doh(reqWireformat) {
    const response = await fetch("https://1.1.1.1/dns-query", {
        method: "POST",
        headers: {
            "content-type": "application/dns-message",
            "accept": "application/dns-message",
        },
        body: reqWireformat,
    });

    if (!response.ok) {
        throw new Error(`DoH request failed with status: ${response.status}`);
    }

    const arrayBuffer = await response.arrayBuffer();
    return new Uint8Array(arrayBuffer);
}
