
export async function doh(reqWireformat) {
    const response = await fetch("https://1.1.1.1/dns-query", {
        method: "POST",
        headers: {
            "Content-Type": "application/dns-message",
            "Accept": "application/dns-message"
        },
        body: reqWireformat
    });

    if (!response.ok) {
        throw new Error(`DoH request failed: ${response.status}`);
    }

    return await response.arrayBuffer();
}
