
export async function kdf(key, path) {
    let currentKey = await crypto.subtle.importKey(
        "raw",
        new TextEncoder().encode("VMess AEAD KDF"),
        { name: "HMAC", hash: "SHA-256" },
        false,
        ["sign"]
    );

    for (const p of path) {
        const pBytes = typeof p === 'string' ? new TextEncoder().encode(p) : p;
        const sig = await crypto.subtle.sign("HMAC", currentKey, pBytes);
        currentKey = await crypto.subtle.importKey(
            "raw",
            sig,
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );
    }

    const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    const finalSig = await crypto.subtle.sign("HMAC", currentKey, keyBytes);
    
    return new Uint8Array(finalSig);
}
