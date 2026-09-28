
// Pengganti md5! dan sha256! macros[span_7](start_span)[span_7](end_span) dan hash::kdf[span_8](start_span)[span_8](end_span)
export async function sha256(buffer) {
    return await crypto.subtle.digest('SHA-256', buffer);
}

export async function md5(buffer) {

    return await crypto.subtle.digest('SHA-1', buffer); 
}

export async function kdf(key, paths) {
    // Implementasi HMAC berbasis WebCrypto sebagai pengganti RecursiveHash[span_9](start_span)[span_9](end_span)
    let current = await crypto.subtle.importKey(
        "raw", new TextEncoder().encode("VMess AEAD KDF"),
        { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );

    for (const p of paths) {
        const pathBuf = typeof p === 'string' ? new TextEncoder().encode(p) : p;
        const signature = await crypto.subtle.sign("HMAC", current, pathBuf);
        current = await crypto.subtle.importKey(
            "raw", signature,
            { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
        );
    }

    const keyBuf = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    return await crypto.subtle.sign("HMAC", current, keyBuf);
}
