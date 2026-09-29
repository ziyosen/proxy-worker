// Variabel cache untuk menyimpan kunci dasar yang sudah di-import
let cachedVmessKdfKey = null;

export async function kdf(key, path) {
    // Optimasi: Gunakan kunci yang sudah di-cache jika tersedia
    if (!cachedVmessKdfKey) {
        cachedVmessKdfKey = await crypto.subtle.importKey(
            "raw",
            new TextEncoder().encode("VMess AEAD KDF"),
            { name: "HMAC", hash: "SHA-256" },
            false,
            ["sign"]
        );
    }

    let currentKey = cachedVmessKdfKey;

    for (const p of path) {
        // Cek tipe data: jika Uint8Array, biarkan; jika string, jadikan Uint8Array
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

export async function sha256(data) {
    // Menghapus instansiasi TextEncoder jika data sudah berupa Uint8Array
    const buffer = typeof data === 'string' ? new TextEncoder().encode(data) : data;
    const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
    return new Uint8Array(hashBuffer);
}
