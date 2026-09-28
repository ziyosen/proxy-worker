
import { kdf, md5, sha256 } from '../utils/crypto.js';

export async function handleVmess(server, buffer, uuidStr, proxyHost, proxyPort) {
    try {
        
        const uuidBytes = new TextEncoder().encode(uuidStr);
       
        const baseKeyString = "c48619fe-8f02-49e0-b9e9-edf763e17e21";
        const authId = buffer.subarray(0, 16);
        const headerLenEnc = buffer.subarray(16, 34);
        const nonce = buffer.subarray(34, 42);

        server.close(1011, "VMess AEAD requires full WebCrypto payload mapping (WIP)");

    } catch (err) {
        server.close(1011, "VMess Parsing Error");
    }
}
