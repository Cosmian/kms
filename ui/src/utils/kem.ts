/** A KEM `Encrypt` result: the shared secret and the encapsulation (KEM ciphertext). */
export interface KemEncapsulation {
    sharedSecret: Uint8Array;
    encapsulation: Uint8Array;
}

/**
 * Split the `Data` of a KEM `Encrypt` response. Every KEM (ML-KEM, X25519MLKEM768,
 * X448MLKEM1024, ConfigurableKEM) packs `(shared secret, encapsulation)` as two
 * length-prefixed byte strings: LEB128 length, then the bytes. `IVCounterNonce` is empty.
 */
export const unpackKemEncapsulation = (data: Uint8Array | number[]): KemEncapsulation => {
    const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
    let offset = 0;
    const readBytes = (): Uint8Array => {
        let length = 0;
        for (let shift = 0; ; shift += 7) {
            const byte = bytes[offset++];
            if (byte === undefined || shift > 28) {
                throw new Error("Invalid KEM response: bad length prefix");
            }
            length += (byte & 0x7f) * 2 ** shift;
            if ((byte & 0x80) === 0) break;
        }
        if (offset + length > bytes.length) {
            throw new Error("Invalid KEM response: truncated data");
        }
        const out = bytes.slice(offset, offset + length);
        offset += length;
        return out;
    };
    const sharedSecret = readBytes();
    const encapsulation = readBytes();
    if (offset !== bytes.length) {
        throw new Error("Invalid KEM response: trailing data");
    }
    return { sharedSecret, encapsulation };
};
