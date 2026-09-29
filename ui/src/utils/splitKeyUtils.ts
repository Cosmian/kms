/**
 * Shared utility for building a KMIP `CreateSplitKey` TTLV request.
 *
 * Used by both the standalone Split Key page and the Crypto Officer ceremony
 * workflow to ensure a single, consistent request shape. `ObjectType` is the
 * first field and is required (non-`Option`) by the server.
 */

/** Build a `CreateSplitKey` TTLV request for an AES-256 symmetric key. */
export const buildCreateSplitKeyRequest = (keyId: string, n: number) => ({
    tag: "CreateSplitKey",
    type: "Structure",
    value: [
        { tag: "ObjectType", type: "Enumeration", value: "SymmetricKey" },
        { tag: "UniqueIdentifier", type: "TextString", value: keyId },
        { tag: "SplitKeyParts", type: "Integer", value: n },
        { tag: "SplitKeyThreshold", type: "Integer", value: n },
        { tag: "SplitKeyMethod", type: "Enumeration", value: "XOR" },
    ],
});
