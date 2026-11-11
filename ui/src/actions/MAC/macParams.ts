export type MacType = "HMAC" | "AES-CMAC" | "AES-GMAC";

export const MAC_TYPES: { label: string; value: MacType }[] = [
    { label: "HMAC", value: "HMAC" },
    { label: "AES-CMAC", value: "AES-CMAC" },
    { label: "AES-GMAC", value: "AES-GMAC" },
];

export const MAC_HASHING_ALGORITHMS = [
    { label: "SHA-1", value: "SHA1" },
    { label: "SHA-224", value: "SHA224" },
    { label: "SHA-256", value: "SHA256" },
    { label: "SHA-384", value: "SHA384" },
    { label: "SHA-512", value: "SHA512" },
    { label: "SHA3-224", value: "SHA3224" },
    { label: "SHA3-256", value: "SHA3256" },
    { label: "SHA3-384", value: "SHA3384" },
    { label: "SHA3-512", value: "SHA3512" },
];

/** KMIP CryptographicParameters TTLV: HMAC selects the hash; AES-CMAC / AES-GMAC select the block cipher mode. */
export const buildCryptographicParameters = (macType: MacType, hashAlgorithm: string) => ({
    tag: "CryptographicParameters",
    type: "Structure",
    value:
        macType === "HMAC"
            ? [{ tag: "HashingAlgorithm", type: "Enumeration", value: hashAlgorithm }]
            : [
                  { tag: "BlockCipherMode", type: "Enumeration", value: macType === "AES-CMAC" ? "CMAC" : "GCM" },
                  { tag: "CryptographicAlgorithm", type: "Enumeration", value: "AES" },
              ],
});
