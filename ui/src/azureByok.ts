export const getTags = (attributes: Map<string, never>): string[] => {
    const vendor_attributes: Array<Map<string, never>> | undefined = attributes.get("vendor_attributes");
    if (typeof vendor_attributes !== "undefined") {
        const attrs_value_map: Map<string, never> | undefined = (vendor_attributes as Array<Map<string, never>>)
            .find((attribute: Map<string, never>) => {
                return attribute.get("AttributeName") === "tag";
            })
            ?.get("AttributeValue");
        if (typeof attrs_value_map === "undefined") {
            return [];
        }
        const tags_string = (attrs_value_map as Map<string, string>).get("_c");
        if (tags_string) {
            try {
                return JSON.parse(tags_string);
            } catch (error) {
                console.error("Error parsing tags JSON:", error);
                return [];
            }
        }
        return [];
    }

    return [];
};

export const base64UrlEncode = (bytes: Uint8Array): string => {
    const base64 = btoa(String.fromCharCode(...bytes));
    return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
};

export const buildAzureByokObject = (kid: string, wrappedKeyBytes: Uint8Array) => {
    return {
        schema_version: "1.0.0",
        header: {
            kid: kid,
            alg: "dir",
            enc: "CKM_RSA_AES_KEY_WRAP",
        },
        ciphertext: base64UrlEncode(wrappedKeyBytes),
        generator: "Cosmian_KMS;v5",
    };
};

export const buildAzureByokContent = (kid: string, wrappedKeyBytes: Uint8Array): string => {
    return JSON.stringify(buildAzureByokObject(kid, wrappedKeyBytes), null, 2);
};

export const getAzureByokFilename = (wrappedKeyId: string, byokFile?: string): string => {
    return byokFile || `${wrappedKeyId}.byok`;
};
