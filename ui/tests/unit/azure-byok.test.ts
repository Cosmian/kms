import { describe, expect, test } from "vitest";

import { base64UrlEncode, buildAzureByokContent, buildAzureByokObject, getAzureByokFilename, getTags } from "../../src/azureByok";
import { azureKekKeyUsage, azureKekTags } from "../../src/azureKek";

describe("Azure BYOK helpers", () => {
    test("base64UrlEncode is url-safe and unpadded", () => {
        const bytes = new Uint8Array([0xfb, 0xff, 0x00]);
        const out = base64UrlEncode(bytes);
        expect(out).not.toContain("=");
        expect(out).not.toContain("+");
        expect(out).not.toContain("/");
        expect(out.length).toBeGreaterThan(0);
    });

    test("buildAzureByokObject sets expected fields", () => {
        const obj = buildAzureByokObject("kid-value", new Uint8Array([1, 2, 3]));
        expect(obj.schema_version).toBe("1.0.0");
        expect(obj.header.kid).toBe("kid-value");
        expect(obj.header.enc).toBe("CKM_RSA_AES_KEY_WRAP");
        expect(obj.ciphertext.length).toBeGreaterThan(0);
        expect(obj.generator).toContain("Cosmian_KMS");
    });

    test("buildAzureByokContent emits valid JSON", () => {
        const json = buildAzureByokContent("kid-value", new Uint8Array([1, 2, 3]));
        const parsed = JSON.parse(json) as { header: { kid: string } };
        expect(parsed.header.kid).toBe("kid-value");
    });

    test("getAzureByokFilename defaults to <wrappedKeyId>.byok", () => {
        expect(getAzureByokFilename("wrapped-key")).toBe("wrapped-key.byok");
        expect(getAzureByokFilename("wrapped-key", "custom.byok")).toBe("custom.byok");
    });

    test("getTags extracts tags JSON from vendor_attributes", () => {
        const attrValue = new Map<string, string>([["__c", "ignored"]]);
        // The implementation reads the "_c" entry.
        attrValue.set("_c", JSON.stringify(["azure", "kid:https://example"]));

        const vendorAttr = new Map<string, never>();
        vendorAttr.set("AttributeName", "tag" as never);
        vendorAttr.set("AttributeValue", attrValue as never);

        const attributes = new Map<string, never>();
        attributes.set("vendor_attributes", [vendorAttr] as never);

        expect(getTags(attributes)).toEqual(["azure", "kid:https://example"]);
    });

    test("azureKekTags and key usage are stable", () => {
        expect(azureKekTags("kid")).toEqual(["azure", "kid:kid"]);
        expect(azureKekKeyUsage).toEqual(["WrapKey", "Encrypt"]);
    });
});
