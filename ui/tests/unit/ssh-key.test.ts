import { describe, expect, test } from "vitest";

import { encodeOpenSshEcdsaP256, generateSshKeyPair } from "../../src/utils/sshKey";

const decodeBlob = (line: string): Uint8Array => Uint8Array.from(atob(line.split(" ")[1]), (c) => c.charCodeAt(0));

describe("OpenSSH ECDSA P-256 public key encoding", () => {
    test("writes the RFC 5656 wire format", () => {
        const point = new Uint8Array(65).fill(4);
        const line = encodeOpenSshEcdsaP256(point);
        expect(line.startsWith("ecdsa-sha2-nistp256 ")).toBe(true);
        const blob = decodeBlob(line);
        const view = new DataView(blob.buffer);
        expect(view.getUint32(0)).toBe(19);
        expect(view.getUint32(4 + 19)).toBe(8);
        expect(view.getUint32(4 + 19 + 4 + 8)).toBe(65);
        expect(blob.length).toBe(4 + 19 + 4 + 8 + 4 + 65);
    });

    test("generates a key pair whose private key is PKCS#8 PEM", async () => {
        const { publicKey, privateKeyPem } = await generateSshKeyPair();
        expect(publicKey).toMatch(/^ecdsa-sha2-nistp256 [A-Za-z0-9+/]+=*$/);
        expect(privateKeyPem).toMatch(/^-----BEGIN PRIV\w+ KEY-----\n[\s\S]+\n-----END PRIV\w+ KEY-----\n$/);
    });
});
