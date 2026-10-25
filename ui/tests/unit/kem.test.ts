import { describe, expect, test } from "vitest";

import { unpackKemEncapsulation } from "../../src/utils/kem";

describe("unpackKemEncapsulation", () => {
    test("splits the secret and an encapsulation with a multi-byte length prefix", () => {
        const secret = new Uint8Array(32).fill(7);
        const encapsulation = new Uint8Array(1088).fill(9);
        // 1088 = 0xC0 0x08 in LEB128
        const packed = new Uint8Array([32, ...secret, 0xc0, 0x08, ...encapsulation]);
        const out = unpackKemEncapsulation(packed);
        expect(out.sharedSecret).toEqual(secret);
        expect(out.encapsulation).toEqual(encapsulation);
        expect(unpackKemEncapsulation(Array.from(packed)).encapsulation).toEqual(encapsulation);
    });

    test("rejects truncated, trailing and empty data", () => {
        const packed = new Uint8Array([2, 1, 2, 1, 3]);
        expect(unpackKemEncapsulation(packed).encapsulation).toEqual(new Uint8Array([3]));
        expect(() => unpackKemEncapsulation(packed.slice(0, 4))).toThrow();
        expect(() => unpackKemEncapsulation(new Uint8Array([...packed, 0]))).toThrow();
        expect(() => unpackKemEncapsulation(new Uint8Array())).toThrow();
    });
});
