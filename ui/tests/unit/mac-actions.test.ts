import { fireEvent, screen, waitFor } from "@testing-library/react";
import React from "react";
import { describe, expect, test, vi } from "vitest";

import MacCompute from "../../src/actions/MAC/MacCompute";
import MacVerify from "../../src/actions/MAC/MacVerify";
import { getMacOptions, HEX_BYTES_PATTERN, hexToBytes } from "../../src/actions/MAC/macParams";
import { smokeRender } from "./test-utils";

interface TtlvItem {
    tag: string;
    type?: string;
    value: unknown;
}

/** Stub the KMIP endpoint and return the TTLV bodies it receives. */
const captureKmipRequests = (response: object): TtlvItem[] => {
    const sent: TtlvItem[] = [];
    vi.stubGlobal(
        "fetch",
        vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
            if (String(input).endsWith("/kmip/2_1")) {
                sent.push(JSON.parse(String(init?.body)) as TtlvItem);
                return new Response(JSON.stringify(response), { status: 200, headers: { "Content-Type": "application/json" } });
            }
            return new Response("{}", { status: 200 });
        }),
    );
    return sent;
};

describe("MAC options from WASM", () => {
    test("lists the MAC types and the HMAC hashes the server supports", () => {
        const { macTypes, hashingAlgorithms } = getMacOptions();
        expect(macTypes.map((o) => o.value)).toEqual(["HMAC", "AES-CMAC", "AES-GMAC"]);
        expect(hashingAlgorithms.map((o) => o.value)).toEqual([
            "SHA1",
            "SHA224",
            "SHA256",
            "SHA384",
            "SHA512",
            "SHA3224",
            "SHA3256",
            "SHA3384",
            "SHA3512",
        ]);
        expect(hashingAlgorithms.find((o) => o.value === "SHA3256")?.label).toBe("SHA3-256");
    });

    test("hexToBytes accepts only whole bytes", () => {
        expect(hexToBytes("00ffA1")).toEqual(new Uint8Array([0x00, 0xff, 0xa1]));
        expect(hexToBytes("")).toEqual(new Uint8Array());
        expect(HEX_BYTES_PATTERN.test("00ff")).toBe(true);
        expect(HEX_BYTES_PATTERN.test("0")).toBe(false);
        expect(HEX_BYTES_PATTERN.test("0g")).toBe(false);
    });
});

describe("MAC actions send the WASM-built request", () => {
    test("MacCompute sends a MAC request with the HMAC hash and the data bytes", async () => {
        const sent = captureKmipRequests({ tag: "MACResponse", value: [{ tag: "MACData", type: "ByteString", value: "AABB" }] });
        smokeRender(React.createElement(MacCompute));

        fireEvent.change(screen.getByPlaceholderText("Enter key ID"), { target: { value: "key-1" } });
        fireEvent.change(screen.getByPlaceholderText("e.g. 0011223344556677"), { target: { value: "0011ff" } });
        fireEvent.click(screen.getByRole("button", { name: "Compute MAC" }));

        await waitFor(() => expect(sent).toHaveLength(1));
        const request = sent[0];
        expect(request.tag).toBe("MAC");
        const items = request.value as TtlvItem[];
        expect(items.find((i) => i.tag === "UniqueIdentifier")?.value).toBe("key-1");
        expect(items.find((i) => i.tag === "Data")?.value).toBe("0011FF");
        expect(items.find((i) => i.tag === "CryptographicParameters")?.value).toEqual([
            { tag: "HashingAlgorithm", type: "Enumeration", value: "SHA256" },
        ]);
        expect(await screen.findByText("MAC (hex): AABB")).toBeInTheDocument();
    });

    test("MacCompute rejects data that is not whole hex bytes without calling the server", async () => {
        const sent = captureKmipRequests({});
        smokeRender(React.createElement(MacCompute));

        fireEvent.change(screen.getByPlaceholderText("Enter key ID"), { target: { value: "key-1" } });
        fireEvent.change(screen.getByPlaceholderText("e.g. 0011223344556677"), { target: { value: "001" } });
        fireEvent.click(screen.getByRole("button", { name: "Compute MAC" }));

        // the field's `help` text replaces the message, so assert the error state instead
        await waitFor(() => expect(document.querySelector(".ant-form-item-has-error")).not.toBeNull());
        expect(sent).toHaveLength(0);
    });

    test("MacVerify sends a MACVerify request with data and MAC bytes", async () => {
        const sent = captureKmipRequests({
            tag: "MACVerifyResponse",
            value: [{ tag: "ValidityIndicator", type: "Enumeration", value: "Valid" }],
        });
        smokeRender(React.createElement(MacVerify));

        fireEvent.change(screen.getByPlaceholderText("Enter key ID"), { target: { value: "key-2" } });
        fireEvent.change(screen.getByPlaceholderText("e.g. 0011223344556677889900"), { target: { value: "0102" } });
        fireEvent.change(screen.getByPlaceholderText("e.g. F91DDB96D12CF8FA..."), { target: { value: "aabbcc" } });
        fireEvent.click(screen.getByRole("button", { name: "Verify MAC" }));

        await waitFor(() => expect(sent).toHaveLength(1));
        const request = sent[0];
        expect(request.tag).toBe("MACVerify");
        const items = request.value as TtlvItem[];
        expect(items.find((i) => i.tag === "UniqueIdentifier")?.value).toBe("key-2");
        expect(items.find((i) => i.tag === "Data")?.value).toBe("0102");
        expect(items.find((i) => i.tag === "MACData")?.value).toBe("AABBCC");
        expect(items.find((i) => i.tag === "CryptographicParameters")?.value).toEqual([
            { tag: "HashingAlgorithm", type: "Enumeration", value: "SHA256" },
        ]);
        expect(await screen.findByText("MAC is valid.")).toBeInTheDocument();
    });

    // The hash select is not mounted for AES MACs, so the form leaves `algorithm` undefined.
    test.each([
        ["AES-CMAC", "CMAC"],
        ["AES-GMAC", "GCM"],
    ])("MacCompute with %s sends the %s block cipher mode and no hash", async (macType, mode) => {
        const sent = captureKmipRequests({ tag: "MACResponse", value: [{ tag: "MACData", type: "ByteString", value: "AABB" }] });
        smokeRender(React.createElement(MacCompute));

        fireEvent.change(screen.getByPlaceholderText("Enter key ID"), { target: { value: "key-3" } });
        fireEvent.mouseDown(screen.getByRole("combobox", { name: "MAC Type" }));
        fireEvent.click(await screen.findByText(macType, { selector: ".ant-select-item-option-content" }));
        fireEvent.change(screen.getByPlaceholderText("e.g. 0011223344556677"), { target: { value: "0011" } });
        fireEvent.click(screen.getByRole("button", { name: "Compute MAC" }));

        await waitFor(() => expect(sent).toHaveLength(1));
        const items = sent[0].value as TtlvItem[];
        expect(items.find((i) => i.tag === "CryptographicParameters")?.value).toEqual([
            { tag: "BlockCipherMode", type: "Enumeration", value: mode },
            { tag: "CryptographicAlgorithm", type: "Enumeration", value: "AES" },
        ]);
    });

    test("MacVerify with AES-GMAC sends the GCM block cipher mode and no hash", async () => {
        const sent = captureKmipRequests({
            tag: "MACVerifyResponse",
            value: [{ tag: "ValidityIndicator", type: "Enumeration", value: "Invalid" }],
        });
        smokeRender(React.createElement(MacVerify));

        fireEvent.change(screen.getByPlaceholderText("Enter key ID"), { target: { value: "key-4" } });
        fireEvent.mouseDown(screen.getByRole("combobox", { name: "MAC Type" }));
        fireEvent.click(await screen.findByText("AES-GMAC", { selector: ".ant-select-item-option-content" }));
        fireEvent.change(screen.getByPlaceholderText("e.g. 0011223344556677889900"), { target: { value: "0102" } });
        fireEvent.change(screen.getByPlaceholderText("e.g. F91DDB96D12CF8FA..."), { target: { value: "aabb" } });
        fireEvent.click(screen.getByRole("button", { name: "Verify MAC" }));

        await waitFor(() => expect(sent).toHaveLength(1));
        const items = sent[0].value as TtlvItem[];
        expect(items.find((i) => i.tag === "CryptographicParameters")?.value).toEqual([
            { tag: "BlockCipherMode", type: "Enumeration", value: "GCM" },
            { tag: "CryptographicAlgorithm", type: "Enumeration", value: "AES" },
        ]);
        expect(await screen.findByText("MAC is invalid.")).toBeInTheDocument();
    });
});
