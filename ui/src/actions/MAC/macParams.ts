import { useEffect, useState } from "react";
import * as wasm from "../../wasm/pkg";

export type MacType = "HMAC" | "AES-CMAC" | "AES-GMAC";

export interface MacOption {
    label: string;
    value: string;
}

export interface MacOptions {
    macTypes: MacOption[];
    hashingAlgorithms: MacOption[];
}

/** MAC types and HMAC hash functions come from the WASM client, so the UI never drifts from the KMIP builders. */
export const getMacOptions = (): MacOptions => ({
    macTypes: wasm.get_mac_types() as MacOption[],
    hashingAlgorithms: wasm.get_mac_hashing_algorithms() as MacOption[],
});

/** Options for the MAC selects; stay empty (and log) when the WASM module failed to load, so the page still renders. */
export const useMacOptions = (): MacOptions => {
    const [options, setOptions] = useState<MacOptions>({ macTypes: [], hashingAlgorithms: [] });
    useEffect(() => {
        try {
            setOptions(getMacOptions());
        } catch (e) {
            console.error("Error loading MAC options from WASM:", e);
        }
    }, []);
    return options;
};

/** Even-length hex string (as enforced by the form rules) to bytes. */
export const hexToBytes = (hex: string): Uint8Array => Uint8Array.from(hex.match(/../g) ?? [], (pair) => parseInt(pair, 16));

/** Form rule: whole bytes written in hex. */
export const HEX_BYTES_PATTERN = /^([0-9a-fA-F]{2})*$/;
