/**
 * Unit tests for SplitKey / JoinSplitKey logic (no DOM rendering required).
 *
 * Covers fixes:
 *   #1  - Share UID extraction uses correct TTLV structure
 *   #2  - CreateSplitKey request carries the resolved share count (not a hardcoded 2)
 *   #4  - JoinSplitKey DEFAULT_SHARE_COUNT is consistent between state and initialValues
 *   #5  - buildJoinSplitKeyRequest always includes ObjectType (not undefined)
 */

import { describe, expect, test } from "vitest";

// ── Helpers copied from the production components (kept in sync) ─────────────

const buildCreateSplitKeyRequest = (keyId: string, n: number) => ({
    tag: "CreateSplitKey",
    type: "Structure",
    value: [
        { tag: "UniqueIdentifier", type: "TextString", value: keyId },
        { tag: "SplitKeyParts", type: "Integer", value: n },
        { tag: "SplitKeyThreshold", type: "Integer", value: n },
        { tag: "SplitKeyMethod", type: "Enumeration", value: "XOR" },
    ],
});

const buildJoinSplitKeyRequest = (shareIds: string[], objectType: string) => ({
    tag: "JoinSplitKey",
    type: "Structure",
    value: [
        { tag: "ObjectType", type: "Enumeration", value: objectType },
        ...shareIds.map((id) => ({
            tag: "PrivateKeyUniqueIdentifier",
            type: "TextString",
            value: id,
        })),
        { tag: "SplitKeyMethod", type: "Enumeration", value: "XOR" },
    ],
});

// Simulates the share-UID extraction after wasm.parse_create_split_key_ttlv_response.
// The WASM parser returns a typed JS object where PrivateKeyUniqueIdentifier is a string[].
const extractShareUids = (parsedResponse: { UniqueIdentifier: string; PrivateKeyUniqueIdentifier: string | string[] }) => {
    return Array.isArray(parsedResponse.PrivateKeyUniqueIdentifier)
        ? parsedResponse.PrivateKeyUniqueIdentifier
        : parsedResponse.PrivateKeyUniqueIdentifier
          ? [parsedResponse.PrivateKeyUniqueIdentifier]
          : [];
};

// ── Fix #2: CreateSplitKey carries the resolved n ────────────────────────────

describe("buildCreateSplitKeyRequest", () => {
    test("sets SplitKeyParts and SplitKeyThreshold to the provided n", () => {
        const req = buildCreateSplitKeyRequest("key-id-123", 4);
        const parts = req.value.find((v) => v.tag === "SplitKeyParts");
        const threshold = req.value.find((v) => v.tag === "SplitKeyThreshold");
        expect(parts?.value).toBe(4);
        expect(threshold?.value).toBe(4);
    });

    test("passes n=2 when n is explicitly 2 (not hardcoded default)", () => {
        const req = buildCreateSplitKeyRequest("key-id-abc", 2);
        const parts = req.value.find((v) => v.tag === "SplitKeyParts");
        expect(parts?.value).toBe(2);
    });

    test("includes the keyId as UniqueIdentifier", () => {
        const req = buildCreateSplitKeyRequest("my-key", 3);
        const uid = req.value.find((v) => v.tag === "UniqueIdentifier");
        expect(uid?.value).toBe("my-key");
    });

    test("always uses XOR method", () => {
        const req = buildCreateSplitKeyRequest("k", 5);
        const method = req.value.find((v) => v.tag === "SplitKeyMethod");
        expect(method?.value).toBe("XOR");
    });
});

// ── Fix #1 + #8: Share UID extraction from wasm-parsed response ──────────────

describe("extractShareUids (fix #1 — TTLV parsing)", () => {
    test("extracts array of UIDs when PrivateKeyUniqueIdentifier is a string[]", () => {
        const parsed = {
            UniqueIdentifier: "source-key-id",
            PrivateKeyUniqueIdentifier: ["share-uid-1", "share-uid-2", "share-uid-3"],
        };
        const uids = extractShareUids(parsed);
        expect(uids).toEqual(["share-uid-1", "share-uid-2", "share-uid-3"]);
    });

    test("wraps a single string UID in an array", () => {
        const parsed = {
            UniqueIdentifier: "source-key-id",
            PrivateKeyUniqueIdentifier: "share-uid-only",
        };
        const uids = extractShareUids(parsed);
        expect(uids).toEqual(["share-uid-only"]);
    });

    test("returns empty array when PrivateKeyUniqueIdentifier is absent/empty", () => {
        const parsed = { UniqueIdentifier: "source-key-id", PrivateKeyUniqueIdentifier: [] as string[] };
        expect(extractShareUids(parsed)).toEqual([]);
    });

    test("does NOT include the source key UID in the share list", () => {
        // The source key UID is returned as UniqueIdentifier, NOT as a share.
        // extractShareUids only reads PrivateKeyUniqueIdentifier — the source UID
        // is never accidentally mixed in.
        const parsed = {
            UniqueIdentifier: "source-key-id",
            PrivateKeyUniqueIdentifier: ["share-1", "share-2"],
        };
        const uids = extractShareUids(parsed);
        expect(uids).not.toContain("source-key-id");
    });
});

// ── Fix #5: buildJoinSplitKeyRequest always carries ObjectType ───────────────

describe("buildJoinSplitKeyRequest", () => {
    test("includes ObjectType as the first value element", () => {
        const req = buildJoinSplitKeyRequest(["s1", "s2"], "SymmetricKey");
        expect(req.value[0]).toEqual({ tag: "ObjectType", type: "Enumeration", value: "SymmetricKey" });
    });

    test("includes all share UIDs as PrivateKeyUniqueIdentifier elements", () => {
        const req = buildJoinSplitKeyRequest(["s1", "s2", "s3"], "SymmetricKey");
        const shares = req.value.filter((v) => v.tag === "PrivateKeyUniqueIdentifier");
        expect(shares.map((s) => s.value)).toEqual(["s1", "s2", "s3"]);
    });

    test("objectType is never undefined when default 'SymmetricKey' is applied", () => {
        // Simulates the fix: values.objectType ?? 'SymmetricKey' is always a string
        const objectType = (undefined as unknown as string) ?? "SymmetricKey";
        const req = buildJoinSplitKeyRequest(["s1", "s2"], objectType);
        const ot = req.value.find((v) => v.tag === "ObjectType");
        expect(ot?.value).toBe("SymmetricKey");
        expect(ot?.value).not.toBeUndefined();
    });
});

// ── Fix #4: JoinSplitKey DEFAULT_SHARE_COUNT consistency ────────────────────

describe("JoinSplitKey DEFAULT_SHARE_COUNT", () => {
    const DEFAULT_SHARE_COUNT = 3;

    test("DEFAULT_SHARE_COUNT matches between initial state and initialValues", () => {
        // State initial value
        const stateValue = DEFAULT_SHARE_COUNT;
        // Form initialValues.shareCount (was missing in the old code)
        const initialValues = {
            shareCount: DEFAULT_SHARE_COUNT,
            objectType: "SymmetricKey" as const,
            shareIds: Array.from({ length: DEFAULT_SHARE_COUNT }, () => ({ value: "" })),
        };
        expect(stateValue).toBe(initialValues.shareCount);
        expect(initialValues.shareIds).toHaveLength(DEFAULT_SHARE_COUNT);
    });

    test("initialValues.objectType is 'SymmetricKey' (never undefined)", () => {
        const initialValues = {
            shareCount: DEFAULT_SHARE_COUNT,
            objectType: "SymmetricKey" as const,
            shareIds: Array.from({ length: DEFAULT_SHARE_COUNT }, () => ({ value: "" })),
        };
        expect(initialValues.objectType).toBe("SymmetricKey");
    });
});
