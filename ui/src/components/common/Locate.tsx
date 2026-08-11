import { Button, Card, Col, Form, Input, Modal, Row, Select, Space, Table, TableColumnsType, Tag, Tooltip } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import HashMapDisplay from "./HashMapDisplay";
import { getNoTTLVRequest, sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

const formatUnixDate = (unixMs: number): string => {
    const d = new Date(unixMs);
    return d.toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
};

/** Structured outcome of a Locate run — rendered through i18n (avoids string-splicing display text). */
type LocateResult = { kind: "located"; count: number } | { kind: "message"; text: string } | { kind: "error"; text: string };

/** Attribute keys fetched for every located row — sourced from WASM (single source of truth).
 *  Lazily initialised on first access so the WASM module is guaranteed to be
 *  ready (eager module-level evaluation can race with async WASM loading). */
let _enrichAttributeKeysCache: string[] | null = null;
function getEnrichAttributeKeys(): string[] {
    if (_enrichAttributeKeysCache === null || _enrichAttributeKeysCache.length === 0) {
        try {
            const keys = wasm.get_locate_enrich_attribute_keys();
            if (Array.isArray(keys) && keys.length > 0) {
                _enrichAttributeKeysCache = keys as string[];
            }
        } catch {
            // WASM not ready yet; will retry on next call
        }
    }
    return _enrichAttributeKeysCache ?? [];
}

interface LocateObjectRow {
    object_id: string;
    state?: string;
    attributes?: { ObjectType?: string };
    meta?: { key_format_type?: string; [key: string]: unknown };
}

interface LocateFormData {
    tags?: string[];
    cryptographicAlgorithm?: string;
    cryptographicLength?: number;
    keyFormatType?: string;
    objectType?: string;
    publicKeyId?: string;
    privateKeyId?: string;
    certificateId?: string;
    state?: string;
}

type AlgoOption = { value: string; label: string };

const LocateForm: React.FC = () => {
    const { t } = useTranslation(["locate", "common"]);
    const NO_FILTER: AlgoOption = { value: "", label: t("noFilter") };
    const [form] = Form.useForm<LocateFormData>();
    const [isLoading, setIsLoading] = useState(false);
    const [result, setResult] = useState<LocateResult | undefined>(undefined);
    const [cryptoAlgorithms, setCryptoAlgorithms] = useState<AlgoOption[]>([]);
    const [keyFormatTypes, setKeyFormatTypes] = useState<AlgoOption[]>([]);
    const [objectTypes, setObjectTypes] = useState<AlgoOption[]>([]);
    const [objectStates, setObjectStates] = useState<AlgoOption[]>([]);
    type LocatedRow = LocateObjectRow;
    const [objects, setObjects] = useState<LocatedRow[] | undefined>(undefined);
    const normalizeState = (s?: string) => (s || "").toLowerCase().replace(/\s+/g, "").replace(/-/g, "");
    const stateEnumToName = (v: unknown): string | undefined => {
        if (v == null) return undefined;
        const s = String(v);
        const n = Number(s);
        if (!Number.isNaN(n)) {
            switch (n) {
                case 1:
                    return "Pre-Active";
                case 2:
                    return "Active";
                case 3:
                    return "Deactivated";
                case 4:
                    return "Compromised";
                case 5:
                    return "Destroyed";
                case 6:
                    return "Destroyed Compromised";
                case 7:
                    return "Archived";
                default:
                    return s;
            }
        }
        // If s already a textual state (possibly with hyphen), return as-is
        return s;
    };
    // Lifecycle state names are kept in English internally (they participate in
    // filtering/sorting); only the rendered text is translated.
    const STATE_DISPLAY_KEYS: Record<string, string> = {
        "Pre-Active": "state.preActive",
        Active: "state.active",
        Deactivated: "state.deactivated",
        Compromised: "state.compromised",
        Destroyed: "state.destroyed",
        "Destroyed Compromised": "state.destroyedCompromised",
        Archived: "state.archived",
        Unknown: "state.unknown",
    };
    const stateDisplay = (state?: string): string => {
        if (!state) return t("state.unknown");
        const key = STATE_DISPLAY_KEYS[state];
        return key ? t(key) : state;
    };
    const { serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const [detailsVisible, setDetailsVisible] = useState<boolean>(false);
    const [detailsData, setDetailsData] = useState<Map<string, unknown> | undefined>(undefined);
    const [detailsForId, setDetailsForId] = useState<string | undefined>(undefined);
    const [actionLoadingId, setActionLoadingId] = useState<string | undefined>(undefined);

    useEffect(() => {
        if (result && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [result]);

    useEffect(() => {
        try {
            const algos = wasm.get_crypto_algorithms() as unknown as AlgoOption[];
            if (Array.isArray(algos)) setCryptoAlgorithms(algos);
        } catch {
            /* ignore if WASM not ready */
        }
        try {
            const kf = wasm.get_key_format_types() as unknown as AlgoOption[];
            if (Array.isArray(kf)) setKeyFormatTypes(kf);
        } catch {
            /* ignore if WASM not ready */
        }
        try {
            const ot = wasm.get_object_types() as unknown as AlgoOption[];
            if (Array.isArray(ot)) setObjectTypes(ot);
        } catch {
            /* ignore if WASM not ready */
        }
        try {
            const os = wasm.get_object_states() as unknown as AlgoOption[];
            if (Array.isArray(os)) setObjectStates(os);
        } catch {
            /* ignore if WASM not ready */
        }
    }, [serverUrl]);

    // normalization helpers
    const normalizeKeyFormatType = (s: string) => s.toLowerCase().replace(/\s+|[-_]/g, "");

    // Utility: parse WASM/Get response into a plain record
    const extractMeta = (parsed: unknown): Record<string, unknown> => {
        if (parsed instanceof Map) return Object.fromEntries(parsed as Map<string, unknown>);
        return (parsed || {}) as Record<string, unknown>;
    };

    // Utility: enrich a list of UIDs via KMIP Get
    const enrichUids = async (uids: string[], serverUrl: string): Promise<LocatedRow[]> => {
        const rows = await Promise.all(
            uids.map(async (uid) => {
                try {
                    const getReq = wasm.get_attributes_ttlv_request(uid);
                    const getRespStr = await sendKmipRequest(getReq, serverUrl);
                    if (getRespStr) {
                        const parsed = await wasm.parse_get_attributes_ttlv_response(getRespStr, getEnrichAttributeKeys());
                        const m = extractMeta(parsed);
                        // HSM keys are always Active; use that as default when state is missing
                        const isHsm = /^hsm[0-9]*::/.test(uid);
                        return {
                            object_id: uid,
                            attributes: { ObjectType: m["object_type"] as string | undefined },
                            state: stateEnumToName(m["state"]) || (isHsm ? "Active" : undefined),
                            meta: m,
                        } as LocatedRow;
                    }
                } catch (e) {
                    console.error(`Error fetching Get for ${uid}:`, e);
                }
                // Fallback: HSM keys default to Active
                return { object_id: uid, state: /^hsm[0-9]*::/.test(uid) ? "Active" : undefined } as LocatedRow;
            }),
        );
        return rows;
    };

    // Utility: build state lookup from /access/owned
    const getOwnedStateMap = async (serverUrl: string): Promise<Map<string, string>> => {
        const stateById = new Map<string, string>();
        const owned = await getNoTTLVRequest("/access/owned", serverUrl);
        if (Array.isArray(owned)) {
            (owned as Array<{ object_id: string; state?: unknown }>).forEach((o) => {
                if (o.object_id) {
                    const s = stateEnumToName(o.state);
                    if (s) stateById.set(o.object_id, s);
                }
            });
        }
        return stateById;
    };

    // Utility: supplement missing state from owned
    const supplementStateFromOwned = async (rows: LocatedRow[], serverUrl: string): Promise<LocatedRow[]> => {
        try {
            const stateById = await getOwnedStateMap(serverUrl);
            return rows.map((row) => ({
                ...row,
                state: row.state || stateEnumToName(stateById.get(row.object_id)),
            }));
        } catch {
            return rows;
        }
    };

    // KMIP Locate helper
    const runKmipLocate = async (
        values: LocateFormData,
        cryptographicAlgorithm: string | undefined,
        keyFormatType: string | undefined,
        objectType: string | undefined,
        serverUrl: string,
    ): Promise<string[]> => {
        const req = wasm.locate_ttlv_request(
            values.tags,
            cryptographicAlgorithm,
            values.cryptographicLength,
            keyFormatType,
            objectType,
            values.publicKeyId,
            values.privateKeyId,
            values.certificateId,
        );
        const respStr = await sendKmipRequest(req, serverUrl);
        if (!respStr) return [];
        const resp = await wasm.parse_locate_ttlv_response(respStr);
        return Array.isArray(resp.UniqueIdentifier) ? (resp.UniqueIdentifier as string[]) : [];
    };

    // Owned-fallback without criteria
    const ownedFallbackNoCriteria = async (serverUrl: string): Promise<LocatedRow[]> => {
        const owned = await getNoTTLVRequest("/access/owned", serverUrl);
        const ids: string[] = Array.isArray(owned) ? (owned as Array<{ object_id: string }>).map((o) => o.object_id).filter(Boolean) : [];
        const enriched = await enrichUids(ids, serverUrl);
        return supplementStateFromOwned(enriched, serverUrl);
    };

    const onFinish = async (values: LocateFormData) => {
        setIsLoading(true);
        setResult(undefined);
        setObjects(undefined);
        try {
            // unauthenticated attempt allowed only when auth method is None
            const norm = (s?: string) => (s && s.trim() !== "" ? s : undefined);
            const keyFormatType = norm(values.keyFormatType);
            const cryptographicAlgorithm = norm(values.cryptographicAlgorithm);
            const objectType = norm(values.objectType);
            const stateVal = norm(values.state);

            // no-op helpers pruned: Locate handles tags & other criteria server-side

            // State-specific search: intersect Locate results with owned-by-state list,
            // but always include HSM keys (hsm:: prefix) from KMIP Locate since
            // /access/owned may not list them on older servers.
            if (stateVal) {
                try {
                    const owned = await getNoTTLVRequest("/access/owned", serverUrl);
                    type OwnedEntry = { object_id?: string; state?: unknown };
                    const ownedList: OwnedEntry[] = Array.isArray(owned) ? (owned as OwnedEntry[]) : [];
                    const mappedOwnedRaw = ownedList.map((o) => ({ id: o.object_id, state: stateEnumToName(o.state) }));
                    const mappedOwned = mappedOwnedRaw.filter((o) => typeof o.id === "string") as Array<{ id: string; state?: string }>;
                    const target = normalizeState(stateVal);
                    const ownedFiltered = mappedOwned.filter((o) => normalizeState(o.state) === target);

                    const hasOtherCriteria = Boolean(
                        (values.tags && values.tags.length) ||
                        cryptographicAlgorithm ||
                        values.cryptographicLength != null ||
                        keyFormatType ||
                        objectType ||
                        values.publicKeyId ||
                        values.privateKeyId ||
                        values.certificateId,
                    );

                    // Always run KMIP Locate to capture HSM keys that may not appear in /access/owned
                    const locatedIds = await runKmipLocate(values, cryptographicAlgorithm, keyFormatType, objectType, serverUrl);
                    // HSM keys from Locate are always Active; include them even if not in owned set
                    const hsmLocatedIds = locatedIds.filter((id) => /^hsm[0-9]*::/.test(id));
                    const ownedIds = new Set(ownedFiltered.map((o) => o.id));

                    if (!hasOtherCriteria) {
                        // Enrich state-only results so Type and Key Format Type are available
                        const enriched = await Promise.all(
                            ownedFiltered.map(async (o) => {
                                const uid = o.id;
                                try {
                                    const getReq = wasm.get_attributes_ttlv_request(uid);
                                    const getRespStr = await sendKmipRequest(getReq, serverUrl);
                                    if (getRespStr) {
                                        const parsed = await wasm.parse_get_attributes_ttlv_response(getRespStr, getEnrichAttributeKeys());
                                        const m = extractMeta(parsed);
                                        return {
                                            object_id: uid,
                                            attributes: { ObjectType: m["object_type"] as string | undefined },
                                            state: o.state || stateEnumToName(m["state"]),
                                            meta: m,
                                        } as LocatedRow;
                                    }
                                } catch (e) {
                                    console.error(`Error fetching Get for ${uid}:`, e);
                                }
                                return { object_id: uid, state: o.state } as LocatedRow;
                            }),
                        );
                        // Merge owned-by-state entries with HSM keys from Locate
                        // (HSM keys are always Active, so they match if target is Active)
                        const isActiveTarget = target === normalizeState("Active");
                        if (isActiveTarget) {
                            for (const hsmId of hsmLocatedIds) {
                                if (!ownedIds.has(hsmId)) {
                                    enriched.push({ object_id: hsmId, state: "Active" } as LocatedRow);
                                }
                            }
                        }
                        setObjects(enriched);
                        setResult({ kind: "located", count: enriched.length });
                        return;
                    }

                    // Intersect Locate results with owned set, but keep HSM keys that Locate found
                    let intersection = locatedIds.filter((id) => ownedIds.has(id) || /^hsm[0-9]*::/.test(id));

                    // Fallback: if KFT provided but intersection is empty, drop KFT server-side and filter locally
                    if (keyFormatType && intersection.length === 0) {
                        try {
                            const fbIds = await runKmipLocate(
                                { ...values, keyFormatType: undefined },
                                cryptographicAlgorithm,
                                undefined,
                                objectType,
                                serverUrl,
                            );
                            intersection = fbIds.filter((id) => ownedIds.has(id) || /^hsm[0-9]*::/.test(id));
                        } catch (e) {
                            console.warn("State+KFT fallback Locate without KFT failed:", e);
                        }
                    }

                    // Enrich only intersection
                    let enriched = await Promise.all(
                        intersection.map(async (uid: string) => {
                            try {
                                const getReq = wasm.get_attributes_ttlv_request(uid);
                                const getRespStr = await sendKmipRequest(getReq, serverUrl);
                                if (getRespStr) {
                                    const parsed = await wasm.parse_get_attributes_ttlv_response(getRespStr, getEnrichAttributeKeys());
                                    const m = extractMeta(parsed);
                                    return {
                                        object_id: uid,
                                        attributes: { ObjectType: m["object_type"] as string | undefined },
                                        state: stateEnumToName(m["state"]) || stateVal,
                                        meta: m,
                                    } as LocatedRow;
                                }
                            } catch (e) {
                                console.error(`Error fetching Get for ${uid}:`, e);
                            }
                            return { object_id: uid, state: /^hsm[0-9]*::/.test(uid) ? "Active" : stateVal } as LocatedRow;
                        }),
                    );
                    // Enforce KFT filter client-side if provided
                    if (keyFormatType) {
                        const target = normalizeKeyFormatType(keyFormatType);
                        enriched = enriched.filter((row) => {
                            const v = row.meta?.["key_format_type"] as string | undefined;
                            return v ? normalizeKeyFormatType(v) === target : false;
                        });
                    }
                    setObjects(enriched);
                    setResult({ kind: "located", count: enriched.length });
                    return;
                } catch {
                    // Fall back to Locate below
                }
            }
            const idsGeneral = await runKmipLocate(values, cryptographicAlgorithm, keyFormatType, objectType, serverUrl);
            if (idsGeneral.length) {
                const mapped: LocatedRow[] = idsGeneral.map((uuid: string) => ({
                    object_id: uuid,
                    attributes: { ObjectType: undefined },
                    state: undefined,
                    meta: undefined,
                }));

                setObjects(mapped);

                // Enrich each object with Type and State using KMIP Get
                try {
                    const enriched = await enrichUids(
                        mapped.map((r) => r.object_id),
                        serverUrl,
                    );

                    // If no additional criteria and state is 'All', display enriched results directly
                    const hasOtherCriteria = Boolean(
                        (values.tags && values.tags.length) ||
                        values.cryptographicAlgorithm ||
                        values.cryptographicLength != null ||
                        values.keyFormatType ||
                        values.objectType ||
                        values.publicKeyId ||
                        values.privateKeyId ||
                        values.certificateId,
                    );
                    if (!hasOtherCriteria && !stateVal) {
                        // Merge state labels from owned list for display, without filtering
                        const merged = await supplementStateFromOwned(enriched, serverUrl);
                        setObjects(
                            merged.map((row) => ({
                                ...row,
                                state: row.state || (row.object_id.startsWith("hsm::") ? "Active" : undefined),
                            })),
                        );
                        setResult({ kind: "located", count: merged.length });
                        return;
                    }
                    // Try to supplement state from non-TTLV owned list when available
                    try {
                        let merged = await supplementStateFromOwned(enriched, serverUrl);
                        // State filter if requested
                        if (stateVal) {
                            const target = normalizeState(stateVal);
                            merged = merged.filter((r) => normalizeState(r.state) === target);
                        }
                        // Enforce KFT filter if provided
                        if (keyFormatType) {
                            const targetKft = normalizeKeyFormatType(keyFormatType);
                            merged = merged.filter((r) => {
                                const v = r.meta?.["key_format_type"] as string | undefined;
                                return v ? normalizeKeyFormatType(v) === targetKft : false;
                            });
                        }
                        // Do not re-filter by tags/criteria; Locate already applied them

                        setObjects(merged);
                        setResult({ kind: "located", count: merged.length });
                    } catch {
                        // If owned endpoint not available, keep KMIP-only enrichment
                        let filtered = enriched;
                        if (stateVal) {
                            const target = normalizeState(stateVal);
                            filtered = filtered.filter((r) => normalizeState(r.state) === target);
                        }
                        if (keyFormatType) {
                            const targetKft = normalizeKeyFormatType(keyFormatType);
                            filtered = filtered.filter((r) => {
                                const v = r.meta?.["key_format_type"] as string | undefined;
                                return v ? normalizeKeyFormatType(v) === targetKft : false;
                            });
                        }
                        // Do not re-filter by tags/criteria; Locate already applied them

                        setObjects(filtered);
                        setResult({ kind: "located", count: filtered.length });
                    }
                } catch {
                    /* ignore */
                }
            } else {
                // No KMIP Locate results with no filters: fallback to /access/owned for a basic listing
                const noCriteria = !(
                    (values.tags && values.tags.length) ||
                    values.cryptographicAlgorithm ||
                    values.cryptographicLength != null ||
                    values.keyFormatType ||
                    values.objectType ||
                    values.publicKeyId ||
                    values.privateKeyId ||
                    values.certificateId ||
                    stateVal
                );
                if (noCriteria) {
                    try {
                        const merged = await ownedFallbackNoCriteria(serverUrl);
                        setObjects(merged);
                        setResult({ kind: "located", count: merged.length });
                        return;
                    } catch {
                        /* owned fallback failed */
                    }
                }
                // No results returned by Locate: if Key Format Type filter is set, try fallback client-side filtering
                if (keyFormatType) {
                    try {
                        const fallbackReq = wasm.locate_ttlv_request(
                            values.tags,
                            cryptographicAlgorithm,
                            values.cryptographicLength,
                            undefined,
                            objectType,
                            values.publicKeyId,
                            values.privateKeyId,
                            values.certificateId,
                        );
                        const fallbackStr = await sendKmipRequest(fallbackReq, serverUrl);
                        if (fallbackStr) {
                            const fb = await wasm.parse_locate_ttlv_response(fallbackStr);
                            const ids: string[] = Array.isArray(fb.UniqueIdentifier) ? fb.UniqueIdentifier : [];
                            const target = normalizeKeyFormatType(keyFormatType);
                            const enriched = await Promise.all(
                                ids.map(async (uid: string) => {
                                    try {
                                        const getReq = wasm.get_attributes_ttlv_request(uid);
                                        const getRespStr = await sendKmipRequest(getReq, serverUrl);
                                        if (getRespStr) {
                                            const parsed = await wasm.parse_get_attributes_ttlv_response(
                                                getRespStr,
                                                getEnrichAttributeKeys(),
                                            );
                                            const m = extractMeta(parsed);
                                            return {
                                                object_id: uid,
                                                attributes: { ObjectType: m["object_type"] as string | undefined },
                                                state: stateEnumToName(m["state"]),
                                                meta: m,
                                            } as LocatedRow;
                                        }
                                    } catch (e) {
                                        console.error(`Error fetching Get for ${uid}:`, e);
                                    }
                                    return { object_id: uid } as LocatedRow;
                                }),
                            );
                            let filtered = enriched.filter((row) => {
                                const v = row.meta?.["key_format_type"] as string | undefined;
                                return v ? normalizeKeyFormatType(v) === target : false;
                            });
                            // Merge state from owned endpoint to avoid 'Unknown'
                            try {
                                const owned = await getNoTTLVRequest("/access/owned", serverUrl);
                                const stateById = new Map<string, string>();
                                if (Array.isArray(owned)) {
                                    (owned as Array<{ object_id: string; state?: unknown }>).forEach((o) => {
                                        if (o.object_id) {
                                            const s = stateEnumToName(o.state);
                                            if (s) stateById.set(o.object_id, s);
                                        }
                                    });
                                }
                                filtered = filtered.map((row) => ({
                                    ...row,
                                    state: row.state || stateEnumToName(stateById.get(row.object_id)),
                                }));
                            } catch {
                                /* owned not available, keep as-is */
                            }
                            // Apply state filter if requested
                            if (stateVal) {
                                const targetState = normalizeState(stateVal);
                                filtered = filtered.filter((r) => normalizeState(r.state) === targetState);
                            }
                            setObjects(filtered);
                            setResult({ kind: "located", count: filtered.length });
                            return;
                        }
                    } catch (e) {
                        console.error("Fallback Locate without KFT failed:", e);
                    }
                }
                // Still nothing: show explicit 0 objects
                setObjects([]);
                setResult({ kind: "located", count: 0 });
            }
            // set by post-filtering to reflect visible rows
        } catch (e) {
            const msg = String(e || "");
            if (msg.startsWith("401:") || msg.startsWith("403:")) {
                setResult({ kind: "message", text: t("authRequired") });
            } else {
                setResult({ kind: "error", text: t("errorLocatingObject", { error: String(e) }) });
            }
        } finally {
            setIsLoading(false);
        }
    };

    const handleShowDetails = async (uid: string) => {
        setActionLoadingId(uid);
        try {
            const getReq = wasm.get_attributes_ttlv_request(uid);
            const getRespStr = await sendKmipRequest(getReq, serverUrl);
            if (getRespStr) {
                const parsed = await wasm.parse_get_attributes_ttlv_response(getRespStr, []);
                if (parsed instanceof Map) {
                    setDetailsData(parsed);
                } else if (parsed && typeof parsed === "object") {
                    // Convert record to Map
                    const m = new Map<string, unknown>(Object.entries(parsed as Record<string, unknown>));
                    setDetailsData(m);
                } else {
                    setDetailsData(new Map());
                }
                setDetailsForId(uid);
                setDetailsVisible(true);
            }
        } catch {
            /* ignore */
        } finally {
            setActionLoadingId(undefined);
        }
    };

    // Optional TTLV helpers for actions (best-effort; may depend on WASM exports)
    const handleRevoke = async (uid: string) => {
        if (!uid) return;
        const ok = window.confirm(t("revokeConfirm"));
        if (!ok) return;
        setActionLoadingId(uid);
        try {
            const w: any = wasm as any; // eslint-disable-line @typescript-eslint/no-explicit-any
            if (typeof w.revoke_ttlv_request === "function") {
                const req = w.revoke_ttlv_request(uid, "User-initiated revoke");
                await sendKmipRequest(req, serverUrl);
                await handleRefreshRow(uid);
                setResult({ kind: "message", text: t("actionCompleted") });
            } else {
                console.warn("revoke_ttlv_request not available in WASM package");
            }
        } catch {
            /* ignore */
        } finally {
            setActionLoadingId(undefined);
        }
    };

    const handleDestroy = async (uid: string) => {
        if (!uid) return;
        const ok = window.confirm(t("destroyConfirm"));
        if (!ok) return;
        setActionLoadingId(uid);
        try {
            const w: any = wasm as any; // eslint-disable-line @typescript-eslint/no-explicit-any
            if (typeof w.destroy_ttlv_request === "function") {
                const req = w.destroy_ttlv_request(uid, true);
                await sendKmipRequest(req, serverUrl);
                setObjects((prev) => (prev ? prev.filter((r) => r.object_id !== uid) : prev));
                setResult({ kind: "message", text: t("objectDestroyed") });
            } else {
                /* destroy_ttlv_request not available in WASM package */
            }
        } catch {
            /* ignore */
        } finally {
            setActionLoadingId(undefined);
        }
    };

    const handleRefreshRow = async (uid: string) => {
        try {
            const getReq = wasm.get_attributes_ttlv_request(uid);
            const getRespStr = await sendKmipRequest(getReq, serverUrl);
            if (getRespStr) {
                const parsed = await wasm.parse_get_attributes_ttlv_response(getRespStr, ["object_type", "state", "key_format_type"]);
                const meta =
                    parsed instanceof Map ? Object.fromEntries(parsed as Map<string, unknown>) : (parsed as Record<string, unknown>);
                setObjects((prev) => {
                    if (!prev) return prev;
                    return prev.map((row) =>
                        row.object_id === uid
                            ? {
                                  ...row,
                                  attributes: { ObjectType: (meta["object_type"] as string | undefined) || row.attributes?.ObjectType },
                                  state:
                                      (typeof meta["state"] === "string" ? (meta["state"] as string) : stateEnumToName(meta["state"])) ||
                                      row.state,
                                  meta: { ...(row.meta || {}), key_format_type: meta["key_format_type"] as string | undefined },
                              }
                            : row,
                    );
                });
            }
        } catch {
            /* ignore */
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{t("title")}</h1>

            <div className="mb-8 space-y-2">
                <p>{t("intro")}</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("basicSearchCriteria")}</h3>
                        <Row gutter={[16, 16]}>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item name="tags" label={t("common:tags")} help={t("tagsHelp")}>
                                    <Select mode="tags" placeholder={t("common:enterTags")} open={false} suffixIcon={null} />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item name="cryptographicAlgorithm" label={t("cryptoAlgorithm")} help={t("cryptoAlgorithmHelp")}>
                                    <Select options={[NO_FILTER, ...cryptoAlgorithms]} allowClear placeholder={t("selectAlgorithm")} />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item name="cryptographicLength" label={t("cryptoLength")} help={t("cryptoLengthHelp")}>
                                    <Input type="number" placeholder={t("enterLengthInBits")} min={0} />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item name="state" label={t("common:state")} help={t("common:state")}>
                                    <Select allowClear placeholder={t("selectState")} options={[NO_FILTER, ...objectStates]} />
                                </Form.Item>
                            </Col>
                        </Row>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("objectTypeAndFormat")}</h3>
                        <Row gutter={[16, 16]}>
                            <Col xs={24} sm={12} md={12} lg={12} xl={12}>
                                <Form.Item name="objectType" label={t("common:objectType")} help={t("objectTypeHelp")}>
                                    <Select options={[NO_FILTER, ...objectTypes]} allowClear placeholder={t("selectObjectType")} />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={12}>
                                <Form.Item name="keyFormatType" label={t("keyFormatType")} help={t("keyFormatTypeHelp")}>
                                    <Select options={[NO_FILTER, ...keyFormatTypes]} allowClear placeholder={t("selectKeyFormat")} />
                                </Form.Item>
                            </Col>
                        </Row>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">{t("linkedObjects")}</h3>
                        <Row gutter={[16, 16]}>
                            <Col xs={24} sm={12} md={12} lg={8} xl={8}>
                                <Form.Item name="publicKeyId" label={t("publicKeyId")} help={t("publicKeyIdHelp")}>
                                    <Input placeholder={t("enterPublicKeyId")} />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={8} xl={8}>
                                <Form.Item name="privateKeyId" label={t("privateKeyId")} help={t("privateKeyIdHelp")}>
                                    <Input placeholder={t("enterPrivateKeyId")} />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={8} xl={8}>
                                <Form.Item name="certificateId" label={t("certificateId")} help={t("certificateIdHelp")}>
                                    <Input placeholder={t("enterCertificateId")} />
                                </Form.Item>
                            </Col>
                        </Row>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("searchObjects")}
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {result && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title={t("responseTitle")}>
                        <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                            <div className="font-bold">
                                {result.kind === "located" ? t("objectsLocated", { count: result.count }) : result.text}
                            </div>

                            <Table<LocateObjectRow>
                                dataSource={objects || []}
                                rowKey="object_id"
                                pagination={{
                                    defaultPageSize: 50,
                                    showSizeChanger: true,
                                    pageSizeOptions: [50, 100, 500, 1000],
                                }}
                                scroll={{ x: "max-content" }}
                                className="border rounded"
                                columns={
                                    [
                                        {
                                            title: "UID",
                                            dataIndex: "object_id",
                                            key: "object_id",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) => a.object_id.localeCompare(b.object_id),
                                        },
                                        {
                                            title: t("colType"),
                                            key: "attributes.ObjectType",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) =>
                                                (a.attributes?.ObjectType ?? "").localeCompare(b.attributes?.ObjectType ?? ""),
                                            filters: [
                                                ...objectTypes.map((opt) => ({ text: opt.label, value: opt.value })),
                                                { text: t("common:na"), value: "N/A" },
                                            ],
                                            // OpaqueObject among probably others are not keys and have no KeyFormatType so N/A is a catch-all handled separately
                                            onFilter: (value: React.Key | boolean, record: LocateObjectRow) => {
                                                return record.attributes?.ObjectType === value;
                                            },
                                            render: (record: LocateObjectRow) => record.attributes?.ObjectType || t("common:na"),
                                        },
                                        {
                                            title: t("colAlgorithm"),
                                            key: "cryptographic_algorithm",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) =>
                                                ((a.meta?.cryptographic_algorithm as string | undefined) ?? "").localeCompare(
                                                    (b.meta?.cryptographic_algorithm as string | undefined) ?? "",
                                                ),
                                            render: (record: LocateObjectRow) =>
                                                (record.meta?.cryptographic_algorithm as string | undefined) || t("common:na"),
                                        },
                                        {
                                            title: t("colLength"),
                                            key: "cryptographic_length",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) =>
                                                ((a.meta?.cryptographic_length as number | undefined) ?? 0) -
                                                ((b.meta?.cryptographic_length as number | undefined) ?? 0),
                                            render: (record: LocateObjectRow) => {
                                                const len = record.meta?.cryptographic_length as number | undefined;
                                                return len != null ? t("bits", { len }) : t("common:na");
                                            },
                                        },
                                        {
                                            title: t("colFormat"),
                                            key: "key_format_type",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) =>
                                                (a.meta?.key_format_type ?? "").localeCompare(b.meta?.key_format_type ?? ""),
                                            filters: [
                                                ...keyFormatTypes.map((opt) => ({ text: opt.label, value: opt.value })),
                                                { text: t("common:na"), value: "N/A" },
                                            ],
                                            onFilter: (value: React.Key | boolean, record: LocateObjectRow) => {
                                                const v = record.meta?.key_format_type as string | undefined;
                                                if (value === "N/A") return !v;
                                                return v ? normalizeKeyFormatType(v) === normalizeKeyFormatType(String(value)) : false;
                                            },
                                            render: (record: LocateObjectRow) => record.meta?.key_format_type || t("common:na"),
                                        },
                                        {
                                            title: t("common:state"),
                                            dataIndex: "state",
                                            key: "state",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) =>
                                                (a.state ?? "").localeCompare(b.state ?? ""),
                                            filters: [
                                                ...objectStates.map((opt) => ({ text: opt.label, value: opt.value })),
                                                { text: t("state.unknown"), value: "Unknown" },
                                            ],
                                            onFilter: (value: React.Key | boolean, record: LocateObjectRow) => {
                                                if (value === "Unknown") return !record.state;
                                                return normalizeState(record.state) === normalizeState(String(value));
                                            },
                                            render: (state?: string) => (
                                                <Space size={4}>
                                                    <Tag color={state === "Active" ? "green" : "orange"}>{stateDisplay(state)}</Tag>
                                                </Space>
                                            ),
                                        },
                                        {
                                            title: t("colDate"),
                                            key: "date",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) => {
                                                const getDate = (row: LocateObjectRow) => {
                                                    const rotateDate = row.meta?.["rotate_date"] as number | undefined;
                                                    const initialDate = row.meta?.["initial_date"] as number | undefined;
                                                    const activationDate = row.meta?.["activation_date"] as number | undefined;
                                                    const originalCreationDate = row.meta?.["original_creation_date"] as number | undefined;
                                                    return rotateDate ?? initialDate ?? activationDate ?? originalCreationDate;
                                                };
                                                const da = getDate(a) ?? 0;
                                                const db = getDate(b) ?? 0;
                                                return da - db;
                                            },
                                            defaultSortOrder: "descend" as const,
                                            render: (row: LocateObjectRow) => {
                                                const rotateDate = row.meta?.["rotate_date"] as number | undefined;
                                                const initialDate = row.meta?.["initial_date"] as number | undefined;
                                                const activationDate = row.meta?.["activation_date"] as number | undefined;
                                                const originalCreationDate = row.meta?.["original_creation_date"] as number | undefined;
                                                const dateValue = rotateDate ?? initialDate ?? activationDate ?? originalCreationDate;
                                                if (!dateValue) {
                                                    if (/^hsm[0-9]*::/.test(row.object_id)) {
                                                        return (
                                                            <Tooltip title={t("hsmNoDate")}>
                                                                <span style={{ color: "#bbb", fontSize: "12px" }}>HSM</span>
                                                            </Tooltip>
                                                        );
                                                    }
                                                    return <span style={{ color: "#bbb" }}>—</span>;
                                                }
                                                const label = rotateDate
                                                    ? t("lastRotation")
                                                    : initialDate
                                                      ? t("created")
                                                      : activationDate
                                                        ? t("activated")
                                                        : t("created");
                                                return (
                                                    <Tooltip title={`${label}: ${formatUnixDate(dateValue)}`}>
                                                        <span style={{ fontSize: "12px", whiteSpace: "nowrap" }}>
                                                            {rotateDate && <span style={{ color: "#1677ff" }}>↻ </span>}
                                                            {formatUnixDate(dateValue)}
                                                        </span>
                                                    </Tooltip>
                                                );
                                            },
                                        },
                                        {
                                            title: t("colActions"),
                                            key: "actions",
                                            render: (row: LocateObjectRow) => (
                                                <Space size="small">
                                                    <Button
                                                        size="small"
                                                        onClick={() => handleRevoke(row.object_id)}
                                                        loading={actionLoadingId === row.object_id}
                                                    >
                                                        {t("common:revoke")}
                                                    </Button>
                                                    <Button
                                                        danger
                                                        size="small"
                                                        onClick={() => handleDestroy(row.object_id)}
                                                        loading={actionLoadingId === row.object_id}
                                                    >
                                                        {t("common:destroy")}
                                                    </Button>
                                                    <Button
                                                        size="small"
                                                        onClick={() => handleShowDetails(row.object_id)}
                                                        loading={actionLoadingId === row.object_id}
                                                    >
                                                        {t("details")}
                                                    </Button>
                                                </Space>
                                            ),
                                        },
                                    ] as TableColumnsType<LocateObjectRow>
                                }
                            />
                        </Space>
                    </Card>
                </div>
            )}
            <Modal
                title={detailsForId ? t("attributesFor", { id: detailsForId }) : t("attributes")}
                open={detailsVisible}
                onCancel={() => setDetailsVisible(false)}
                footer={<Button onClick={() => setDetailsVisible(false)}>{t("close")}</Button>}
            >
                {detailsData && detailsData.size ? <HashMapDisplay data={detailsData} /> : <div>{t("noAttributesFound")}</div>}
            </Modal>
        </div>
    );
};

export default LocateForm;
