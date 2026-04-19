import type { TableColumnsType } from "antd";
import { Button, Card, Col, Form, Input, InputNumber, Modal, Popover, Row, Select, Space, Table, Tag, Tooltip } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "../../contexts/AuthContext";
import { AuthMethod, downloadFile, fetchAuthMethod, getNoTTLVRequest, sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";
import HashMapDisplay from "./HashMapDisplay";

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
    const NO_FILTER: AlgoOption = { value: "", label: "— No filter —" };
    const [form] = Form.useForm<LocateFormData>();
    const [isLoading, setIsLoading] = useState(false);
    const [res, setRes] = useState<string | undefined>(undefined);
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
    // Details modal removed; tags are shown inline
    const { idToken, serverUrl } = useAuth();
    const [authMethod, setAuthMethod] = useState<AuthMethod>("None");
    const responseRef = useRef<HTMLDivElement>(null);
    const [detailsVisible, setDetailsVisible] = useState<boolean>(false);
    const [detailsData, setDetailsData] = useState<Map<string, unknown> | undefined>(undefined);
    const [detailsForId, setDetailsForId] = useState<string | undefined>(undefined);
    const [actionLoadingId, setActionLoadingId] = useState<string | undefined>(undefined);
    const [rotatePopovers, setRotatePopovers] = useState<Record<string, boolean>>({});
    const [rotateInputs, setRotateInputs] = useState<Record<string, string>>({});
    const [rotateUnits, setRotateUnits] = useState<Record<string, string>>({});
    const [tablePageSize, setTablePageSize] = useState<number>(10);
    const [exportPopovers, setExportPopovers] = useState<Record<string, boolean>>({});
    const [exportFormats, setExportFormats] = useState<Record<string, string>>({});
    const [exportLoadingId, setExportLoadingId] = useState<string | undefined>(undefined);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    useEffect(() => {
        (async () => {
            try {
                const method = await fetchAuthMethod(serverUrl);
                setAuthMethod(method);
            } catch {
                /* ignore */
            }
        })();
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
    const enrichUids = async (uids: string[], idToken: string | null, serverUrl: string): Promise<LocatedRow[]> => {
        const rows = await Promise.all(
            uids.map(async (uid) => {
                try {
                    const getReq = wasm.get_attributes_ttlv_request(uid);
                    const getRespStr = await sendKmipRequest(getReq, idToken, serverUrl);
                    if (getRespStr) {
                        const parsed = await wasm.parse_get_attributes_ttlv_response(getRespStr, [
                            "object_type",
                            "state",
                            "tags",
                            "user_tags",
                            "cryptographic_algorithm",
                            "cryptographic_length",
                            "key_format_type",
                            "public_key_id",
                            "private_key_id",
                            "certificate_id",
                            "rotate_date",
                            "initial_date",
                            "activation_date",
                            "original_creation_date",
                            "rotate_interval",
                        ]);
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
    const getOwnedStateMap = async (idToken: string | null, serverUrl: string): Promise<Map<string, string>> => {
        const stateById = new Map<string, string>();
        const owned = await getNoTTLVRequest("/access/owned", idToken, serverUrl);
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
    const supplementStateFromOwned = async (rows: LocatedRow[], idToken: string | null, serverUrl: string): Promise<LocatedRow[]> => {
        try {
            const stateById = await getOwnedStateMap(idToken, serverUrl);
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
        idToken: string | null,
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
        const respStr = await sendKmipRequest(req, idToken, serverUrl);
        if (!respStr) return [];
        const resp = await wasm.parse_locate_ttlv_response(respStr);
        return Array.isArray(resp.UniqueIdentifier) ? (resp.UniqueIdentifier as string[]) : [];
    };

    // Owned-fallback without criteria
    const ownedFallbackNoCriteria = async (idToken: string | null, serverUrl: string): Promise<LocatedRow[]> => {
        const owned = await getNoTTLVRequest("/access/owned", idToken, serverUrl);
        const ids: string[] = Array.isArray(owned) ? (owned as Array<{ object_id: string }>).map((o) => o.object_id).filter(Boolean) : [];
        const enriched = await enrichUids(ids, idToken, serverUrl);
        return supplementStateFromOwned(enriched, idToken, serverUrl);
    };

    const onFinish = async (values: LocateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        setObjects(undefined);
        try {
            if (authMethod === "JWT" && !idToken) {
                setRes("Authentication required: please log in to search.");
                return;
            }
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
                    const owned = await getNoTTLVRequest("/access/owned", idToken, serverUrl);
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
                    const locatedIds = await runKmipLocate(values, cryptographicAlgorithm, keyFormatType, objectType, idToken, serverUrl);
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
                                    const getRespStr = await sendKmipRequest(getReq, idToken, serverUrl);
                                    if (getRespStr) {
                                        const parsed = await wasm.parse_get_attributes_ttlv_response(getRespStr, [
                                            "object_type",
                                            "state",
                                            "tags",
                                            "user_tags",
                                            "cryptographic_algorithm",
                                            "cryptographic_length",
                                            "key_format_type",
                                            "public_key_id",
                                            "private_key_id",
                                            "certificate_id",
                                            "rotate_date",
                                            "initial_date",
                                            "activation_date",
                                            "original_creation_date",
                                            "rotate_interval",
                                        ]);
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
                        setRes(`${enriched.length} Object(s) located.`);
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
                                idToken,
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
                                const getRespStr = await sendKmipRequest(getReq, idToken, serverUrl);
                                if (getRespStr) {
                                    const parsed = await wasm.parse_get_attributes_ttlv_response(getRespStr, [
                                        "object_type",
                                        "state",
                                        "tags",
                                        "user_tags",
                                        "cryptographic_algorithm",
                                        "cryptographic_length",
                                        "key_format_type",
                                        "public_key_id",
                                        "private_key_id",
                                        "certificate_id",
                                        "rotate_date",
                                        "initial_date",
                                        "activation_date",
                                        "original_creation_date",
                                        "rotate_interval",
                                    ]);
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
                    setRes(`${enriched.length} Object(s) located.`);
                    return;
                } catch {
                    // Fall back to Locate below
                }
            }
            const idsGeneral = await runKmipLocate(values, cryptographicAlgorithm, keyFormatType, objectType, idToken, serverUrl);
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
                        idToken,
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
                        const merged = await supplementStateFromOwned(enriched, idToken, serverUrl);
                        setObjects(merged);
                        setRes(`${merged.length} Object(s) located.`);
                        return;
                    }
                    // Try to supplement state from non-TTLV owned list when available
                    try {
                        let merged = await supplementStateFromOwned(enriched, idToken, serverUrl);
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
                        setRes(`${merged.length} Object(s) located.`);
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
                        setRes(`${filtered.length} Object(s) located.`);
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
                        const merged = await ownedFallbackNoCriteria(idToken, serverUrl);
                        setObjects(merged);
                        setRes(`${merged.length} Object(s) located.`);
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
                        const fallbackStr = await sendKmipRequest(fallbackReq, idToken, serverUrl);
                        if (fallbackStr) {
                            const fb = await wasm.parse_locate_ttlv_response(fallbackStr);
                            const ids: string[] = Array.isArray(fb.UniqueIdentifier) ? fb.UniqueIdentifier : [];
                            const target = normalizeKeyFormatType(keyFormatType);
                            const enriched = await Promise.all(
                                ids.map(async (uid: string) => {
                                    try {
                                        const getReq = wasm.get_attributes_ttlv_request(uid);
                                        const getRespStr = await sendKmipRequest(getReq, idToken, serverUrl);
                                        if (getRespStr) {
                                            const parsed = await wasm.parse_get_attributes_ttlv_response(getRespStr, [
                                                "object_type",
                                                "state",
                                                "tags",
                                                "user_tags",
                                                "cryptographic_algorithm",
                                                "cryptographic_length",
                                                "key_format_type",
                                                "rotate_date",
                                                "initial_date",
                                                "activation_date",
                                                "original_creation_date",
                                                "rotate_interval",
                                            ]);
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
                                const owned = await getNoTTLVRequest("/access/owned", idToken, serverUrl);
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
                            setRes(`${filtered.length} Object(s) located.`);
                            return;
                        }
                    } catch (e) {
                        console.error("Fallback Locate without KFT failed:", e);
                    }
                }
                // Still nothing: show explicit 0 objects
                setObjects([]);
                setRes("0 Object(s) located.");
            }
            // set by post-filtering to reflect visible rows
        } catch (e) {
            const msg = String(e || "");
            if (msg.startsWith("401:") || msg.startsWith("403:")) {
                setRes("Authentication required or forbidden. Please log in or check permissions.");
            } else {
                setRes(`Error locating object: ${e}`);
            }
        } finally {
            setIsLoading(false);
        }
    };

    const handleShowDetails = async (uid: string) => {
        setActionLoadingId(uid);
        try {
            const getReq = wasm.get_attributes_ttlv_request(uid);
            const getRespStr = await sendKmipRequest(getReq, idToken, serverUrl);
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
        const ok = window.confirm("Revoke this object? This will set its state to Revoked/Compromised as per policy.");
        if (!ok) return;
        setActionLoadingId(uid);
        try {
            const w: any = wasm as any; // eslint-disable-line @typescript-eslint/no-explicit-any
            if (typeof w.revoke_ttlv_request === "function") {
                const req = w.revoke_ttlv_request(uid, "User-initiated revoke");
                await sendKmipRequest(req, idToken, serverUrl);
                await handleRefreshRow(uid);
                setRes((prev) => (prev ? String(prev).replace(/\d+ Object\(s\) located\./, "Action completed.") : "Action completed."));
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
        const ok = window.confirm("Destroy this object? This operation is irreversible.");
        if (!ok) return;
        setActionLoadingId(uid);
        try {
            const w: any = wasm as any; // eslint-disable-line @typescript-eslint/no-explicit-any
            if (typeof w.destroy_ttlv_request === "function") {
                const req = w.destroy_ttlv_request(uid, true);
                await sendKmipRequest(req, idToken, serverUrl);
                setObjects((prev) => (prev ? prev.filter((r) => r.object_id !== uid) : prev));
                setRes("Object destroyed.");
            } else {
                /* destroy_ttlv_request not available in WASM package */
            }
        } catch {
            /* ignore */
        } finally {
            setActionLoadingId(undefined);
        }
    };

    const formatUnixDate = (ts: number): string => {
        const d = new Date(ts * 1000);
        return d.toISOString().replace("T", " ").slice(0, 16);
    };

    const formatInterval = (secs: number): string => {
        if (secs <= 0) return "disabled";
        const d = Math.floor(secs / 86400);
        if (d >= 365) return `${Math.floor(d / 365)}y`;
        if (d >= 30) return `${Math.floor(d / 30)}mo`;
        if (d >= 7) return `${Math.floor(d / 7)}w`;
        if (d > 0) return `${d}d`;
        const h = Math.floor(secs / 3600);
        if (h > 0) return `${h}h`;
        const m = Math.floor(secs / 60);
        if (m > 0) return `${m}min`;
        return `${secs}s`;
    };

    const unitToSeconds = (unit: string): number => {
        switch (unit) {
            case "seconds":
                return 1;
            case "minutes":
                return 60;
            case "hours":
                return 3600;
            case "days":
                return 86400;
            case "months":
                return 2592000;
            case "years":
                return 31536000;
            default:
                return 86400;
        }
    };

    const handleSetRotateInterval = async (uid: string, seconds: number) => {
        try {
            const req = wasm.set_attribute_ttlv_request(uid, "rotate_interval", String(seconds));
            await sendKmipRequest(req, idToken, serverUrl);
            setObjects((prev) =>
                prev ? prev.map((r) => (r.object_id === uid ? { ...r, meta: { ...(r.meta || {}), rotate_interval: seconds } } : r)) : prev,
            );
            setRotatePopovers((p) => ({ ...p, [uid]: false }));
        } catch (e) {
            console.error("Failed to set rotate_interval:", e);
        }
    };

    const handleRefreshRow = async (uid: string) => {
        try {
            const getReq = wasm.get_attributes_ttlv_request(uid);
            const getRespStr = await sendKmipRequest(getReq, idToken, serverUrl);
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

    // Returns the format options and default format for the export popover,
    // mirroring the per-type choices in KeysExport.tsx.
    const getExportFormats = (objectType?: string, meta?: Record<string, unknown>): { formats: AlgoOption[]; defaultFmt: string } => {
        if (objectType === "Certificate") {
            return {
                formats: [
                    { value: "Pem", label: "PEM" },
                    { value: "JsonTtlv", label: "JSON TTLV" },
                    { value: "Pkcs12", label: "PKCS#12" },
                    { value: "Pkcs7", label: "PKCS#7" },
                ],
                defaultFmt: "Pem",
            };
        }
        if (objectType === "SymmetricKey" || objectType === "SecretData" || objectType === "Secret Data") {
            return {
                formats: [
                    { value: "json-ttlv", label: "JSON TTLV (default)" },
                    { value: "base64", label: "Base64" },
                    { value: "raw", label: "Raw" },
                ],
                defaultFmt: "json-ttlv",
            };
        }
        if (objectType === "OpaqueObject" || objectType === "Opaque Object") {
            return {
                formats: [
                    { value: "json-ttlv", label: "JSON TTLV (default)" },
                    { value: "base64", label: "Base64" },
                    { value: "raw", label: "Raw" },
                ],
                defaultFmt: "json-ttlv",
            };
        }
        if (objectType === "PrivateKey" || objectType === "PublicKey") {
            const algo = String(meta?.["cryptographic_algorithm"] ?? "").toUpperCase();
            if (algo === "RSA") {
                return {
                    formats: [
                        { value: "json-ttlv", label: "JSON TTLV (default)" },
                        { value: "pkcs1-pem", label: "PKCS1 PEM" },
                        { value: "pkcs1-der", label: "PKCS1 DER" },
                        { value: "pkcs8-pem", label: "PKCS8 PEM" },
                        { value: "pkcs8-der", label: "PKCS8 DER" },
                        { value: "base64", label: "Base64" },
                        { value: "raw", label: "Raw" },
                    ],
                    defaultFmt: "json-ttlv",
                };
            }
            if (algo === "EC" || algo === "ECDH" || algo === "ECDSA" || algo.startsWith("ED")) {
                return {
                    formats: [
                        { value: "json-ttlv", label: "JSON TTLV (default)" },
                        { value: "sec1-pem", label: "SEC1 PEM" },
                        { value: "sec1-der", label: "SEC1 DER" },
                        { value: "pkcs8-pem", label: "PKCS8 PEM" },
                        { value: "pkcs8-der", label: "PKCS8 DER" },
                        { value: "base64", label: "Base64" },
                        { value: "raw", label: "Raw" },
                    ],
                    defaultFmt: "json-ttlv",
                };
            }
            // PQC / Covercrypt / unknown asymmetric
            return {
                formats: [
                    { value: "json-ttlv", label: "JSON TTLV (default)" },
                    { value: "raw", label: "Raw" },
                ],
                defaultFmt: "json-ttlv",
            };
        }
        // Fallback: json-ttlv + raw
        return {
            formats: [
                { value: "json-ttlv", label: "JSON TTLV (default)" },
                { value: "raw", label: "Raw" },
            ],
            defaultFmt: "json-ttlv",
        };
    };

    const handleExport = async (uid: string, format: string, objectType?: string) => {
        setExportLoadingId(uid);
        try {
            const isCert = objectType === "Certificate";
            if (isCert) {
                const req = wasm.export_certificate_ttlv_request(uid, format, undefined);
                const respStr = await sendKmipRequest(req, idToken, serverUrl);
                if (respStr) {
                    const data = await wasm.parse_export_certificate_ttlv_response(respStr, format);
                    const extMap: Record<string, string> = {
                        JsonTtlv: "json",
                        Pem: "pem",
                        Pkcs12: "p12",
                        Pkcs12Legacy: "p12",
                        Pkcs7: "p7b",
                    };
                    const ext = extMap[format] ?? "bin";
                    const mimeType =
                        format === "JsonTtlv"
                            ? "application/json"
                            : format === "Pem"
                              ? "application/x-pem-file"
                              : "application/octet-stream";
                    downloadFile(data, `certificate_${uid}.${ext}`, mimeType);
                }
            } else {
                const req = wasm.export_ttlv_request(uid, false, format, undefined, undefined, undefined);
                const respStr = await sendKmipRequest(req, idToken, serverUrl);
                if (respStr) {
                    const data = await wasm.parse_export_ttlv_response(respStr, format);
                    const extMap: Record<string, string> = {
                        "json-ttlv": "json",
                        "sec1-pem": "pem",
                        "pkcs1-pem": "pem",
                        "pkcs8-pem": "pem",
                        "sec1-der": "der",
                        "pkcs1-der": "der",
                        "pkcs8-der": "der",
                        base64: "b64",
                    };
                    const ext = extMap[format] ?? "bin";
                    const mimeType =
                        format === "json-ttlv" ? "application/json" : format === "base64" ? "text/plain" : "application/octet-stream";
                    downloadFile(data, `${uid}.${ext}`, mimeType);
                }
            }
            setExportPopovers((p) => ({ ...p, [uid]: false }));
        } catch (e) {
            console.error("Export error:", e);
        } finally {
            setExportLoadingId(undefined);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Locate Cryptographic Objects</h1>

            <div className="mb-8 space-y-2">
                <p>Search for cryptographic objects in the KMS using various criteria.</p>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Basic Search Criteria</h3>
                        <Row gutter={[16, 16]}>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item name="tags" label="Tags" help="User tags or system tags to locate the object">
                                    <Select mode="tags" placeholder="Enter tags" open={false} suffixIcon={null} />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item
                                    name="cryptographicAlgorithm"
                                    label="Cryptographic Algorithm"
                                    help="Algorithm used by the cryptographic object"
                                >
                                    <Select options={[NO_FILTER, ...cryptoAlgorithms]} allowClear placeholder="Select algorithm" />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item name="cryptographicLength" label="Cryptographic Length" help="Key size in bits">
                                    <Input type="number" placeholder="Enter length in bits" min={0} />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item name="state" label="State" help="Lifecycle state of the object">
                                    <Select allowClear placeholder="Select state" options={[NO_FILTER, ...objectStates]} />
                                </Form.Item>
                            </Col>
                        </Row>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Object Type and Format</h3>
                        <Row gutter={[16, 16]}>
                            <Col xs={24} sm={12} md={12} lg={12} xl={12}>
                                <Form.Item name="objectType" label="Object Type" help="Type of cryptographic object">
                                    <Select options={[NO_FILTER, ...objectTypes]} allowClear placeholder="Select object type" />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={12}>
                                <Form.Item name="keyFormatType" label="Key Format Type" help="Format used to store the key">
                                    <Select options={[NO_FILTER, ...keyFormatTypes]} allowClear placeholder="Select key format" />
                                </Form.Item>
                            </Col>
                        </Row>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Linked Objects</h3>
                        <Row gutter={[16, 16]}>
                            <Col xs={24} sm={12} md={12} lg={8} xl={8}>
                                <Form.Item name="publicKeyId" label="Public Key ID" help="Find objects linked to this public key">
                                    <Input placeholder="Enter public key ID" />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={8} xl={8}>
                                <Form.Item name="privateKeyId" label="Private Key ID" help="Find objects linked to this private key">
                                    <Input placeholder="Enter private key ID" />
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={8} xl={8}>
                                <Form.Item name="certificateId" label="Certificate ID" help="Find objects linked to this certificate">
                                    <Input placeholder="Enter certificate ID" />
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
                            Search Objects
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef} data-testid="response-output">
                    <Card title="Locate response">
                        <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                            <div className="font-bold">{res}</div>

                            <Table<LocateObjectRow>
                                dataSource={objects || []}
                                rowKey="object_id"
                                pagination={{
                                    pageSize: tablePageSize,
                                    showSizeChanger: true,
                                    pageSizeOptions: [10, 20, 50, 100],
                                    onShowSizeChange: (_current, size) => setTablePageSize(size),
                                }}
                                className="border rounded"
                                columns={
                                    [
                                        {
                                            title: "Object UID",
                                            dataIndex: "object_id",
                                            key: "object_id",
                                            render: (text: string, record: LocateObjectRow) => {
                                                const uid = text;
                                                const objectType = record.attributes?.ObjectType;
                                                const { formats: availableFormats, defaultFmt } = getExportFormats(objectType, record.meta);
                                                const fmt = exportFormats[uid] ?? defaultFmt;
                                                return (
                                                    <Popover
                                                        open={exportPopovers[uid]}
                                                        onOpenChange={(v) => setExportPopovers((p) => ({ ...p, [uid]: v }))}
                                                        trigger={["hover", "click"]}
                                                        mouseLeaveDelay={0.4}
                                                        content={
                                                            <Space size="small">
                                                                <Select
                                                                    size="small"
                                                                    style={{ width: 150 }}
                                                                    value={fmt}
                                                                    options={availableFormats}
                                                                    onChange={(v) => setExportFormats((p) => ({ ...p, [uid]: v }))}
                                                                />
                                                                <Button
                                                                    size="small"
                                                                    type="primary"
                                                                    loading={exportLoadingId === uid}
                                                                    onClick={() => handleExport(uid, fmt, objectType)}
                                                                >
                                                                    Export
                                                                </Button>
                                                            </Space>
                                                        }
                                                    >
                                                        <span style={{ fontFamily: "monospace", fontSize: 12, cursor: "default" }}>
                                                            {uid}
                                                        </span>
                                                    </Popover>
                                                );
                                            },
                                        },
                                        {
                                            title: "Type",
                                            key: "attributes.ObjectType",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) =>
                                                (a.attributes?.ObjectType ?? "").localeCompare(b.attributes?.ObjectType ?? ""),
                                            filters: [
                                                ...objectTypes.map((t) => ({ text: t.label, value: t.value })),
                                                { text: "N/A", value: "N/A" },
                                            ],
                                            // OpaqueObject among probably others are not keys and have no KeyFormatType so N/A is a catch-all handled separately
                                            onFilter: (value: React.Key | boolean, record: LocateObjectRow) => {
                                                return record.attributes?.ObjectType === value;
                                            },
                                            render: (record: LocateObjectRow) => record.attributes?.ObjectType || "N/A",
                                        },
                                        {
                                            title: "Key Format Type",
                                            key: "key_format_type",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) =>
                                                (a.meta?.key_format_type ?? "").localeCompare(b.meta?.key_format_type ?? ""),
                                            filters: [
                                                ...keyFormatTypes.map((k) => ({ text: k.label, value: k.value })),
                                                { text: "N/A", value: "N/A" },
                                            ],
                                            onFilter: (value: React.Key | boolean, record: LocateObjectRow) => {
                                                const v = record.meta?.key_format_type as string | undefined;
                                                if (value === "N/A") return !v;
                                                return v ? normalizeKeyFormatType(v) === normalizeKeyFormatType(String(value)) : false;
                                            },
                                            render: (record: LocateObjectRow) => record.meta?.key_format_type || "N/A",
                                        },
                                        {
                                            title: "State",
                                            dataIndex: "state",
                                            key: "state",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) =>
                                                (a.state ?? "").localeCompare(b.state ?? ""),
                                            filters: [
                                                ...objectStates.map((s) => ({ text: s.label, value: s.value })),
                                                { text: "Unknown", value: "Unknown" },
                                            ],
                                            onFilter: (value: React.Key | boolean, record: LocateObjectRow) => {
                                                if (value === "Unknown") return !record.state;
                                                return normalizeState(record.state) === normalizeState(String(value));
                                            },
                                            render: (state?: string) => (
                                                <Space size={4}>
                                                    <Tag color={state === "Active" ? "green" : "orange"}>{state || "Unknown"}</Tag>
                                                </Space>
                                            ),
                                        },
                                        {
                                            title: "Date",
                                            key: "date",
                                            sorter: (a: LocateObjectRow, b: LocateObjectRow) => {
                                                const da = (a.meta?.["rotate_date"] ??
                                                    a.meta?.["initial_date"] ??
                                                    a.meta?.["activation_date"] ??
                                                    a.meta?.["original_creation_date"]) as number | undefined;
                                                const db = (b.meta?.["rotate_date"] ??
                                                    b.meta?.["initial_date"] ??
                                                    b.meta?.["activation_date"] ??
                                                    b.meta?.["original_creation_date"]) as number | undefined;
                                                return (da ?? 0) - (db ?? 0);
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
                                                            <Tooltip title="HSM-resident keys have no creation date stored in the PKCS#11 token">
                                                                <span style={{ color: "#bbb", fontSize: "12px" }}>HSM</span>
                                                            </Tooltip>
                                                        );
                                                    }
                                                    return <span style={{ color: "#bbb" }}>—</span>;
                                                }
                                                const label = rotateDate
                                                    ? "Last rotation"
                                                    : initialDate
                                                      ? "Created"
                                                      : activationDate
                                                        ? "Activated"
                                                        : "Created";
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
                                            title: "Actions",
                                            key: "actions",
                                            render: (row: LocateObjectRow) => {
                                                const interval = row.meta?.["rotate_interval"] as number | undefined;
                                                const hasInterval = interval != null && Number(interval) > 0;
                                                return (
                                                    <Space size="small">
                                                        <Button
                                                            size="small"
                                                            onClick={() => handleRevoke(row.object_id)}
                                                            loading={actionLoadingId === row.object_id}
                                                        >
                                                            Revoke
                                                        </Button>
                                                        <Button
                                                            danger
                                                            size="small"
                                                            onClick={() => handleDestroy(row.object_id)}
                                                            loading={actionLoadingId === row.object_id}
                                                        >
                                                            Destroy
                                                        </Button>
                                                        <Button
                                                            size="small"
                                                            onClick={() => handleShowDetails(row.object_id)}
                                                            loading={actionLoadingId === row.object_id}
                                                        >
                                                            Details
                                                        </Button>
                                                        <Popover
                                                            open={rotatePopovers[row.object_id] ?? false}
                                                            onOpenChange={(v) => setRotatePopovers((p) => ({ ...p, [row.object_id]: v }))}
                                                            title="Auto-Rotate"
                                                            trigger="click"
                                                            content={
                                                                <Space direction="vertical" size="small" style={{ width: 260 }}>
                                                                    {hasInterval && (
                                                                        <div>
                                                                            Current: <b>{formatInterval(Number(interval))}</b>
                                                                        </div>
                                                                    )}
                                                                    <Space>
                                                                        <InputNumber
                                                                            size="small"
                                                                            min={0}
                                                                            addonAfter={
                                                                                <Select
                                                                                    size="small"
                                                                                    style={{ width: 76 }}
                                                                                    value={rotateUnits[row.object_id] ?? "days"}
                                                                                    onChange={(v: string) =>
                                                                                        setRotateUnits((p) => ({
                                                                                            ...p,
                                                                                            [row.object_id]: v,
                                                                                        }))
                                                                                    }
                                                                                    options={[
                                                                                        { value: "seconds", label: "sec" },
                                                                                        { value: "minutes", label: "min" },
                                                                                        { value: "hours", label: "h" },
                                                                                        { value: "days", label: "days" },
                                                                                        { value: "months", label: "mo" },
                                                                                        { value: "years", label: "yr" },
                                                                                    ]}
                                                                                />
                                                                            }
                                                                            style={{ width: 170 }}
                                                                            value={
                                                                                rotateInputs[row.object_id] !== undefined
                                                                                    ? Number(rotateInputs[row.object_id])
                                                                                    : undefined
                                                                            }
                                                                            onChange={(v) =>
                                                                                setRotateInputs((p) => ({
                                                                                    ...p,
                                                                                    [row.object_id]: String(v ?? 0),
                                                                                }))
                                                                            }
                                                                            placeholder="Interval"
                                                                        />
                                                                    </Space>
                                                                    <Space>
                                                                        <Button
                                                                            size="small"
                                                                            type="primary"
                                                                            onClick={() =>
                                                                                handleSetRotateInterval(
                                                                                    row.object_id,
                                                                                    Math.round(
                                                                                        Number(rotateInputs[row.object_id] ?? 0) *
                                                                                            unitToSeconds(
                                                                                                rotateUnits[row.object_id] ?? "days",
                                                                                            ),
                                                                                    ),
                                                                                )
                                                                            }
                                                                        >
                                                                            Set
                                                                        </Button>
                                                                        {hasInterval && (
                                                                            <Button
                                                                                size="small"
                                                                                danger
                                                                                onClick={() => handleSetRotateInterval(row.object_id, 0)}
                                                                            >
                                                                                Disable
                                                                            </Button>
                                                                        )}
                                                                    </Space>
                                                                </Space>
                                                            }
                                                        >
                                                            {hasInterval ? (
                                                                <Tag color="blue" style={{ cursor: "pointer", fontSize: "11px" }}>
                                                                    ↻ {formatInterval(Number(interval))}
                                                                </Tag>
                                                            ) : (
                                                                <Button size="small" style={{ fontSize: "11px" }}>
                                                                    Auto-Rotate
                                                                </Button>
                                                            )}
                                                        </Popover>
                                                    </Space>
                                                );
                                            },
                                        },
                                    ] as TableColumnsType<LocateObjectRow>
                                }
                            />
                        </Space>
                    </Card>
                </div>
            )}
            <Modal
                title={detailsForId ? `Attributes for ${detailsForId}` : "Attributes"}
                open={detailsVisible}
                onCancel={() => setDetailsVisible(false)}
                footer={<Button onClick={() => setDetailsVisible(false)}>Close</Button>}
            >
                {detailsData && detailsData.size ? <HashMapDisplay data={detailsData} /> : <div>No attributes found.</div>}
            </Modal>
            {/* Details modal no longer used after replacing Actions with Tags */}
        </div>
    );
};

export default LocateForm;
