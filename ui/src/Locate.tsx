import { Button, Card, Col, Form, Input, Row, Select, Space, Table, Tag } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { getNoTTLVRequest, sendKmipRequest } from "./utils";
import { locate_ttlv_request, parse_locate_ttlv_response } from "./wasm/pkg";
import { get_attributes_ttlv_request, get_crypto_algorithms, get_key_format_types, get_object_states, get_object_types, parse_get_attributes_ttlv_response } from "./wasm/pkg/cosmian_kms_client_wasm";

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
    type LocatedRow = { object_id: string; state?: string; attributes?: { ObjectType?: string }; meta?: Record<string, unknown> };
    const [objects, setObjects] = useState<LocatedRow[] | undefined>(undefined);
    const [currentPage, setCurrentPage] = useState<number>(1);
    const [pageSize, setPageSize] = useState<number>(10);
    const normalizeState = (s?: string) => (s || "").toLowerCase().replace(/\s+/g, "").replace(/-/g, "");
    const stateEnumToName = (v: unknown): string | undefined => {
        if (v == null) return undefined;
        const s = String(v);
        const n = Number(s);
        if (!Number.isNaN(n)) {
            switch (n) {
                case 1: return "Pre-Active";
                case 2: return "Active";
                case 3: return "Deactivated";
                case 4: return "Compromised";
                case 5: return "Destroyed";
                case 6: return "Destroyed Compromised";
                case 7: return "Archived";
                default: return s;
            }
        }
        // If s already a textual state (possibly with hyphen), return as-is
        return s;
    };
    // Details modal removed; tags are shown inline
    const {idToken, serverUrl} = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({behavior: "smooth"});
        }
    }, [res]);

    useEffect(() => {
        try {
            const algos = (get_crypto_algorithms() as unknown) as AlgoOption[];
            if (Array.isArray(algos)) setCryptoAlgorithms(algos);
        } catch {
            /* ignore if WASM not ready */
        }
        try {
            const kf = (get_key_format_types() as unknown) as AlgoOption[];
            if (Array.isArray(kf)) setKeyFormatTypes(kf);
        } catch {
            /* ignore if WASM not ready */
        }
        try {
            const ot = (get_object_types() as unknown) as AlgoOption[];
            if (Array.isArray(ot)) setObjectTypes(ot);
        } catch {
            /* ignore if WASM not ready */
        }
        try {
            const os = (get_object_states() as unknown) as AlgoOption[];
            if (Array.isArray(os)) setObjectStates(os);
        } catch {
            /* ignore if WASM not ready */
        }
    }, []);

    const onFinish = async (values: LocateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        setObjects(undefined);
        setCurrentPage(1);
        try {
            const norm = (s?: string) => (s && s.trim() !== "" ? s : undefined);
            const keyFormatType = norm(values.keyFormatType);
            const cryptographicAlgorithm = norm(values.cryptographicAlgorithm);
            const objectType = norm(values.objectType);
            const stateVal = norm(values.state);
            const kftNorm = (s: string) => s.toLowerCase().replace(/\s+|[-_]/g, "");
            // Helpers to parse attributes and match criteria client-side
            const extractMeta = (parsed: unknown): Record<string, unknown> => {
                if (parsed instanceof Map) return Object.fromEntries(parsed as Map<string, unknown>);
                return (parsed || {}) as Record<string, unknown>;
            };

            // no-op helpers pruned: Locate handles tags & other criteria server-side

            // State-specific search: intersect Locate results with owned-by-state list
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
                        values.certificateId
                    );
                    if (!hasOtherCriteria) {
                        // Enrich state-only results so Type and Key Format Type are available
                        const enriched = await Promise.all(
                            ownedFiltered.map(async (o) => {
                                const uid = o.id;
                                try {
                                    const getReq = get_attributes_ttlv_request(uid);
                                    const getRespStr = await sendKmipRequest(getReq, idToken, serverUrl);
                                    if (getRespStr) {
                                        const parsed = await parse_get_attributes_ttlv_response(getRespStr, [
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
                            })
                        );
                        setObjects(enriched);
                        setRes(`${enriched.length} Object(s) located.`);
                        return;
                    }
                    // Get server-side filtered IDs (tags/algorithm/etc.)
                    const locateResp = await sendKmipRequest(
                        locate_ttlv_request(
                            values.tags,
                            cryptographicAlgorithm,
                            values.cryptographicLength,
                            keyFormatType,
                            objectType,
                            values.publicKeyId,
                            values.privateKeyId,
                            values.certificateId
                        ),
                        idToken,
                        serverUrl
                    );
                    let locatedIds: string[] = [];
                    if (locateResp) {
                        const lr = await parse_locate_ttlv_response(locateResp);
                        if (lr.UniqueIdentifier && lr.UniqueIdentifier.length) locatedIds = lr.UniqueIdentifier as string[];
                    }
                    const ownedIds = new Set(ownedFiltered.map((o) => o.id));
                    let intersection = locatedIds.filter((id) => ownedIds.has(id));

                    // Fallback: if KFT provided but intersection is empty, drop KFT server-side and filter locally
                    if (keyFormatType && intersection.length === 0) {
                        try {
                            const fallbackLocateResp = await sendKmipRequest(
                                locate_ttlv_request(
                                    values.tags,
                                    cryptographicAlgorithm,
                                    values.cryptographicLength,
                                    undefined,
                                    objectType,
                                    values.publicKeyId,
                                    values.privateKeyId,
                                    values.certificateId
                                ),
                                idToken,
                                serverUrl
                            );
                            if (fallbackLocateResp) {
                                const flr = await parse_locate_ttlv_response(fallbackLocateResp);
                                const fbIds: string[] = Array.isArray(flr.UniqueIdentifier) ? flr.UniqueIdentifier : [];
                                intersection = fbIds.filter((id) => ownedIds.has(id));
                            }
                        } catch (e) {
                            console.warn("State+KFT fallback Locate without KFT failed:", e);
                        }
                    }

                    // Enrich only intersection
                    let enriched = await Promise.all(
                        intersection.map(async (uid: string) => {
                            try {
                                const getReq = get_attributes_ttlv_request(uid);
                                const getRespStr = await sendKmipRequest(getReq, idToken, serverUrl);
                                if (getRespStr) {
                                    const parsed = await parse_get_attributes_ttlv_response(getRespStr, [
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
                            return { object_id: uid, state: stateVal } as LocatedRow;
                        })
                    );
                    // Enforce KFT filter client-side if provided
                    if (keyFormatType) {
                        const target = kftNorm(keyFormatType);
                        enriched = enriched.filter((row) => {
                            const v = row.meta?.["key_format_type"] as string | undefined;
                            return v ? kftNorm(v) === target : false;
                        });
                    }
                    setObjects(enriched);
                    setRes(`${enriched.length} Object(s) located.`);
                    return;
                } catch (e) {
                    console.error("Owned+filter fallback failed:", e);
                    // Fall back to Locate below
                }
            }
            const request = locate_ttlv_request(
                values.tags,
                cryptographicAlgorithm,
                values.cryptographicLength,
                keyFormatType,
                objectType,
                values.publicKeyId,
                values.privateKeyId,
                values.certificateId
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = await parse_locate_ttlv_response(result_str);
                if (response.UniqueIdentifier && response.UniqueIdentifier.length) {
                    const mapped: LocatedRow[] = response.UniqueIdentifier.map((uuid: string) => ({
                        object_id: uuid,
                        attributes: { ObjectType: undefined },
                        state: undefined,
                        meta: undefined,
                    }));

                    setObjects(mapped);

                    // Enrich each object with Type and State using KMIP Get
                    try {
                        const enriched = await Promise.all(
                            mapped.map(async (row: LocatedRow) => {
                                try {
                                    const getReq = get_attributes_ttlv_request(row.object_id);
                                    const getRespStr = await sendKmipRequest(getReq, idToken, serverUrl);
                                    if (getRespStr) {
                                        const parsed = await parse_get_attributes_ttlv_response(getRespStr, [
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
                                        ]);
                                        const m = extractMeta(parsed);
                                        // silently proceed if attributes are missing
                                        return {
                                            ...row,
                                            attributes: { ObjectType: m["object_type"] as string | undefined },
                                            state: stateEnumToName(m["state"]),
                                            meta: m,
                                        };
                                    }
                                } catch (e) {
                                    console.error(`Error fetching Get for ${row.object_id}:`, e);
                                }
                                return row;
                            })
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
                            values.certificateId
                        );
                        if (!hasOtherCriteria && !stateVal) {
                            // Merge state labels from owned list for display, without filtering
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
                                const merged = enriched.map((row) => ({
                                    ...row,
                                    state: row.state || stateEnumToName(stateById.get(row.object_id)),
                                }));
                                setObjects(merged);
                                setRes(`${merged.length} Object(s) located.`);

                                return;
                            } catch {
                                setObjects(enriched);
                                setRes(`${enriched.length} Object(s) located.`);
                                return;
                            }
                        }
                        // Try to supplement state from non-TTLV owned list when available
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
                            let merged = enriched.map((row) => ({
                                ...row,
                                state: row.state || stateEnumToName(stateById.get(row.object_id)),
                            }));
                            // State filter if requested
                            if (stateVal) {
                                const target = normalizeState(stateVal);
                                merged = merged.filter((r) => normalizeState(r.state) === target);
                            }
                            // Enforce KFT filter if provided
                            if (keyFormatType) {
                                const targetKft = kftNorm(keyFormatType);
                                merged = merged.filter((r) => {
                                    const v = r.meta?.["key_format_type"] as string | undefined;
                                    return v ? kftNorm(v) === targetKft : false;
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
                                const targetKft = kftNorm(keyFormatType);
                                filtered = filtered.filter((r) => {
                                    const v = r.meta?.["key_format_type"] as string | undefined;
                                    return v ? kftNorm(v) === targetKft : false;
                                });
                            }
                            // Do not re-filter by tags/criteria; Locate already applied them

                            setObjects(filtered);
                            setRes(`${filtered.length} Object(s) located.`);
                        }
                    } catch (e) {
                        console.error("Error enriching locate results with Get:", e);
                    }
                } else {
                    // No results returned by Locate: if Key Format Type filter is set, try fallback client-side filtering
                    if (keyFormatType) {
                        try {
                            const fallbackReq = locate_ttlv_request(
                                values.tags,
                                cryptographicAlgorithm,
                                values.cryptographicLength,
                                undefined,
                                objectType,
                                values.publicKeyId,
                                values.privateKeyId,
                                values.certificateId
                            );
                            const fallbackStr = await sendKmipRequest(fallbackReq, idToken, serverUrl);
                            if (fallbackStr) {
                                const fb = await parse_locate_ttlv_response(fallbackStr);
                                const ids: string[] = Array.isArray(fb.UniqueIdentifier) ? fb.UniqueIdentifier : [];
                                const target = kftNorm(keyFormatType);
                                const enriched = await Promise.all(
                                    ids.map(async (uid: string) => {
                                        try {
                                            const getReq = get_attributes_ttlv_request(uid);
                                            const getRespStr = await sendKmipRequest(getReq, idToken, serverUrl);
                                            if (getRespStr) {
                                                const parsed = await parse_get_attributes_ttlv_response(getRespStr, [
                                                    "object_type",
                                                    "state",
                                                    "tags",
                                                    "user_tags",
                                                    "cryptographic_algorithm",
                                                    "cryptographic_length",
                                                    "key_format_type",
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
                                    })
                                );
                                let filtered = enriched.filter((row) => {
                                    const v = row.meta?.["key_format_type"] as string | undefined;
                                    return v ? kftNorm(v) === target : false;
                                });
                                // Merge state from owned endpoint to avoid 'Unknown'
                                try {
                                    const owned = await getNoTTLVRequest("/access/owned", idToken, serverUrl);
                                    const stateById = new Map<string, string>();
                                    if (Array.isArray(owned)) {
                                        (owned as Array<{ object_id: string; state?: unknown }>).
                                            forEach((o) => {
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
                            console.warn("KeyFormatType fallback failed:", e);
                        }
                    }
                    // Still nothing: show explicit 0 objects
                    setObjects([]);
                    setRes("0 Object(s) located.");
                }
                // set by post-filtering to reflect visible rows
            }
        } catch (e) {
            setRes(`Error locating object: ${e}`);
            console.error("Error locating object:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Locate Cryptographic Objects</h1>

            <div className="mb-8 space-y-2">
                <p>Search for cryptographic objects in the KMS using various criteria.</p>
                <p>The HSM, if any, will not be searched</p>
            </div>



            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{display: "flex"}}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Basic Search Criteria</h3>
                        <Row gutter={[16, 16]}>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item name="tags" label="Tags" help="User tags or system tags to locate the object">
                                    <Select mode="tags" placeholder="Enter tags" open={false}/>
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item
                                    name="cryptographicAlgorithm"
                                    label="Cryptographic Algorithm"
                                    help="Algorithm used by the cryptographic object"
                                >
                                    <Select options={[NO_FILTER, ...cryptoAlgorithms]} allowClear placeholder="Select algorithm"/>
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={6}>
                                <Form.Item name="cryptographicLength" label="Cryptographic Length" help="Key size in bits">
                                    <Input type="number" placeholder="Enter length in bits" min={0}/>
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
                                    <Select options={[NO_FILTER, ...objectTypes]} allowClear placeholder="Select object type"/>
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={12} xl={12}>
                                <Form.Item name="keyFormatType" label="Key Format Type" help="Format used to store the key">
                                    <Select options={[NO_FILTER, ...keyFormatTypes]} allowClear placeholder="Select key format"/>
                                </Form.Item>
                            </Col>
                        </Row>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Linked Objects</h3>
                        <Row gutter={[16, 16]}>
                            <Col xs={24} sm={12} md={12} lg={8} xl={8}>
                                <Form.Item name="publicKeyId" label="Public Key ID"
                                           help="Find objects linked to this public key">
                                    <Input placeholder="Enter public key ID"/>
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={8} xl={8}>
                                <Form.Item name="privateKeyId" label="Private Key ID"
                                           help="Find objects linked to this private key">
                                    <Input placeholder="Enter private key ID"/>
                                </Form.Item>
                            </Col>
                            <Col xs={24} sm={12} md={12} lg={8} xl={8}>
                                <Form.Item name="certificateId" label="Certificate ID"
                                           help="Find objects linked to this certificate">
                                    <Input placeholder="Enter certificate ID"/>
                                </Form.Item>
                            </Col>
                        </Row>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading}
                                className="w-full text-white font-medium">
                            Search Objects
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Locate response">
                        <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                            <div className="font-bold">{res}</div>

                            {(() => {
                                const data = objects || [];
                                const start = (currentPage - 1) * pageSize;
                                const end = start + pageSize;
                                const pageData = data.slice(start, end);
                                return (
                                    <Table
                                        dataSource={pageData}
                                        rowKey="object_id"
                                        pagination={{
                                            current: currentPage,
                                            pageSize,
                                            total: data.length,
                                            showSizeChanger: true,
                                            pageSizeOptions: [10, 20, 50, 100],
                                            onChange: (page: number, size?: number) => {
                                                setCurrentPage(page);
                                                if (size && size !== pageSize) {
                                                    setPageSize(size);
                                                    setCurrentPage(1);
                                                }
                                            },
                                        }}
                                        className="border rounded"
                                        columns={[
                                            {
                                                title: "Object UID",
                                                dataIndex: "object_id",
                                                key: "object_id",
                                            },
                                            {
                                                title: "Type",
                                                key: "attributes.ObjectType",
                                                render: (record: { attributes?: { ObjectType?: string } }) =>
                                                    record.attributes?.ObjectType || "N/A",
                                            },
                                            {
                                                title: "Key Format Type",
                                                key: "key_format_type",
                                                render: (record: { meta?: Record<string, unknown> }) =>
                                                    (record.meta?.["key_format_type"] as string | undefined) || "N/A",
                                            },
                                            {
                                                title: "State",
                                                dataIndex: "state",
                                                key: "state",
                                                render: (state?: string) => (
                                                    <Space size={4}>
                                                        <Tag color={state === "Active" ? "green" : "orange"}>{state || "Unknown"}</Tag>
                                                    </Space>
                                                ),
                                            },

                                        ]}
                                    />
                                );
                            })()}
                        </Space>
                    </Card>
                </div>
            )}
            {/* Details modal no longer used after replacing Actions with Tags */}
        </div>
    );
};

export default LocateForm;
