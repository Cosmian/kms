import { Button, Card, Form, Input, Select, Space, Table, Tag } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { getNoTTLVRequest, sendKmipRequest } from "./utils";
import { locate_ttlv_request, parse_locate_ttlv_response } from "./wasm/pkg";
import { get_attributes_ttlv_request, parse_get_attributes_ttlv_response } from "./wasm/pkg/cosmian_kms_client_wasm";

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

const CRYPTO_ALGORITHMS = [
    {label: "Covercrypt", value: "CoverCrypt"},
    {label: "ECDH", value: "ECDH"},
    {label: "ChaCha20-Poly1305", value: "ChaCha20Poly1305"},
    {label: "AES", value: "AES"},
    {label: "Ed25519", value: "Ed25519"},
];

const KEY_FORMAT_TYPES = [
    {label: "CoverCrypt Secret Key", value: "CoverCryptSecretKey"},
    {label: "CoverCrypt Public Key", value: "CoverCryptPublicKey"},
    {label: "Raw", value: "Raw"},
    {label: "PKCS8", value: "PKCS8"},
];

const OBJECT_TYPES = [
    {label: "Certificate", value: "Certificate"},
    {label: "Symmetric Key", value: "SymmetricKey"},
    {label: "Public Key", value: "PublicKey"},
    {label: "Private Key", value: "PrivateKey"},
    {label: "Split Key", value: "SplitKey"},
    {label: "Secret Data", value: "SecretData"},
    {label: "Opaque Object", value: "OpaqueObject"},
    {label: "PGP Key", value: "PGPKey"},
    {label: "Certificate Request", value: "CertificateRequest"},
];

const OBJECT_STATES = [
    { label: "All", value: "__ALL__" },
    { label: "Pre-Active", value: "Pre-Active" },
    { label: "Active", value: "Active" },
    { label: "Deactivated", value: "Deactivated" },
    { label: "Compromised", value: "Compromised" },
    { label: "Destroyed", value: "Destroyed" },
    { label: "Destroyed Compromised", value: "Destroyed Compromised" },
    { label: "Archived", value: "Archived" },
];

const LocateForm: React.FC = () => {
    const [form] = Form.useForm<LocateFormData>();
    const [isLoading, setIsLoading] = useState(false);
    const [res, setRes] = useState<string | undefined>(undefined);
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

    const onFinish = async (values: LocateFormData) => {
        setIsLoading(true);
        setRes(undefined);
        setObjects(undefined);
        setCurrentPage(1);
        try {
            // Helpers to parse attributes and match criteria client-side
            const extractMeta = (parsed: unknown): Record<string, unknown> => {
                if (parsed instanceof Map) return Object.fromEntries(parsed as Map<string, unknown>);
                return (parsed || {}) as Record<string, unknown>;
            };

            // no-op helpers pruned: Locate handles tags & other criteria server-side

            // State-specific search: intersect Locate results with owned-by-state list
            if (values.state && values.state !== "__ALL__") {
                try {
                    const owned = await getNoTTLVRequest("/access/owned", idToken, serverUrl);
                    type OwnedEntry = { object_id?: string; state?: unknown };
                    const ownedList: OwnedEntry[] = Array.isArray(owned) ? (owned as OwnedEntry[]) : [];
                    const mappedOwnedRaw = ownedList.map((o) => ({ id: o.object_id, state: stateEnumToName(o.state) }));
                    const mappedOwned = mappedOwnedRaw.filter((o) => typeof o.id === "string") as Array<{ id: string; state?: string }>;
                    const target = normalizeState(values.state);
                    const ownedFiltered = mappedOwned.filter((o) => normalizeState(o.state) === target);

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
                    if (!hasOtherCriteria) {
                        const rows: LocatedRow[] = ownedFiltered.map((o) => ({ object_id: o.id, state: o.state }));
                        setObjects(rows);
                        setRes(`${rows.length} Object(s) located.`);

                        return;
                    }
                    // Get server-side filtered IDs (tags/algorithm/etc.)
                    const locateResp = await sendKmipRequest(
                        locate_ttlv_request(
                            values.tags,
                            values.cryptographicAlgorithm,
                            values.cryptographicLength,
                            values.keyFormatType,
                            values.objectType,
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
                    const intersection = locatedIds.filter((id) => ownedIds.has(id));

                    // Enrich only intersection
                    const enriched = await Promise.all(
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
                                        state: stateEnumToName(m["state"]) || values.state,
                                        meta: m,
                                    } as LocatedRow;
                                }
                            } catch (e) {
                                console.error(`Error fetching Get for ${uid}:`, e);
                            }
                            return { object_id: uid, state: values.state } as LocatedRow;
                        })
                    );
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
                values.cryptographicAlgorithm,
                values.cryptographicLength,
                values.keyFormatType,
                values.objectType,
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
                        if (!hasOtherCriteria && (!values.state || values.state === "__ALL__")) {
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
                                owned.forEach((o: { object_id: string; state?: string }) => {
                                    if (o.object_id && o.state) stateById.set(o.object_id, o.state);
                                });
                            }
                            let merged = enriched.map((row) => ({
                                ...row,
                                state: row.state || stateEnumToName(stateById.get(row.object_id)),
                            }));
                            // State filter if requested
                            if (values.state && values.state !== "__ALL__") {
                                const target = normalizeState(values.state);
                                merged = merged.filter((r) => normalizeState(r.state) === target);
                            }
                            // Do not re-filter by tags/criteria; Locate already applied them

                            setObjects(merged);
                            setRes(`${merged.length} Object(s) located.`);
                        } catch {
                            // If owned endpoint not available, keep KMIP-only enrichment
                            let filtered = enriched;
                            if (values.state && values.state !== "__ALL__") {
                                const target = normalizeState(values.state);
                                filtered = filtered.filter((r) => normalizeState(r.state) === target);
                            }
                            // Do not re-filter by tags/criteria; Locate already applied them

                            setObjects(filtered);
                            setRes(`${filtered.length} Object(s) located.`);
                        }
                    } catch (e) {
                        console.error("Error enriching locate results with Get:", e);
                    }
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



            <Form form={form} onFinish={onFinish} layout="vertical" initialValues={{ state: "__ALL__" }}>
                <Space direction="vertical" size="middle" style={{display: "flex"}}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Basic Search Criteria</h3>

                        <Form.Item name="tags" label="Tags" help="User tags or system tags to locate the object">
                            <Select mode="tags" placeholder="Enter tags" open={false}/>
                        </Form.Item>

                        <Form.Item
                            name="cryptographicAlgorithm"
                            label="Cryptographic Algorithm"
                            help="Algorithm used by the cryptographic object"
                        >
                            <Select options={CRYPTO_ALGORITHMS} allowClear placeholder="Select algorithm"/>
                        </Form.Item>

                        <Form.Item name="cryptographicLength" label="Cryptographic Length" help="Key size in bits">
                            <Input type="number" placeholder="Enter length in bits" min={0}/>
                        </Form.Item>

                        <Form.Item name="state" label="State" help="Lifecycle state of the object">
                            <Select allowClear placeholder="Select state" options={OBJECT_STATES} />
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Object Type and Format</h3>

                        <Form.Item name="keyFormatType" label="Key Format Type" help="Format used to store the key">
                            <Select options={KEY_FORMAT_TYPES} allowClear placeholder="Select key format"/>
                        </Form.Item>

                        <Form.Item name="objectType" label="Object Type" help="Type of cryptographic object">
                            <Select options={OBJECT_TYPES} allowClear placeholder="Select object type"/>
                        </Form.Item>
                    </Card>

                    <Card>
                        <h3 className="text-m font-bold mb-4">Linked Objects</h3>

                        <Form.Item name="publicKeyId" label="Public Key ID"
                                   help="Find objects linked to this public key">
                            <Input placeholder="Enter public key ID"/>
                        </Form.Item>

                        <Form.Item name="privateKeyId" label="Private Key ID"
                                   help="Find objects linked to this private key">
                            <Input placeholder="Enter private key ID"/>
                        </Form.Item>

                        <Form.Item name="certificateId" label="Certificate ID"
                                   help="Find objects linked to this certificate">
                            <Input placeholder="Enter certificate ID"/>
                        </Form.Item>
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
                                            onChange: (page, size) => {
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
