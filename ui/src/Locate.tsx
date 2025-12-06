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

const LocateForm: React.FC = () => {
    const [form] = Form.useForm<LocateFormData>();
    const [isLoading, setIsLoading] = useState(false);
    const [res, setRes] = useState<string | undefined>(undefined);
    type LocatedRow = { object_id: string; state?: string; attributes?: { ObjectType?: string }; meta?: Record<string, unknown> };
    const [objects, setObjects] = useState<LocatedRow[] | undefined>(undefined);
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
        try {
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
                                        const parsed = await parse_get_attributes_ttlv_response(getRespStr, ["object_type", "state", "tags", "user_tags"]);
                                        let objectType: string | undefined;
                                        let state: string | undefined;
                                        let meta: Record<string, unknown> | undefined;
                                        if (parsed instanceof Map) {
                                            const mapParsed = parsed as Map<string, unknown>;
                                            meta = Object.fromEntries(mapParsed);
                                            objectType = (mapParsed.get("object_type") as string | undefined);
                                            state = (mapParsed.get("state") as string | undefined);
                                        } else {
                                            const obj = parsed as Record<string, unknown>;
                                            meta = obj;
                                            objectType = obj["object_type"] as string | undefined;
                                            state = obj["state"] as string | undefined;
                                        }
                                        // silently proceed if attributes are missing
                                        return {
                                            ...row,
                                            attributes: { ObjectType: objectType },
                                            state: state,
                                            meta,
                                        };
                                    }
                                } catch (e) {
                                    console.error(`Error fetching Get for ${row.object_id}:`, e);
                                }
                                return row;
                            })
                        );
                        // Try to supplement state from non-TTLV owned list when available
                        try {
                            const owned = await getNoTTLVRequest("/access/owned", idToken, serverUrl);
                            const stateById = new Map<string, string>();
                            if (Array.isArray(owned)) {
                                owned.forEach((o: { object_id: string; state?: string }) => {
                                    if (o.object_id && o.state) stateById.set(o.object_id, o.state);
                                });
                            }
                            const merged = enriched.map((row) => ({
                                ...row,
                                state: row.state || stateById.get(row.object_id),
                            }));
                            setObjects(merged);
                        } catch {
                            // If owned endpoint not available, keep KMIP-only enrichment
                            setObjects(enriched);
                        }
                    } catch (e) {
                        console.error("Error enriching locate results with Get:", e);
                    }
                }
                setRes(`${response.LocatedItems} Object(s) located.`);
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
                            <Table
                                dataSource={objects || []}
                                rowKey="object_id"
                                pagination={{
                                    defaultPageSize: 10,
                                    showSizeChanger: true,
                                    pageSizeOptions: [10, 20, 50, 100],
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
                                            <Tag color={state === "Active" ? "green" : "orange"}>{state || "Unknown"}</Tag>
                                        ),
                                    },

                                ]}
                            />
                        </Space>
                    </Card>
                </div>
            )}
            {/* Details modal no longer used after replacing Actions with Tags */}
        </div>
    );
};

export default LocateForm;
