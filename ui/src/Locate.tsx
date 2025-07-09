import {Button, Card, Form, Input, List, Select, Space} from "antd";
import React, {useEffect, useRef, useState} from "react";
import {useAuth} from "./AuthContext";
import {sendKmipRequest} from "./utils";
import {locate_ttlv_request, parse_locate_ttlv_response} from "./wasm/pkg";

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
    const [objects, setObjects] = useState<string[] | undefined>(undefined);
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
                    setObjects(response.UniqueIdentifier);
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
                        <List
                            header={<div className="font-bold">{res}</div>}
                            size="small"
                            bordered
                            dataSource={objects}
                            renderItem={(uuid) => <List.Item>{uuid}</List.Item>}
                        />
                    </Card>
                </div>
            )}
        </div>
    );
};

export default LocateForm;
