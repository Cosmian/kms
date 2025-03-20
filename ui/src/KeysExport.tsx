import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { downloadFile, sendKmipRequest } from "./utils";
import { export_ttlv_request, parse_export_ttlv_response } from "./wasm/pkg";

interface KeyExportFormData {
    keyId?: string;
    tags?: string[];
    keyFormat: ExportKeyFormat;
    unwrap: boolean;
    wrapKeyId?: string;
    allowRevoked: boolean;
    wrappingAlgorithm?: WrappingAlgorithm;
    authenticatedAdditionalData?: string;
}

type ExportKeyFormat =
    | "json-ttlv"
    | "sec1-pem"
    | "sec1-der"
    | "pkcs1-pem"
    | "pkcs1-der"
    | "pkcs8-pem"
    | "pkcs8-der"
    | "spki-pem"
    | "spki-der"
    | "base64"
    | "raw";

type WrappingAlgorithm = "nist-key-wrap" | "aes-gcm" | "rsa-pkcs-v15" | "rsa-oaep" | "rsa-aes-key-wrap";

const WRAPPING_ALGORITHMS: { label: string; value: WrappingAlgorithm }[] = [
    { label: "NIST Key Wrap (RFC 5649)", value: "nist-key-wrap" },
    { label: "AES GCM", value: "aes-gcm" },
    { label: "RSA PKCS v1.5", value: "rsa-pkcs-v15" },
    { label: "RSA OAEP", value: "rsa-oaep" },
    { label: "RSA AES Key Wrap", value: "rsa-aes-key-wrap" },
];

type KeyType = "rsa" | "ec" | "symmetric" | "covercrypt";

const exportFileExtension = {
    "json-ttlv": "json",
    "sec1-pem": "pem",
    "pkcs1-pem": "pem",
    "pkcs8-pem": "pem",
    "spki-pem": "pem",
    "sec1-der": "der",
    "pkcs1-der": "der",
    "pkcs8-der": "der",
    "spki-der": "der",
    base64: "b64",
    raw: "",
};

interface KeyExportFormProps {
    key_type: KeyType;
}

const KeyExportForm: React.FC<KeyExportFormProps> = (props: KeyExportFormProps) => {
    const [form] = Form.useForm<KeyExportFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: KeyExportFormData) => {
        console.log("Export key values:", values);
        setIsLoading(true);
        setRes(undefined);
        const id = values.keyId ? values.keyId : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing key identifier.");
                throw Error("Missing key identifier");
            }
            const request = export_ttlv_request(id, values.unwrap, values.keyFormat, values.wrapKeyId, values.wrappingAlgorithm);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const data = await parse_export_ttlv_response(result_str, values.keyFormat);
                const filename = `${id}.${exportFileExtension[values.keyFormat]}`;
                let mimeType;
                switch (values.keyFormat) {
                    case "json-ttlv":
                        mimeType = "application/json";
                        break;
                    case "base64":
                        mimeType = "text/plain";
                        break;
                    default:
                        mimeType = "application/octet-stream";
                }
                downloadFile(data, filename, mimeType);
                setRes("File has been exported");
            }
        } catch (e) {
            setRes(`Error exporting key: ${e}`);
            console.error("Error exporting key:", e);
        } finally {
            setIsLoading(false);
        }
    };

    let key_type_string = "";
    let key_formats = [];
    if (props.key_type === "rsa") {
        key_type_string = "an RSA";
        key_formats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "PKCS1 PEM", value: "pkcs1-pem" },
            { label: "PKCS1 DER", value: "pkcs1-der" },
            { label: "PKCS8 PEM", value: "pkcs8-pem" },
            { label: "PKCS8 DER", value: "pkcs8-der" },
            { label: "Base64", value: "base64" },
            { label: "Raw", value: "raw" },
        ];
    } else if (props.key_type === "ec") {
        key_type_string = "an EC";
        key_formats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "SEC1 PEM", value: "sec1-pem" },
            { label: "SEC1 DER", value: "sec1-der" },
            { label: "PKCS8 PEM", value: "pkcs8-pem" },
            { label: "PKCS8 DER", value: "pkcs8-der" },
            { label: "Base64", value: "base64" },
            { label: "Raw", value: "raw" },
        ];
    } else if (props.key_type === "symmetric") {
        key_type_string = "a symmetric";
        key_formats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "Base64", value: "base64" },
            { label: "Raw", value: "raw" },
        ];
    } else {
        key_type_string = "a Covercrypt";
        key_formats = [
            { label: "JSON TTLV (default)", value: "json-ttlv" },
            { label: "Raw", value: "raw" },
        ];
    }

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Export {key_type_string} key</h1>

            <div className="mb-8 space-y-2">
                <p>Export {key_type_string} key from the KMS. The key can be identified using either its ID or associated tags.</p>
                <p>The key can optionally be unwrapped and/or wrapped when exported.</p>
                <p className="text-sm text-yellow-600">Note: Wrapping a key that is already wrapped is an error.</p>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    keyFormat: "json-ttlv",
                    unwrap: false,
                    allowRevoked: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Key Identification (required)</h3>
                        <Form.Item name="keyId" label="Key ID" help="The unique identifier of the key stored in the KMS">
                            <Input placeholder="Enter key ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Alternative to Key ID: specify tags to identify the key">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="keyFormat"
                            label="Key Format"
                            help="Format for the exported key. JSON TTLV is recommended for later re-import."
                            rules={[{ required: true }]}
                        >
                            <Select options={key_formats} />
                        </Form.Item>
                    </Card>
                    <Card>
                        <h3 className="text-m font-bold mb-4">Wrapping Options</h3>

                        <Form.Item name="unwrap" valuePropName="checked">
                            <Checkbox>Unwrap the key before export</Checkbox>
                        </Form.Item>

                        <Form.Item name="wrapKeyId" label="Wrap Key ID" help="ID of the key/certificate to use for wrapping">
                            <Input placeholder="Enter wrap key ID" />
                        </Form.Item>

                        <Form.Item name="wrappingAlgorithm" label="Wrapping Algorithm" help="Algorithm to use when wrapping the key">
                            <Select options={WRAPPING_ALGORITHMS} placeholder="Select wrapping algorithm" />
                        </Form.Item>

                        <Form.Item
                            name="authenticatedAdditionalData"
                            label="Authenticated Additional Data"
                            help="Only available for AES GCM wrapping"
                        >
                            <Input placeholder="Enter authenticated data" />
                        </Form.Item>
                    </Card>
                    <Card>
                        <Form.Item
                            name="allowRevoked"
                            valuePropName="checked"
                            help="Allow exporting revoked and destroyed keys (user must be the owner)"
                        >
                            <Checkbox>Allow revoked keys</Checkbox>
                        </Form.Item>
                    </Card>
                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Export Key
                        </Button>
                    </Form.Item>
                </Space>
            </Form>
            {res && (
                <div ref={responseRef}>
                    <Card title="Key export response">{res}</Card>
                </div>
            )}
        </div>
    );
};

export default KeyExportForm;
