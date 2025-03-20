import { Button, Card, Form, Input, Select, Space, Typography } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import HashMapDisplay from "./HashMapDisplay";
import { sendKmipRequest } from "./utils";
import { get_attributes_ttlv_request, parse_get_attributes_ttlv_response } from "./wasm/pkg/cosmian_kms_ui_utils";

const { Title } = Typography;
const { Option } = Select;

// Define link types based on the CLAP documentation
const LINK_TYPES = [
    {
        value: "Certificate",
        label: "Certificate",
        description:
            "For Certificate objects: the parent certificate for a certificate in a certificate chain. For Public Key objects: the corresponding certificate(s), containing the same public key.",
    },
    {
        value: "PublicKey",
        label: "Public Key",
        description:
            "For a Private Key object: the public key corresponding to the private key. For a Certificate object: the public key contained in the certificate.",
    },
    { value: "PrivateKey", label: "Private Key", description: "For a Public Key object: the private key corresponding to the public key." },
    {
        value: "DerivationBaseObject",
        label: "Derivation Base Object",
        description: "For a derived Symmetric Key or Secret Data object: the object(s) from which the current symmetric key was derived.",
    },
    {
        value: "DerivedKey",
        label: "Derived Key",
        description: "The symmetric key(s) or Secret Data object(s) that were derived from the current object.",
    },
    {
        value: "ReplacementObject",
        label: "Replacement Object",
        description:
            "For a Symmetric Key, an Asymmetric Private Key, or an Asymmetric Public Key object: the key that resulted from the re-key of the current key.",
    },
    {
        value: "ReplacedObject",
        label: "Replaced Object",
        description:
            "For a Symmetric Key, an Asymmetric Private Key, or an Asymmetric Public Key object: the key that was re-keyed to obtain the current key.",
    },
    {
        value: "Parent",
        label: "Parent",
        description: "For all object types: the container or other parent object corresponding to the object.",
    },
    {
        value: "Child",
        label: "Child",
        description: "For all object types: the subordinate, derived or other child object corresponding to the object.",
    },
    { value: "Previous", label: "Previous", description: "For all object types: the previous object to this object." },
    { value: "Next", label: "Next", description: "For all object types: the next object to this object." },
    { value: "PKCS12Certificate", label: "PKCS12 Certificate" },
    { value: "PKCS12Password", label: "PKCS12 Password" },
    { value: "WrappingKey", label: "Wrapping Key", description: "For wrapped objects: the object that was used to wrap this object." },
];

// Sample KMIP tags - in a real application, these would come from your backend
const KMIP_TAGS = [
    { value: "ActivationDate", label: "Activation Date" },
    { value: "CryptographicAlgorithm", label: "Cryptographic Algorithm" },
    { value: "CryptographicLength", label: "Cryptographic Length" },
    { value: "CryptographicUsageMask", label: "Cryptographic Usage Mask (Key usage)" },
    { value: "ObjectType", label: "Object Type" },
    { value: "KeyFormatType", label: "Key Format Type" },
];

interface AttributeGetFormData {
    id?: string;
    tags?: string[];
    attribute_tags: string[];
    attribute_link_types: string[];
}

const AttributeGetForm: React.FC = () => {
    const [form] = Form.useForm<AttributeGetFormData>();
    const [res, setRes] = useState<Map<any, any> | string>(new Map());
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    const onFinish = async (values: AttributeGetFormData) => {
        console.log("Get attributes values:", values);
        setIsLoading(true);

        const id = values.id ? values.id : values.tags ? JSON.stringify(values.tags) : undefined;
        try {
            if (id == undefined) {
                setRes("Missing object identifier.");
                throw Error("Missing object identifier");
            }
            const request = get_attributes_ttlv_request(id, values.attribute_tags);
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const response = parse_get_attributes_ttlv_response(result_str, values.attribute_tags, values.attribute_link_types);
                setRes(response);
            }
        } catch (e) {
            setRes(`Error validating certificate: ${e}`);
            console.error("Error validating certificate:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <Title level={2}>Get KMIP Object Attributes and Tags</Title>
            <div className="mb-8 space-y-2">
                <div>Retrieve attributes and tags for a KMIP object by specifying either the object ID or tags.</div>
                <div className="text-sm text-yellow-600">
                    When using tags to retrieve the object, rather than the object id, an error is returned if multiple objects matching the
                    tags are found.
                </div>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    attribute_tags: [],
                    attribute_link_types: [],
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card title="Object Identification">
                        <div className="mb-5">Specify either the Object ID or one or more tags to identify the object.</div>

                        <Form.Item name="id" label="Object ID" help="The unique identifier of the cryptographic object">
                            <Input placeholder="Enter object ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Tags to use to retrieve the key when no key ID is specified">
                            <Select mode="tags" style={{ width: "100%" }} placeholder="Enter tags" tokenSeparators={[","]} />
                        </Form.Item>
                    </Card>

                    <Card title="Attribute Selection">
                        <Form.Item
                            name="attribute_tags"
                            label="Attribute Tags"
                            help="The attributes or KMIP-tags to retrieve (all attributes will be returned if none specified)"
                        >
                            <Select mode="multiple" style={{ width: "100%" }} placeholder="Select attribute tags">
                                {KMIP_TAGS.map((tag) => (
                                    <Option key={tag.value} value={tag.value}>
                                        {tag.label}
                                    </Option>
                                ))}
                            </Select>
                        </Form.Item>

                        <Form.Item
                            name="attribute_link_types"
                            label="Link Types"
                            help="Filter on retrieved links (only if LinkType is used in attribute tags)"
                        >
                            <Select mode="multiple" style={{ width: "100%" }} placeholder="Select link types" optionLabelProp="label">
                                {LINK_TYPES.map((type) => (
                                    <Option key={type.value} value={type.value} label={type.label}>
                                        <div>
                                            <div>{type.label}</div>
                                            {type.description && <div className="text-xs text-gray-500">{type.description}</div>}
                                        </div>
                                    </Option>
                                ))}
                            </Select>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Get Attributes
                        </Button>
                    </Form.Item>
                </Space>
            </Form>

            {res &&
                (typeof res !== "string" && res.size ? (
                    <div ref={responseRef}>
                        <HashMapDisplay data={res} />
                    </div>
                ) : (
                    <div ref={responseRef}>Empty result. {res}</div>
                ))}
        </div>
    );
};

export default AttributeGetForm;
