import { Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useRef, useState } from "react";
import { useAuth } from "./AuthContext";
import { sendKmipRequest } from "./utils";
import { create_opaque_object_ttlv_request, parse_import_ttlv_response } from "./wasm/pkg";

interface OpaqueObjectFormData {
    objectId?: string;
    objectValue?: string;
    objectType: "Opaque";
    tags: string[];
    sensitive: boolean;
    wrappingKeyId?: string;
}

type ImportResponse = {
    UniqueIdentifier: string;
};

const OpaqueObjectForm: React.FC = () => {
    const [form] = Form.useForm<OpaqueObjectFormData>();
    const [res, setRes] = useState<undefined | string>(undefined);
    const [isLoading, setIsLoading] = useState(false);
    const { idToken, serverUrl } = useAuth();
    const responseRef = useRef<HTMLDivElement>(null);
    const objectValue = Form.useWatch("objectValue", form);

    useEffect(() => {
        if (res && responseRef.current) {
            responseRef.current.scrollIntoView({ behavior: "smooth" });
        }
    }, [res]);

    useEffect(() => {
        if (!objectValue) {
            form.setFieldsValue({ objectType: "Opaque" });
        }
    }, [objectValue, form]);

    const onFinish = async (values: OpaqueObjectFormData) => {
        setIsLoading(true);
        setRes(undefined);
        try {
            const request = create_opaque_object_ttlv_request(
                values.objectValue,
                values.objectId,
                values.tags,
                values.sensitive,
                values.wrappingKeyId
            );
            const result_str = await sendKmipRequest(request, idToken, serverUrl);
            if (result_str) {
                const result: ImportResponse = await parse_import_ttlv_response(result_str);
                setRes(`${result.UniqueIdentifier} has been created.`);
            }
        } catch (e) {
            setRes(`Error creating opaque object: ${e}`);
            console.error("Error creating opaque object:", e);
        } finally {
            setIsLoading(false);
        }
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">Create a new opaque object</h1>

            <div className="mb-8 space-y-2">
                <p>Create a new opaque object:</p>
                <ul className="list-disc pl-5 space-y-1">
                    <li>When a value is specified, the object will be created from the provided bytes (UTF-8 string).</li>
                    <li>Otherwise, an empty opaque object will be created.</li>
                    <li>Tags can later be used to retrieve the object. Tags are optional.</li>
                </ul>
            </div>

            <Form
                form={form}
                onFinish={onFinish}
                layout="vertical"
                initialValues={{
                    objectType: "Opaque",
                    tags: [],
                    sensitive: false,
                }}
            >
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <Form.Item
                            name="objectValue"
                            label="Opaque Data"
                            help="Optional opaque data string, UTF-8 encoded. If not provided, an empty object is created."
                        >
                            <Input.TextArea placeholder="Enter opaque data" rows={2} />
                        </Form.Item>

                        <Form.Item
                            name="objectType"
                            label="Object Type"
                            help="Opaque object type is fixed."
                            rules={[{ required: true, message: "Please confirm object type" }]}
                        >
                            <Select disabled>
                                <Select.Option value="Opaque">Opaque</Select.Option>
                            </Select>
                        </Form.Item>

                        <Form.Item name="objectId" label="Object ID" help="Optional: a random UUID will be generated if not specified">
                            <Input placeholder="Enter object ID" />
                        </Form.Item>

                        <Form.Item name="tags" label="Tags" help="Optional: Add tags to help retrieve the object later">
                            <Select mode="tags" placeholder="Enter tags" open={false} />
                        </Form.Item>

                        <Form.Item
                            name="wrappingKeyId"
                            label="Wrapping Key ID"
                            help="Optional: ID of the key to wrap this new opaque object with"
                        >
                            <Input placeholder="Enter wrapping key ID" />
                        </Form.Item>

                        <Form.Item name="sensitive" valuePropName="checked" help="If set, the object will not be exportable">
                            <Checkbox>Sensitive</Checkbox>
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button type="primary" htmlType="submit" loading={isLoading} className="w-full text-white font-medium">
                            Create Opaque Object
                        </Button>
                    </Form.Item>
                </Space>
                {res && (
                    <div ref={responseRef}>
                        <Card title="Opaque object creation response">{res}</Card>
                    </div>
                )}
            </Form>
        </div>
    );
};

export default OpaqueObjectForm;
