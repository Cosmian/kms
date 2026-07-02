import { DatePicker, Form, Input, Select } from "antd";
import React from "react";
import { ATTRIBUTE_REGISTRY, type AlgoOption } from "./attributeRegistry";

const { Option } = Select;

const KEY_USAGE_OPTIONS = [
    { value: "Sign", label: "Sign" },
    { value: "Verify", label: "Verify" },
    { value: "Encrypt", label: "Encrypt" },
    { value: "Decrypt", label: "Decrypt" },
    { value: "WrapKey", label: "Wrap Key" },
    { value: "UnwrapKey", label: "Unwrap Key" },
    { value: "MACGenerate", label: "MAC Generate" },
    { value: "MACVerify", label: "MAC Verify" },
    { value: "DeriveKey", label: "Derive Key" },
    { value: "KeyAgreement", label: "Key Agreement" },
    { value: "CertificateSign", label: "Certificate Sign" },
    { value: "CRLSign", label: "CRL Sign" },
    { value: "Authenticate", label: "Authenticate" },
    { value: "Unrestricted", label: "Unrestricted" },
];

interface Props {
    selectedAttributeName: string | undefined;
    cryptoAlgorithms: AlgoOption[];
}

/**
 * Renders the appropriate value input for a KMIP attribute based on its
 * `inputType` in the attribute registry.  Used by both AttributeSet and
 * AttributeModify to avoid duplicating the switch logic.
 */
const AttributeValueInput: React.FC<Props> = ({ selectedAttributeName, cryptoAlgorithms }) => {
    if (!selectedAttributeName) {
        return <Input placeholder="First select an attribute name" disabled />;
    }

    const entry = ATTRIBUTE_REGISTRY.find((a) => a.value === selectedAttributeName);

    if (!entry) {
        return (
            <Form.Item name="attribute_value" label="Attribute Value" rules={[{ required: true, message: "Please enter attribute value" }]}>
                <Input placeholder="Enter attribute value" />
            </Form.Item>
        );
    }

    switch (entry.inputType) {
        case "date":
            return (
                <Form.Item
                    name="attribute_value"
                    label={entry.label}
                    rules={[{ required: true, message: `Please select ${entry.label.toLowerCase()}` }]}
                >
                    <DatePicker showTime style={{ width: "100%" }} />
                </Form.Item>
            );

        case "algorithm":
            return (
                <Form.Item name="attribute_value" label={entry.label} rules={[{ required: true, message: "Please select an algorithm" }]}>
                    <Select placeholder="Select algorithm">
                        {cryptoAlgorithms.map((algo) => (
                            <Option key={algo.value} value={algo.value}>
                                {algo.label}
                            </Option>
                        ))}
                    </Select>
                </Form.Item>
            );

        case "key_usage":
            return (
                <Form.Item
                    name="attribute_value"
                    label={entry.label}
                    rules={[{ required: true, message: "Please select at least one key usage" }]}
                >
                    <Select mode="multiple" placeholder="Select one or more key usages">
                        {KEY_USAGE_OPTIONS.map((usage) => (
                            <Option key={usage.value} value={usage.value}>
                                {usage.label}
                            </Option>
                        ))}
                    </Select>
                </Form.Item>
            );

        case "boolean":
            return (
                <Form.Item name="attribute_value" label={entry.label} rules={[{ required: true, message: "Please select true or false" }]}>
                    <Select placeholder="Select value">
                        <Option value="true">True</Option>
                        <Option value="false">False</Option>
                    </Select>
                </Form.Item>
            );

        case "number":
            return (
                <Form.Item
                    name="attribute_value"
                    label={entry.label}
                    help={entry.help}
                    rules={[{ required: true, message: "Please enter a number" }]}
                >
                    <Input type="number" placeholder="Enter value" />
                </Form.Item>
            );

        case "link":
            return (
                <Form.Item
                    name="attribute_value"
                    label={`${entry.label} Value`}
                    rules={[{ required: true, message: "Please enter ID value" }]}
                >
                    <Input placeholder="Enter ID value" />
                </Form.Item>
            );

        case "text":
        default:
            return (
                <Form.Item
                    name="attribute_value"
                    label={entry.label}
                    help={entry.help}
                    rules={[{ required: true, message: "Please enter a value" }]}
                >
                    <Input placeholder={entry.placeholder ?? "Enter value"} />
                </Form.Item>
            );
    }
};

export default AttributeValueInput;
