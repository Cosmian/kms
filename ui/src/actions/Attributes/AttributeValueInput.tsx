import { DatePicker, Form, Input, Select } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
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

type RegistryEntry = (typeof ATTRIBUTE_REGISTRY)[number];

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
    const { t } = useTranslation("actions");
    const attrLabel = (entry: RegistryEntry) => t(`attribute.${entry.value}`, { defaultValue: entry.label });
    const attrHelp = (entry: RegistryEntry) => (entry.help ? t(`attribute.${entry.value}.help`, { defaultValue: entry.help }) : undefined);
    const attrPlaceholder = (entry: RegistryEntry) =>
        entry.placeholder ? t(`attribute.${entry.value}.placeholder`, { defaultValue: entry.placeholder }) : undefined;

    if (!selectedAttributeName) {
        return <Input placeholder={t("attributeValueInput.firstSelectAttribute")} disabled />;
    }

    const entry = ATTRIBUTE_REGISTRY.find((a) => a.value === selectedAttributeName);

    if (!entry) {
        return (
            <Form.Item
                name="attribute_value"
                label={t("attributeValueInput.attributeValue")}
                rules={[{ required: true, message: t("attributeValueInput.pleaseEnterAttributeValue") }]}
            >
                <Input placeholder={t("attributeValueInput.enterAttributeValue")} />
            </Form.Item>
        );
    }

    switch (entry.inputType) {
        case "date":
            return (
                <Form.Item
                    name="attribute_value"
                    label={attrLabel(entry)}
                    rules={[{ required: true, message: t("attributeValueInput.pleaseSelectValue", { value: attrLabel(entry) }) }]}
                >
                    <DatePicker showTime style={{ width: "100%" }} />
                </Form.Item>
            );

        case "algorithm":
            return (
                <Form.Item
                    name="attribute_value"
                    label={attrLabel(entry)}
                    rules={[{ required: true, message: t("attributeValueInput.pleaseSelectAlgorithm") }]}
                >
                    <Select placeholder={t("attributeValueInput.selectAlgorithm")}>
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
                    label={attrLabel(entry)}
                    rules={[{ required: true, message: t("attributeValueInput.pleaseSelectKeyUsage") }]}
                >
                    <Select mode="multiple" placeholder={t("attributeValueInput.selectKeyUsages")}>
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
                <Form.Item
                    name="attribute_value"
                    label={attrLabel(entry)}
                    rules={[{ required: true, message: t("attributeValueInput.pleaseSelectBoolean") }]}
                >
                    <Select placeholder={t("attributeValueInput.selectValue")}>
                        <Option value="true">{t("common:true")}</Option>
                        <Option value="false">{t("common:false")}</Option>
                    </Select>
                </Form.Item>
            );

        case "number":
            return (
                <Form.Item
                    name="attribute_value"
                    label={attrLabel(entry)}
                    help={attrHelp(entry)}
                    rules={[{ required: true, message: t("attributeValueInput.pleaseEnterNumber") }]}
                >
                    <Input type="number" placeholder={t("attributeValueInput.enterValue")} />
                </Form.Item>
            );

        case "link":
            return (
                <Form.Item
                    name="attribute_value"
                    label={t("attributeValueInput.linkValue", { label: attrLabel(entry) })}
                    rules={[{ required: true, message: t("attributeValueInput.pleaseEnterIdValue") }]}
                >
                    <Input placeholder={t("attributeValueInput.enterIdValue")} />
                </Form.Item>
            );

        case "text":
        default:
            return (
                <Form.Item
                    name="attribute_value"
                    label={attrLabel(entry)}
                    help={attrHelp(entry)}
                    rules={[{ required: true, message: t("attributeValueInput.pleaseEnterValue") }]}
                >
                    <Input placeholder={attrPlaceholder(entry) ?? t("attributeValueInput.enterValue")} />
                </Form.Item>
            );
    }
};

export default AttributeValueInput;
