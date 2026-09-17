/**
 * KeyIdInput — a reusable Input + "Search Objects" LocateButton pair.
 *
 * Renders a flex row containing:
 *   - An `<Input>` (takes the remaining width)
 *   - A `<LocateButton>` that pre-filters by `objectType` and writes the
 *     selected UID into the form field identified by `fieldName`.
 *
 * Drop-in replacement for the common pattern:
 * ```tsx
 * <Form.Item name="keyId" label={t("common:keyId")} help="...">
 *     <Input placeholder={t("common:enterKeyId")} />
 * </Form.Item>
 * ```
 * ↓ becomes:
 * ```tsx
 * <KeyIdInput form={form} fieldName="keyId" label={t("common:keyId")} help="..." objectType="SymmetricKey" />
 * ```
 */
import { Form, FormInstance, Input } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import LocateButton from "./LocateButton";

interface KeyIdInputProps {
    /** The Ant Design form instance (from `Form.useForm()`). */
    form: FormInstance;
    /** The `name` of the form field that stores the UID. */
    fieldName: string;
    /** Label displayed above the input. */
    label: React.ReactNode;
    /** Optional help/hint text shown below the input. */
    help?: React.ReactNode;
    /** Input placeholder text. */
    placeholder?: string;
    /** KMIP ObjectType to pre-filter the Locate search (e.g. "SymmetricKey", "PublicKey"). Omit to show all types. */
    objectType?: string;
    /** AntD Form validation rules forwarded to the inner Form.Item. */
    rules?: React.ComponentProps<typeof Form.Item>["rules"];
    /** HTML data-testid for the text input. */
    "data-testid"?: string;
}

/**
 * KeyIdInput renders an Input field and a "Search Objects" button side by side.
 * Selecting an object in the search modal writes its UID into the form field.
 */
const KeyIdInput: React.FC<KeyIdInputProps> = ({
    form,
    fieldName,
    label,
    help,
    placeholder,
    objectType,
    rules,
    "data-testid": dataTestId,
}) => {
    const { t } = useTranslation("common");
    return (
        <Form.Item label={label} help={help}>
            <div className="flex gap-2 items-center">
                <Form.Item noStyle name={fieldName} rules={rules}>
                    <Input placeholder={placeholder ?? t("enterKeyId")} style={{ flex: 1 }} data-testid={dataTestId} />
                </Form.Item>
                <LocateButton objectType={objectType} onSelect={(uid) => form.setFieldValue(fieldName, uid)} />
            </div>
        </Form.Item>
    );
};

export default KeyIdInput;
