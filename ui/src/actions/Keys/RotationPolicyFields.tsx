import { Collapse, Form, Input, InputNumber, Select } from "antd";
import React from "react";

const { Panel } = Collapse;

/** Supported duration units for the rotation interval picker. */
const DURATION_UNITS = [
    { label: "Days", value: 86400 },
    { label: "Weeks", value: 604800 },
    { label: "Months (30 days)", value: 2592000 },
];

/**
 * A collapsible form section that adds optional rotation policy fields.
 *
 * When the user expands the panel, they can set:
 * - Rotation Interval — triggers automatic re-keying when due (minimum 1 day)
 * - Rotation Name — optional label to identify the lineage
 * - Rotation Offset — delay before the first rotation (minimum 1 day)
 *
 * These fields map to the `rotate_interval`, `rotate_name`, and `rotate_offset`
 * KMIP attributes that are applied via `SetAttribute` after the object is created.
 */
const RotationPolicyFields: React.FC = () => (
    <Collapse ghost>
        <Panel header="Auto Rotation Policy (optional)" key="rotation-policy">
            <Form.Item
                label="Rotation Interval"
                help="Automatically re-key this object at the given interval (minimum 1 day). Leave empty to disable."
            >
                <Input.Group compact>
                    <Form.Item name="rotateIntervalValue" noStyle>
                        <InputNumber className="w-[120px]" min={1} step={1} placeholder="e.g. 1" />
                    </Form.Item>
                    <Form.Item name="rotateIntervalUnit" noStyle initialValue={86400}>
                        <Select className="w-[170px]" options={DURATION_UNITS} />
                    </Form.Item>
                </Input.Group>
            </Form.Item>

            <Form.Item name="rotateName" label="Rotation name" help="Optional label to identify this rotation policy lineage">
                <Input placeholder="e.g. daily-rotation" />
            </Form.Item>

            <Form.Item
                label="Rotation offset"
                help="Delay before the first automatic rotation (minimum 1 day). Defaults to the interval if not set."
            >
                <Input.Group compact>
                    <Form.Item name="rotateOffsetValue" noStyle>
                        <InputNumber className="w-[120px]" min={1} step={1} placeholder="e.g. 1" />
                    </Form.Item>
                    <Form.Item name="rotateOffsetUnit" noStyle initialValue={86400}>
                        <Select className="w-[170px]" options={DURATION_UNITS} />
                    </Form.Item>
                </Input.Group>
            </Form.Item>
        </Panel>
    </Collapse>
);

export default RotationPolicyFields;

/** Fields contributed by the rotation policy panel. */
export interface RotationPolicyFormValues {
    rotateIntervalValue?: number;
    rotateIntervalUnit?: number;
    rotateName?: string;
    rotateOffsetValue?: number;
    rotateOffsetUnit?: number;
}

/** Convert the form values to seconds. Returns undefined when no value is set. */
export function rotationIntervalToSeconds(value?: number, unit?: number): number | undefined {
    if (value == null || value <= 0) return undefined;
    return value * (unit ?? 86400);
}

/**
 * Apply rotation policy attributes to an already-created object via sequential
 * `set_attribute_ttlv_request` calls.  Only attributes that are set are sent.
 */
export async function applyRotationPolicy(
    keyId: string,
    rotateInterval: number | undefined,
    rotateName: string | undefined,
    rotateOffset: number | undefined,
    sendRequest: (request: object, idToken: string | null, serverUrl: string) => Promise<string>,
    parseSetResponse: (response: string) => unknown,
    setAttributeRequest: (objectId: string, attrName: string, attrValue: string) => object,
    idToken: string | null,
    serverUrl: string,
): Promise<void> {
    const attrs: Array<[string, string]> = [];
    if (rotateInterval != null && rotateInterval > 0) {
        attrs.push(["rotate_interval", String(Math.round(rotateInterval))]);
    }
    if (rotateName) {
        attrs.push(["rotate_name", rotateName]);
    }
    if (rotateOffset != null && rotateOffset > 0) {
        attrs.push(["rotate_offset", String(Math.round(rotateOffset))]);
    }

    for (const [attrName, attrValue] of attrs) {
        const req = setAttributeRequest(keyId, attrName, attrValue);
        const result = await sendRequest(req, idToken, serverUrl);
        if (result) {
            parseSetResponse(result);
        }
    }
}
