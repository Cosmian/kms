import { Collapse, Form, Input, InputNumber } from "antd";
import React from "react";

const { Panel } = Collapse;

/**
 * A collapsible form section that adds optional rotation policy fields.
 *
 * When the user expands the panel, they can set:
 * - Rotation Interval (seconds) — triggers automatic re-keying when due
 * - Rotation Name — optional label to identify the lineage
 * - Rotation Offset (seconds) — delay before the first rotation
 *
 * These fields map to the `rotate_interval`, `rotate_name`, and `rotate_offset`
 * KMIP attributes that are applied via `SetAttribute` after the object is created.
 */
const RotationPolicyFields: React.FC = () => (
    <Collapse ghost>
        <Panel header="Auto Rotation Policy (optional)" key="rotation-policy">
            <Form.Item
                name="rotateInterval"
                label="Rotation Interval (seconds)"
                help="Automatically re-key this object at the given interval. Set 0 to disable."
            >
                <InputNumber className="w-[200px]" min={0} step={3600} placeholder="e.g. 86400 (daily)" />
            </Form.Item>

            <Form.Item name="rotateName" label="Rotation name" help="Optional label to identify this rotation policy lineage">
                <Input placeholder="e.g. daily-rotation" />
            </Form.Item>

            <Form.Item
                name="rotateOffset"
                label="Rotation offset (seconds)"
                help="Delay before the first automatic rotation. Defaults to the interval if not set."
            >
                <InputNumber className="w-[200px]" min={0} step={3600} placeholder="e.g. 0" />
            </Form.Item>
        </Panel>
    </Collapse>
);

export default RotationPolicyFields;

/** Fields contributed by the rotation policy panel. */
export interface RotationPolicyFormValues {
    rotateInterval?: number;
    rotateName?: string;
    rotateOffset?: number;
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
