import { expect, test } from "vitest";

import { ATTRIBUTE_REGISTRY, DELETE_ATTRIBUTES, SET_MODIFY_ATTRIBUTES } from "../../src/actions/Attributes/attributeRegistry";

// Server-managed (KMIP 2.1 §4.13, §4.15): Get only, never offered for Set/Modify/Delete.
const SERVER_MANAGED = ["cryptographic_algorithm", "cryptographic_length"];

test("server-managed attributes are readable but not editable", () => {
    const values = (entries: { value: string }[]) => entries.map((entry) => entry.value);
    for (const attribute of SERVER_MANAGED) {
        expect(values(ATTRIBUTE_REGISTRY)).toContain(attribute);
        expect(values(SET_MODIFY_ATTRIBUTES)).not.toContain(attribute);
        expect(values(DELETE_ATTRIBUTES)).not.toContain(attribute);
    }
});
