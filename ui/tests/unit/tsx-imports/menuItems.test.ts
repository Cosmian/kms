import { expect, test } from "vitest";

import { menuItems } from "../../../src/menuItems";

test("menuItems exports a non-empty menu", () => {
    expect(Array.isArray(menuItems)).toBe(true);
    expect(menuItems.length).toBeGreaterThan(0);
});
