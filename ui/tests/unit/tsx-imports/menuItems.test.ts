import { expect, test } from "vitest";

import { getMenuItems } from "../../../src/menuItems";

test("menuItems exports a non-empty menu", () => {
    const menuItems = getMenuItems();
    expect(Array.isArray(menuItems)).toBe(true);
    expect(menuItems.length).toBeGreaterThan(0);
});
