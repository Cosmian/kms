import { expect, test } from "vitest";

import { getMenuItems } from "../../../src/menuItems";

test("menuItems exports a non-empty menu", () => {
    const menuItems = getMenuItems();
    expect(Array.isArray(menuItems)).toBe(true);
    expect(menuItems.length).toBeGreaterThan(0);
});

const NON_FIPS_SECTIONS = ["pgp", "pqc", "fpe", "tokenize", "cc"];

test("non-FIPS sections are hidden in FIPS mode", () => {
    const keys = getMenuItems({ isFips: true }).map((item) => item.key);
    for (const section of NON_FIPS_SECTIONS) {
        expect(keys).not.toContain(section);
    }
});

test("non-FIPS sections are shown outside FIPS mode", () => {
    const keys = getMenuItems({ isFips: false, enableCovercrypt: true }).map((item) => item.key);
    for (const section of NON_FIPS_SECTIONS) {
        expect(keys).toContain(section);
    }
});

test("MAC section stays available in FIPS mode", () => {
    const keys = getMenuItems({ isFips: true }).map((item) => item.key);
    expect(keys).toContain("mac");
});
