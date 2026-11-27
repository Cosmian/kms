import { expect, test } from "vitest";

import { getMenuItems } from "../../../src/menuItems";

test("menuItems exports a non-empty menu", () => {
    const menuItems = getMenuItems();
    expect(Array.isArray(menuItems)).toBe(true);
    expect(menuItems.length).toBeGreaterThan(0);
});

const NON_FIPS_SECTIONS = ["pgp", "fpe", "tokenize", "cc"];

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

test("hides only the optional sections the server disables, including nested items", () => {
    const menu = getMenuItems({ isFips: true, features: { kv: true, hsm: false, google_cse: false, crypto_officer: false } });
    const keys = menu.map((item) => item.key);
    expect(keys).toContain("kv-secrets");
    expect(keys).not.toContain("hsm-status");
    expect(keys).not.toContain("fpe");
    expect(menu.find((item) => item.key === "hyperscalers")?.children?.map((item) => item.key)).toEqual(["azure", "aws"]);
    expect(menu.find((item) => item.key === "access-rights")?.children?.map((item) => item.key)).not.toContain(
        "access-rights/crypto-officer",
    );
    expect(menu.find((item) => item.key === "sym")?.children?.map((item) => item.key)).toContain("rotation-policy/sym");
});

test("keeps the old menu when flags are unavailable or missing", () => {
    const keys = (features?: { hsm: boolean }) => getMenuItems({ features }).map((item) => item.key);
    expect(keys()).toContain("hsm-status");
    expect(keys({ hsm: true })).toContain("kv-secrets");
});
