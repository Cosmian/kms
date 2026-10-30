import { screen, fireEvent, waitFor } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import Header, { ServerInfo } from "../../../src/components/layout/Header";
import { smokeRender } from "../test-utils";

test("renders Header", () => {
    smokeRender(React.createElement(Header, { isDarkMode: false }));
    expect(screen.getByText("Key Management System")).toBeInTheDocument();
});

test("renders Header with single HSM instance and verifies minWidth calculation", () => {
    const serverInfo: ServerInfo = {
        version: "4.15.0",
        fips_mode: true,
        hsm_instances: [
            {
                prefix: "hsm",
                model: "softhsm2",
                slots: [{ slot_id: 0, accessible: true }],
            },
        ],
        default_username: "admin",
    };
    const { container } = smokeRender(React.createElement(Header, { isDarkMode: false, serverInfo }));

    // Verify the select is rendered
    const select = container.querySelector(".ant-select") as HTMLElement;
    expect(select).toBeInTheDocument();

    // Calculate expected minWidth from the actual label text
    // Label: "hsm: softhsm2 (slot 0)" = 22 chars
    const labelText = "hsm: softhsm2 (slot 0)";
    const expectedMinWidth = Math.max(160, labelText.length * 8 + 64);
    expect(expectedMinWidth).toBe(240); // 22 * 8 + 64 = 240

    // Verify the Select has the correct minWidth style
    expect(select).toHaveStyle({ minWidth: `${expectedMinWidth}px` });

    // Verify the Select trigger is rendered
    const selectTrigger = select.querySelector(".ant-select-selector");
    expect(selectTrigger).toBeInTheDocument();
    expect(selectTrigger?.textContent).toContain("softhsm2");
});

test("renders Header with multiple HSM instances, verifies minWidth, and opens dropdown to show all options", async () => {
    const serverInfo: ServerInfo = {
        version: "4.15.0",
        fips_mode: true,
        hsm_instances: [
            {
                prefix: "hsm",
                model: "softhsm2",
                slots: [{ slot_id: 0, accessible: true }],
            },
            {
                prefix: "hsm::softhsm2",
                model: "softhsm2",
                slots: [{ slot_id: 1, accessible: true }],
            },
            {
                prefix: "hsm::softhsm2_1",
                model: "softhsm2",
                slots: [{ slot_id: 2, accessible: true }],
            },
        ],
        default_username: "admin",
    };
    const { container } = smokeRender(React.createElement(Header, { isDarkMode: false, serverInfo }));

    // Verify the select is rendered
    const select = container.querySelector(".ant-select") as HTMLElement;
    expect(select).toBeInTheDocument();

    // Calculate expected minWidth from the longest label
    // Longest label: "hsm::softhsm2_1: softhsm2 (slot 2)" = 34 chars
    const longestLabel = "hsm::softhsm2_1: softhsm2 (slot 2)";
    const expectedMinWidth = Math.max(160, longestLabel.length * 8 + 64);
    expect(expectedMinWidth).toBe(336); // 34 * 8 + 64 = 336

    // Verify the Select has the correct minWidth style
    expect(select).toHaveStyle({ minWidth: `${expectedMinWidth}px` });

    // Get the select trigger element to open dropdown
    const selectTrigger = select.querySelector(".ant-select-selector") as HTMLElement;
    expect(selectTrigger).toBeInTheDocument();

    // Open the dropdown by firing mouseDown event on the trigger
    fireEvent.mouseDown(selectTrigger);

    // Wait for the dropdown to appear and options to render in the DOM
    await waitFor(
        () => {
            const dropdown = document.querySelector(".ant-select-dropdown");
            expect(dropdown).toBeInTheDocument();
        },
        { timeout: 1000 },
    );

    // Verify all three HSM instances are rendered as options
    const options = document.querySelectorAll(".ant-select-item-option");
    expect(options.length).toBe(3);

    // Verify the option texts contain the expected HSM instance information
    const optionTexts = Array.from(options).map((opt) => opt.textContent || "");

    // First option: hsm
    expect(optionTexts[0]).toMatch(/hsm.*softhsm2.*slot 0/i);

    // Second option: hsm::softhsm2
    expect(optionTexts[1]).toMatch(/hsm::softhsm2.*softhsm2.*slot 1/i);

    // Third option: hsm::softhsm2_1
    expect(optionTexts[2]).toMatch(/hsm::softhsm2_1.*softhsm2.*slot 2/i);

    // Verify the check-circle suffix icon is present
    const checkCircleIcon = select.querySelector(".anticon-check-circle");
    expect(checkCircleIcon).toBeInTheDocument();
});
