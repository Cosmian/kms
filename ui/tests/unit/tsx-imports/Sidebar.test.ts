import { screen, waitFor } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";
import i18n from "i18next";

import Sidebar from "../../../src/components/layout/Sidebar";
import { smokeRender } from "../test-utils";

test("renders Sidebar", () => {
    smokeRender(React.createElement(Sidebar));
    expect(screen.getByText("Locate")).toBeInTheDocument();
    expect(screen.getByText("Symmetric")).toBeInTheDocument();
    expect(screen.getByText("RSA")).toBeInTheDocument();
});

test("Sidebar computes wider width in French than English", async () => {
    // Ensure we start with English
    await i18n.changeLanguage("en");

    // Render Sidebar with English language
    const { container: enContainer, unmount: unmountEn } = smokeRender(React.createElement(Sidebar));

    // Wait for Sidebar to render in English
    await waitFor(() => {
        expect(screen.getByText("Locate")).toBeInTheDocument();
    });

    // Get the Sider element and measure its width
    const siderEn = enContainer.querySelector(".ant-layout-sider") as HTMLElement;
    expect(siderEn).toBeInTheDocument();

    // Get the computed width
    const enStyle = window.getComputedStyle(siderEn);
    const enWidthStr = enStyle.width;
    const enWidth = parseFloat(enWidthStr);

    console.log(`English sidebar width: ${enWidth}px`);

    expect(enWidth).toBeGreaterThanOrEqual(220);
    expect(enWidth).toBeLessThanOrEqual(360);

    // Unmount English sidebar
    unmountEn();

    // Wait for DOM to clear
    await waitFor(
        () => {
            expect(screen.queryByText("Locate")).not.toBeInTheDocument();
        },
        { timeout: 1000 },
    ).catch(() => {
        // Timeout is ok - just ensure component is unmounted
    });

    // Change language to French
    await i18n.changeLanguage("fr");

    // Render Sidebar with French language
    const { container: frContainer, unmount: unmountFr } = smokeRender(React.createElement(Sidebar));

    // Wait for Sidebar to render in French
    await waitFor(
        () => {
            const text = screen.queryByText(/Localiser|Locate/);
            expect(text).toBeInTheDocument();
        },
        { timeout: 2000 },
    );

    // Get the Sider element and measure its width
    const siderFr = frContainer.querySelector(".ant-layout-sider") as HTMLElement;
    expect(siderFr).toBeInTheDocument();

    // Get the computed width
    const frStyle = window.getComputedStyle(siderFr);
    const frWidthStr = frStyle.width;
    const frWidth = parseFloat(frWidthStr);

    console.log(`French sidebar width: ${frWidth}px`);

    expect(frWidth).toBeGreaterThanOrEqual(220);
    expect(frWidth).toBeLessThanOrEqual(360);

    // KEY ASSERTION: French sidebar width should be STRICTLY GREATER than English width
    // French translations like "Créer la paire de clés maîtresses" are longer than English
    expect(frWidth).toBeGreaterThan(enWidth);

    // Clean up
    unmountFr();

    // Reset to English for other tests
    await i18n.changeLanguage("en");
});

test("Sidebar width is responsive - calculates based on longest menu label", () => {
    const { container } = smokeRender(React.createElement(Sidebar));

    // Verify the Sider component is rendered
    const sider = container.querySelector(".ant-layout-sider");
    expect(sider).toBeInTheDocument();

    // Get the computed width of the Sider when not collapsed
    const siderElement = sider as HTMLElement;
    const computedStyle = window.getComputedStyle(siderElement);
    const siderWidth = computedStyle.width;

    // The width should be set to a pixel value in the range [220px, 360px]
    // (per the calculation: Math.max(220, Math.min(360, longestLabelLength * 8.5 + 80)))
    const widthValue = parseFloat(siderWidth);
    expect(widthValue).toBeGreaterThanOrEqual(220);
    expect(widthValue).toBeLessThanOrEqual(360);
});

test("Sidebar renders all expected menu items for width calculation", () => {
    const { container } = smokeRender(React.createElement(Sidebar));

    // Verify all top-level menu sections are present
    // These items' labels are used to calculate the responsive width
    expect(screen.getByText("Locate")).toBeInTheDocument();
    expect(screen.getByText("Symmetric")).toBeInTheDocument();
    expect(screen.getByText("RSA")).toBeInTheDocument();
    expect(screen.getByText("Elliptic Curve")).toBeInTheDocument();

    // Verify the Sider is rendered with collapsible trigger
    const sider = container.querySelector(".ant-layout-sider");
    expect(sider).toBeInTheDocument();

    const trigger = container.querySelector(".ant-layout-sider-trigger");
    expect(trigger).toBeInTheDocument();

    // Verify the Menu is rendered inside
    const menu = container.querySelector(".ant-menu");
    expect(menu).toBeInTheDocument();
});

test("Sidebar width is in valid responsive range", () => {
    const { container } = smokeRender(React.createElement(Sidebar));

    // Verify the Sider component is rendered
    const sider = container.querySelector(".ant-layout-sider");
    expect(sider).toBeInTheDocument();

    // Get the computed width of the Sider when not collapsed
    const siderElement = sider as HTMLElement;
    const computedStyle = window.getComputedStyle(siderElement);
    const siderWidth = computedStyle.width;

    // The width should be set to a pixel value in the range [220px, 360px]
    const widthValue = parseFloat(siderWidth);
    expect(widthValue).toBeGreaterThanOrEqual(220);
    expect(widthValue).toBeLessThanOrEqual(360);
});
