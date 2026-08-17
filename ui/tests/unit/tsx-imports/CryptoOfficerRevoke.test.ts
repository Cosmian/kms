/**
 * Component tests for CryptoOfficerRole revocation — Scenario 1 (Trusted CO).
 *
 * The CO is a trusted person. Revocation is:
 *   - Active CO → sees "Revoke My Crypto Officer Role" button (single call, immediate)
 *   - Non-active user → no revoke button shown
 *
 * This replaces the former dual-control revocation tests (sub-views B/C/D).
 */

import { screen } from "@testing-library/react";
import React from "react";
import { describe, expect, test, vi, beforeEach } from "vitest";

import CryptoOfficerRole from "../../../src/actions/Access/CryptoOfficerRole";
import { smokeRender } from "../test-utils";

const baseActiveStatus = {
    enabled: true,
    require_ceremony: true,
    ceremony_activated: true,
    custodians_count: 3,
    users: ["alice@example.com", "bob@example.com", "carol@example.com"],
    co_candidates: ["alice@example.com", "bob@example.com", "carol@example.com"],
};

function mockStatus(status: object) {
    vi.stubGlobal(
        "fetch",
        vi.fn(async (input: RequestInfo | URL) => {
            const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
            if (url.includes("/access/crypto_officer/status")) {
                return new Response(JSON.stringify(status), {
                    status: 200,
                    headers: { "Content-Type": "application/json" },
                });
            }
            if (url.includes("/ui/whoami")) {
                return new Response(JSON.stringify({ user_id: "dummy" }), {
                    status: 200,
                    headers: { "Content-Type": "application/json" },
                });
            }
            return new Response(JSON.stringify({}), { status: 200 });
        }),
    );
}

// ── Scenario 1: Active CO sees the self-revoke button ───────────────────────

describe("CO revocation (Scenario 1): active CO can self-revoke", () => {
    beforeEach(() => mockStatus({ ...baseActiveStatus, is_crypto_officer: true }));

    test("renders the revoke ceremony card", async () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        // The status card is always shown when enabled
        await screen.findByTestId("role-status-card");
    });

    test("renders the self-revoke button for active CO", async () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        await screen.findByTestId("disable-btn");
        expect(screen.getByTestId("disable-btn")).toBeInTheDocument();
    });

    test("does not render the split-key workflow when ceremony is active", async () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        // The Create & Split Key / Activate workflow is only shown while the ceremony is dormant.
        await screen.findByTestId("role-status-card");
        expect(screen.queryByTestId("split-key-step-card")).toBeNull();
        expect(screen.queryByTestId("activate-ceremony-card")).toBeNull();
    });

    test("does not render any pending/confirm/waiting elements", async () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        await screen.findByTestId("role-status-card");
        expect(screen.queryByTestId("pending-confirm-alert")).toBeNull();
        expect(screen.queryByTestId("pending-waiting-alert")).toBeNull();
        expect(screen.queryByTestId("confirm-revoke-btn")).toBeNull();
        expect(screen.queryByTestId("cancel-pending-btn")).toBeNull();
        expect(screen.queryByTestId("cancel-own-request-btn")).toBeNull();
    });
});

// ── Non-CO user: no revoke button ───────────────────────────────────────────

describe("CO revocation (Scenario 1): non-CO user sees no revoke button", () => {
    beforeEach(() => mockStatus({ ...baseActiveStatus, is_crypto_officer: false }));

    test("does not render the self-revoke button for a non-active CO", async () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        await screen.findByTestId("role-status-card");
        expect(screen.queryByTestId("disable-btn")).toBeNull();
    });
});

// ── Ceremony dormant: activation workflow shown ──────────────────────────────

describe("CO page: ceremony dormant shows activation workflow", () => {
    beforeEach(() =>
        mockStatus({
            ...baseActiveStatus,
            ceremony_activated: false,
            is_crypto_officer: false,
        }),
    );

    test("renders the heading", () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        expect(screen.getByRole("heading", { name: "Crypto Officer Role" })).toBeInTheDocument();
    });

    test("renders split key step card when ceremony dormant", async () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        await screen.findByTestId("split-key-step-card");
        expect(screen.getByTestId("activate-ceremony-card")).toBeInTheDocument();
    });

    test("does not render revoke button when ceremony is dormant", async () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        await screen.findByTestId("split-key-step-card");
        expect(screen.queryByTestId("disable-btn")).toBeNull();
    });
});

// ── Role not configured ──────────────────────────────────────────────────────

describe("CO page: role not configured", () => {
    beforeEach(() =>
        mockStatus({
            enabled: false,
            require_ceremony: false,
            ceremony_activated: false,
            custodians_count: 0,
            users: [],
            is_crypto_officer: false,
        }),
    );

    test("renders heading", () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        expect(screen.getByRole("heading", { name: "Crypto Officer Role" })).toBeInTheDocument();
    });

    test("renders not-configured message", async () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        await screen.findByTestId("response-output");
        expect(screen.getByText(/not configured/i)).toBeInTheDocument();
    });
});
