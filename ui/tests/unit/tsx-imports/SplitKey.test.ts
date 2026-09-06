/**
 * Component smoke/render tests for SplitKey, JoinSplitKey, and CryptoOfficerRole.
 *
 * Covers:
 *   SplitKey    — generic page: share count always editable, no CO/ceremony references
 *   JoinSplitKey — fix #4 (initialValues) + fix #5 (Ant Design Select)
 *   CryptoOfficerRole — CO Role page renders heading and refresh button
 */

import { screen } from "@testing-library/react";
import React from "react";
import { describe, expect, test, vi, beforeEach } from "vitest";

import SplitKeyForm from "../../../src/actions/Keys/SplitKey";
import JoinSplitKeyForm from "../../../src/actions/Keys/JoinSplitKey";
import CryptoOfficerRole from "../../../src/actions/Access/CryptoOfficerRole";
import { smokeRender } from "../test-utils";

// ── SplitKey component — generic page ────────────────────────────────────────

describe("SplitKey page — generic, parametrable share count", () => {
    test("renders the 'Split Key' heading", () => {
        smokeRender(React.createElement(SplitKeyForm));
        expect(screen.getByRole("heading", { name: "Split Key" })).toBeInTheDocument();
    });

    test("renders an editable share count input (always, not locked to CO config)", () => {
        smokeRender(React.createElement(SplitKeyForm));
        const input = screen.getByTestId("split-key-share-count-input");
        expect(input).toBeInTheDocument();
        // Must be enabled — the page is generic and never locks the count
        expect(input).not.toBeDisabled();
    });

    test("renders the key ID input", () => {
        smokeRender(React.createElement(SplitKeyForm));
        expect(screen.getByTestId("split-key-id-input")).toBeInTheDocument();
    });

    test("renders the submit button", () => {
        smokeRender(React.createElement(SplitKeyForm));
        expect(screen.getByTestId("split-key-submit-btn")).toBeInTheDocument();
    });

    test("does NOT mention key ceremony anywhere on the page", () => {
        smokeRender(React.createElement(SplitKeyForm));
        // The generic Split Key page must not reference ceremony concepts
        expect(screen.queryByText(/ceremony/i)).toBeNull();
        expect(screen.queryByText(/crypto officer/i)).toBeNull();
        expect(screen.queryByText(/CO candidate/i)).toBeNull();
    });

    test("does NOT render a ceremony-mode badge", () => {
        smokeRender(React.createElement(SplitKeyForm));
        expect(document.querySelector("[data-testid='split-key-mode-badge']")).toBeNull();
    });
});

// ── JoinSplitKey component ───────────────────────────────────────────────────

describe("JoinSplitKey page (fixes #4 and #5)", () => {
    test("renders the 'Join Split Key' heading", () => {
        smokeRender(React.createElement(JoinSplitKeyForm));
        expect(screen.getByRole("heading", { name: "Join Split Key" })).toBeInTheDocument();
    });

    test("renders 3 share UID inputs by default (fix #4 — consistent DEFAULT_SHARE_COUNT)", () => {
        smokeRender(React.createElement(JoinSplitKeyForm));
        expect(screen.getByTestId("join-share-id-0")).toBeInTheDocument();
        expect(screen.getByTestId("join-share-id-1")).toBeInTheDocument();
        expect(screen.getByTestId("join-share-id-2")).toBeInTheDocument();
    });

    test("does NOT render a raw <select> element for objectType (fix #5 — Ant Design Select)", () => {
        smokeRender(React.createElement(JoinSplitKeyForm));
        const rawSelect = document.querySelector("select[data-testid='join-object-type-select']");
        expect(rawSelect).toBeNull();
    });

    test("renders the submit button", () => {
        smokeRender(React.createElement(JoinSplitKeyForm));
        expect(screen.getByTestId("join-split-key-submit-btn")).toBeInTheDocument();
    });
});

// ── CryptoOfficerRole component ──────────────────────────────────────────────

describe("CryptoOfficerRole page — integrated SplitKey and JoinKey", () => {
    beforeEach(() => {
        vi.stubGlobal(
            "fetch",
            vi.fn(async (input: RequestInfo | URL) => {
                const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
                if (url.includes("/access/crypto_officer/status")) {
                    return new Response(
                        JSON.stringify({
                            enabled: true,
                            require_ceremony: true,
                            custodians_count: 2,
                            users: ["alice", "bob"],
                            ceremony_activated: false,
                            is_crypto_officer: false,
                            co_candidates: ["alice", "bob"],
                        }),
                        { status: 200, headers: { "Content-Type": "application/json" } },
                    );
                }
                return new Response(JSON.stringify({}), { status: 200 });
            }),
        );
    });

    test("renders the 'Crypto Officer Role' heading", () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        expect(screen.getByRole("heading", { name: "Crypto Officer Role" })).toBeInTheDocument();
    });

    test("renders the Refresh button", () => {
        smokeRender(React.createElement(CryptoOfficerRole));
        expect(screen.getByTestId("refresh-btn")).toBeInTheDocument();
    });
});
