import { screen } from "@testing-library/react";
import React from "react";
import { expect, test } from "vitest";

import Locate, { mapWithLocateConcurrency } from "../../../src/components/common/Locate";
import { smokeRender } from "../test-utils";

test("renders Locate", () => {
    smokeRender(React.createElement(Locate));
    expect(screen.getByRole("heading", { name: "Locate Cryptographic Objects" })).toBeInTheDocument();
    expect(screen.getByText("Basic Search Criteria")).toBeInTheDocument();
    expect(screen.getByLabelText("Tags")).toBeInTheDocument();
});

test("limits Locate enrichment to eight concurrent requests", async () => {
    let active = 0;
    let maxActive = 0;
    let started = 0;
    let resolveFirstBatch: () => void;
    let resolveSecondBatch: () => void;
    const firstBatchStarted = new Promise<void>((resolve) => {
        resolveFirstBatch = resolve;
    });
    const secondBatchStarted = new Promise<void>((resolve) => {
        resolveSecondBatch = resolve;
    });
    const release: Array<() => void> = [];
    const ids = Array.from({ length: 16 }, (_, index) => index);

    const result = mapWithLocateConcurrency(
        ids,
        (id) =>
            new Promise<number>((resolve) => {
                active += 1;
                started += 1;
                maxActive = Math.max(maxActive, active);
                if (started === 8) resolveFirstBatch();
                if (started === 16) resolveSecondBatch();
                release.push(() => {
                    active -= 1;
                    resolve(id);
                });
            }),
    );

    await firstBatchStarted;
    expect(maxActive).toBe(8);
    release.splice(0).forEach((resolve) => resolve());
    await secondBatchStarted;
    expect(maxActive).toBe(8);
    release.splice(0).forEach((resolve) => resolve());

    expect(await result).toEqual(ids);
});
