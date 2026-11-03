import { afterEach, expect, test, vi } from "vitest";

import { sendKmipRequest } from "../../src/utils/utils";

afterEach(() => {
    vi.useRealTimers();
});

test("aborts a stalled KMIP request when given a timeout", async () => {
    vi.useFakeTimers();
    vi.stubGlobal(
        "fetch",
        vi.fn(
            (_input: RequestInfo | URL, init?: RequestInit) =>
                new Promise<Response>((_resolve, reject) => {
                    init?.signal?.addEventListener("abort", () => reject(new DOMException("The operation was aborted.", "AbortError")), {
                        once: true,
                    });
                }),
        ),
    );

    let error: unknown;
    void sendKmipRequest({}, "https://kms.example.test", { timeoutMs: 30_000 }).catch((reason: unknown) => {
        error = reason;
    });

    await vi.advanceTimersByTimeAsync(30_000);

    expect(error).toBeInstanceOf(DOMException);
});

test("leaves KMIP requests unbounded without a timeout", async () => {
    vi.useFakeTimers();
    let signal: AbortSignal | null | undefined;
    let resolveResponse: ((response: Response) => void) | undefined;
    vi.stubGlobal(
        "fetch",
        vi.fn(
            (_input: RequestInfo | URL, init?: RequestInit) =>
                new Promise<Response>((resolve) => {
                    signal = init?.signal;
                    resolveResponse = resolve;
                }),
        ),
    );

    const request = sendKmipRequest({}, "https://kms.example.test");
    await vi.advanceTimersByTimeAsync(30_000);

    expect(signal).toBeUndefined();
    if (!resolveResponse) throw new Error("Fetch did not start");
    resolveResponse(new Response(JSON.stringify({}), { status: 200 }));
    await expect(request).resolves.toBe("{}");
});
