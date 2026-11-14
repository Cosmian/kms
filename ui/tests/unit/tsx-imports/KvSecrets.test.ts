import { act, fireEvent, screen, waitFor, within } from "@testing-library/react";
import React from "react";
import { expect, test, vi } from "vitest";

import KvSecrets from "../../../src/actions/Secrets/KvSecrets";
import { smokeRender } from "../test-utils";

type Call = { url: string; init: RequestInit };

/** Replace `fetch` with `handler` and record every request. */
function stubKv(handler: () => Response | Promise<Response>): Call[] {
    const calls: Call[] = [];
    vi.stubGlobal(
        "fetch",
        vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
            const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
            calls.push({ url, init });
            return handler();
        }),
    );
    return calls;
}

const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

const activePanel = () => within(screen.getByRole("tabpanel"));

const openTab = (name: string) => fireEvent.click(screen.getByRole("tab", { name }));

const type = (element: HTMLElement, value: string) => fireEvent.change(element, { target: { value } });

test("renders KvSecrets", () => {
    smokeRender(React.createElement(KvSecrets));
    expect(screen.getByRole("heading", { name: "Secrets (KV)" })).toBeInTheDocument();
    expect(screen.getByTestId("kv-mount")).toHaveValue("kv");
    expect(screen.getByTestId("kv-put-file")).toBeInTheDocument();
    for (const name of ["Put", "Get", "List", "Delete"]) {
        expect(screen.getByRole("tab", { name })).toBeInTheDocument();
    }
});

test("a JSON file keeps its value types and is forgotten once written", async () => {
    const calls = stubKv(() => json(200, { data: { version: 3 } }));
    const { container } = smokeRender(React.createElement(KvSecrets));
    const secret = {
        token: "abc",
        port: 5432,
        ratio: 0.25,
        enabled: true,
        none: null,
        nested: { hosts: ["a", "b"], limits: { max: 10 } },
    };
    const content = JSON.stringify(secret);
    const file = new File([content], "secret.json", { type: "application/json" });
    // jsdom's Blob has no text().
    Object.defineProperty(file, "text", { value: async () => content });

    fireEvent.change(container.querySelector('input[type="file"]') as HTMLInputElement, { target: { files: [file] } });
    await screen.findByTestId("kv-put-file-loaded");
    type(screen.getByTestId("kv-put-path"), "app/db");
    fireEvent.click(screen.getByTestId("submit-btn"));

    await screen.findByTestId("kv-put-result");
    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe("/kv/data/app/db");
    expect(calls[0].init).toMatchObject({ method: "POST", headers: { "Content-Type": "application/json" } });
    expect(JSON.parse(calls[0].init.body as string)).toEqual({ data: secret });
    expect(screen.queryByTestId("kv-put-file-loaded")).toBeNull();
    expect(screen.getByTestId("kv-put-value-0")).toHaveValue("");
});

test("pairs go to the selected mount with the expected owner and are cleared once written", async () => {
    const calls = stubKv(() => json(200, { data: { version: 1 } }));
    smokeRender(React.createElement(KvSecrets));

    type(screen.getByTestId("kv-mount"), "kvstore");
    type(screen.getByTestId("kv-put-path"), "app/db");
    type(screen.getByTestId("kv-put-key-0"), "password");
    type(screen.getByTestId("kv-put-value-0"), "s3cret");
    type(screen.getByTestId("kv-put-expected-owner"), "alice@acme.com");
    fireEvent.click(screen.getByTestId("submit-btn"));

    await screen.findByTestId("kv-put-result");
    expect(calls[0].url).toBe("/kvstore/data/app/db");
    expect(JSON.parse(calls[0].init.body as string)).toEqual({
        data: { password: "s3cret" },
        options: { expected_owner: "alice@acme.com" },
    });
    expect(screen.getByTestId("kv-put-key-0")).toHaveValue("");
    expect(screen.getByTestId("kv-put-value-0")).toHaveValue("");
});

test("a key given twice is refused before any request", async () => {
    const calls = stubKv(() => json(200, { data: { version: 1 } }));
    smokeRender(React.createElement(KvSecrets));

    type(screen.getByTestId("kv-put-path"), "app/db");
    fireEvent.click(screen.getByTestId("kv-put-add"));
    for (const index of [0, 1]) {
        type(await screen.findByTestId(`kv-put-key-${index}`), "k");
        type(screen.getByTestId(`kv-put-value-${index}`), `v${index}`);
    }
    fireEvent.click(screen.getByTestId("submit-btn"));

    expect(await screen.findByTestId("kv-error")).toHaveTextContent("more than once");
    expect(calls).toHaveLength(0);
});

test("an empty LIST (404) shows no keys while other failures are reported", async () => {
    let status = 404;
    const calls = stubKv(() => json(status, { errors: [] }));
    smokeRender(React.createElement(KvSecrets));
    openTab("List");

    fireEvent.click(activePanel().getByTestId("submit-btn"));
    expect(await screen.findByText("No keys found")).toBeInTheDocument();
    expect(screen.queryByTestId("kv-error")).toBeNull();

    status = 500;
    fireEvent.click(activePanel().getByTestId("submit-btn"));
    expect(await screen.findByTestId("kv-error")).toHaveTextContent("500");
    expect(screen.queryByText("No keys found")).toBeNull();
    expect(calls.map((call) => call.url)).toEqual(["/kv/metadata/?list=true", "/kv/metadata/?list=true"]);
});

test("a response arriving after a mount change is dropped", async () => {
    let respond: (response: Response) => void = () => {};
    const calls = stubKv(
        () =>
            new Promise<Response>((resolve) => {
                respond = resolve;
            }),
    );
    const secretResponse = () => json(200, { data: { data: { password: "s3cret" }, metadata: {} } });
    smokeRender(React.createElement(KvSecrets));
    openTab("Get");
    type(activePanel().getByTestId("kv-get-path"), "app/db");

    fireEvent.click(activePanel().getByTestId("submit-btn"));
    await waitFor(() => expect(calls).toHaveLength(1));
    type(screen.getByTestId("kv-mount"), "other");
    await act(async () => {
        respond(secretResponse());
        // Nothing signals a dropped response: let its promise chain settle before asserting absence.
        await new Promise((resolve) => setTimeout(resolve, 50));
    });
    expect(screen.queryByTestId("response-output")).toBeNull();
    expect(screen.queryByTestId("kv-error")).toBeNull();

    // The same request in the current scope is shown.
    fireEvent.click(activePanel().getByTestId("submit-btn"));
    await waitFor(() => expect(calls).toHaveLength(2));
    respond(secretResponse());
    expect(await screen.findByTestId("response-output")).toBeInTheDocument();
    expect(calls[1].url).toBe("/other/data/app/db");
});

test("switching tabs forgets a fetched secret; revealed values keep their JSON form", async () => {
    stubKv(() => json(200, { data: { data: { password: "s3cret", nested: { a: 1 } }, metadata: {} } }));
    smokeRender(React.createElement(KvSecrets));
    openTab("Get");
    type(activePanel().getByTestId("kv-get-path"), "app/db");
    fireEvent.click(activePanel().getByTestId("submit-btn"));

    fireEvent.click(await screen.findByTestId("kv-reveal"));
    expect(await screen.findByText('{"a":1}')).toBeInTheDocument();
    expect(screen.getByText("s3cret")).toBeInTheDocument();

    openTab("Put");
    openTab("Get");
    expect(screen.queryByTestId("response-output")).toBeNull();
    expect(screen.queryByText("s3cret")).toBeNull();
});

test("delete sends the session cookie with a JSON content type and no body", async () => {
    const calls = stubKv(() => new Response(null, { status: 204 }));
    smokeRender(React.createElement(KvSecrets));
    openTab("Delete");
    type(activePanel().getByTestId("kv-delete-path"), "app/db");

    fireEvent.click(activePanel().getByTestId("kv-delete-soft"));
    fireEvent.click(await screen.findByTestId("kv-confirm-ok"));

    await waitFor(() => expect(calls).toHaveLength(1));
    expect(calls[0]).toMatchObject({
        url: "/kv/data/app/db",
        init: { method: "DELETE", credentials: "include", headers: { "Content-Type": "application/json" } },
    });
    expect(calls[0].init.body).toBeUndefined();
});
