import { EyeInvisibleOutlined, EyeOutlined, MinusCircleOutlined, PlusOutlined, UploadOutlined } from "@ant-design/icons";
import { Alert, Button, Card, Form, Input, InputNumber, Modal, Space, Table, Tabs, message } from "antd";
import React, { useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { FormUpload } from "../../components/common/FormUpload";
import { useAuth } from "../../contexts/useAuth";

/** Default KV mount of the server (`kv_mount`), like `ckms kv --mount`. */
const DEFAULT_KV_MOUNT = "kv";

interface KvPair {
    key: string;
    value: string;
}

interface PutValues {
    path: string;
    pairs?: KvPair[];
    ttl?: string;
    expectedOwner?: string;
}

/** A secret loaded from a JSON file: values keep their JSON type, like `ckms kv put --from-file`. */
interface FileSecret {
    name: string;
    data: Record<string, unknown>;
}

const emptyPairs = (): KvPair[] => [{ key: "", value: "" }];

interface KvData {
    data: Record<string, unknown>;
    metadata: Record<string, unknown>;
}

const encodePath = (path: string): string =>
    path
        .split("/")
        .filter((s) => s.length > 0)
        .map(encodeURIComponent)
        .join("/");

class KvHttpError extends Error {
    status: number;
    constructor(status: number, message: string) {
        super(message);
        this.status = status;
    }
}

/** Vault-compatible KV request; returns parsed JSON (or undefined on 204). */
const kvRequest = async (serverUrl: string, method: string, path: string, body?: object) => {
    const response = await fetch(serverUrl + path, {
        method,
        credentials: "include",
        // State-changing requests need a non-safelisted Content-Type: the session cookie guard rejects them otherwise.
        headers: method === "GET" ? {} : { "Content-Type": "application/json" },
        body: body ? JSON.stringify(body) : undefined,
    });
    if (!response.ok) {
        const text = await response.text();
        throw new KvHttpError(response.status, `${response.status}: ${text.replace(/<[^>]*>/g, "").trim()}`);
    }
    return response.status === 204 ? undefined : await response.json();
};

const isJsonObject = (value: unknown): value is Record<string, unknown> =>
    typeof value === "object" && value !== null && !Array.isArray(value);

const KvSecrets: React.FC = () => {
    const { t } = useTranslation("actions");
    const { serverUrl } = useAuth();
    const [messageApi, contextHolder] = message.useMessage();
    const [modal, modalContext] = Modal.useModal();
    const [putForm] = Form.useForm<PutValues>();
    const [getForm] = Form.useForm<{ path: string; version?: number }>();
    const [listForm] = Form.useForm<{ prefix?: string }>();
    const [delForm] = Form.useForm<{ path: string }>();
    const [activeTab, setActiveTab] = useState("put");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | undefined>(undefined);
    const [putRes, setPutRes] = useState<number | undefined>(undefined);
    const [secret, setSecret] = useState<KvData | undefined>(undefined);
    const [reveal, setReveal] = useState(false);
    const [keys, setKeys] = useState<string[] | undefined>(undefined);
    const [listPrefix, setListPrefix] = useState("");
    const [fileSecret, setFileSecret] = useState<FileSecret | undefined>(undefined);
    const [mount, setMount] = useState(DEFAULT_KV_MOUNT);
    const kvMount = `/${encodeURIComponent(mount.trim() || DEFAULT_KV_MOUNT)}`;
    /** Bumped on every request and scope change (mount, tab): a response of an older scope is dropped. */
    const scope = useRef(0);

    /** Forget every secret and result, and drop the responses still in flight. */
    const clearScope = () => {
        scope.current += 1;
        setLoading(false);
        setError(undefined);
        setPutRes(undefined);
        setSecret(undefined);
        setReveal(false);
        setKeys(undefined);
        setFileSecret(undefined);
        putForm.setFieldsValue({ pairs: emptyPairs() });
    };

    /** Load the secret from a JSON object file (`ckms kv put --from-file`); values are kept as is. */
    const loadFile = async (file: File) => {
        const loadScope = scope.current;
        let parsed: unknown;
        try {
            parsed = JSON.parse(await file.text());
        } catch {
            parsed = undefined;
        }
        if (scope.current !== loadScope) return;
        if (!isJsonObject(parsed) || Object.keys(parsed).length === 0) {
            setError(t("kvSecrets.fileInvalid"));
            return;
        }
        setError(undefined);
        setFileSecret({ name: file.name, data: parsed });
        putForm.setFieldsValue({ pairs: emptyPairs() });
    };

    /** Run `request`; the state update it returns is applied only if no newer request or scope change happened. */
    const run = async (request: () => Promise<() => void>) => {
        const requestScope = ++scope.current;
        setLoading(true);
        setError(undefined);
        try {
            const commit = await request();
            if (scope.current === requestScope) commit();
        } catch (e) {
            if (scope.current === requestScope) setError(String(e));
        } finally {
            if (scope.current === requestScope) setLoading(false);
        }
    };

    const fetchSecret = (path: string, version?: number) =>
        run(async () => {
            setSecret(undefined);
            setReveal(false);
            const query = version ? `?version=${version}` : "";
            const res = await kvRequest(serverUrl, "GET", `${kvMount}/data/${encodePath(path)}${query}`);
            return () => setSecret(res.data as KvData);
        });

    const onPut = (v: PutValues) => {
        const pairs = v.pairs ?? [];
        const duplicate = pairs.find((p, i) => pairs.findIndex((q) => q.key === p.key) !== i);
        if (!fileSecret && duplicate) {
            setError(t("kvSecrets.duplicateKey", { key: duplicate.key }));
            return;
        }
        const data = fileSecret?.data ?? Object.fromEntries(pairs.map((p) => [p.key, p.value]));
        const ttl = v.ttl?.trim();
        const expectedOwner = v.expectedOwner?.trim();
        const options = { ...(ttl ? { ttl } : {}), ...(expectedOwner ? { expected_owner: expectedOwner } : {}) };
        return run(async () => {
            setPutRes(undefined);
            const res = await kvRequest(serverUrl, "POST", `${kvMount}/data/${encodePath(v.path)}`, {
                data,
                ...(Object.keys(options).length > 0 ? { options } : {}),
            });
            return () => {
                setPutRes(res.data.version as number);
                // Do not keep the written values once the server has them.
                setFileSecret(undefined);
                putForm.setFieldsValue({ pairs: emptyPairs() });
            };
        });
    };

    const fetchList = (prefix: string) =>
        run(async () => {
            setKeys(undefined);
            const p = encodePath(prefix);
            let found: string[] = [];
            try {
                const res = await kvRequest(serverUrl, "GET", `${kvMount}/metadata/${p}${p ? "/" : ""}?list=true`);
                found = (res.data.keys as string[]) ?? [];
            } catch (e) {
                // Vault answers a LIST with no keys with 404; every other failure is reported.
                if (!(e instanceof KvHttpError && e.status === 404)) throw e;
            }
            return () => {
                setListPrefix(prefix);
                setKeys(found);
            };
        });

    const changeTab = (key: string) => {
        setActiveTab(key);
        clearScope();
    };

    const openKey = (key: string) => {
        const full = `${listPrefix.replace(/\/+$/, "")}${listPrefix ? "/" : ""}${key}`;
        if (key.endsWith("/")) {
            listForm.setFieldsValue({ prefix: full });
            void fetchList(full);
            return;
        }
        getForm.setFieldsValue({ path: full, version: undefined });
        changeTab("get");
        void fetchSecret(full);
    };

    const del = (destroy: boolean) => async (v: { path: string }) => {
        const confirmed = await modal.confirm({
            title: t(destroy ? "kvSecrets.confirmDestroy" : "kvSecrets.confirmDelete", { path: v.path }),
            okButtonProps: { danger: true, "data-testid": "kv-confirm-ok" },
        });
        if (!confirmed) return;
        await run(async () => {
            await kvRequest(serverUrl, "DELETE", `${kvMount}/${destroy ? "metadata" : "data"}/${encodePath(v.path)}`);
            return () => messageApi.success(t(destroy ? "kvSecrets.destroyed" : "kvSecrets.deleted"));
        });
    };

    const putTab = (
        <Form form={putForm} layout="vertical" onFinish={onPut} initialValues={{ pairs: emptyPairs() }}>
            <Form.Item name="path" label={t("kvSecrets.path")} rules={[{ required: true }]}>
                <Input placeholder="app/db" data-testid="kv-put-path" />
            </Form.Item>
            <Form.Item>
                <FormUpload
                    accept=".json,application/json"
                    showUploadList={false}
                    beforeUpload={(file) => {
                        void loadFile(file);
                        return false;
                    }}
                >
                    <Button icon={<UploadOutlined />} data-testid="kv-put-file">
                        {t("kvSecrets.fromFile")}
                    </Button>
                </FormUpload>
            </Form.Item>
            {fileSecret ? (
                <Alert
                    className="mb-4"
                    type="info"
                    showIcon
                    closable
                    onClose={() => setFileSecret(undefined)}
                    message={t("kvSecrets.fileLoaded", { name: fileSecret.name, keys: Object.keys(fileSecret.data).length })}
                    data-testid="kv-put-file-loaded"
                />
            ) : (
                <Form.List name="pairs">
                    {(fields, { add, remove }) => (
                        <>
                            {fields.map((f) => (
                                <Space key={f.key} align="baseline" className="flex">
                                    <Form.Item name={[f.name, "key"]} rules={[{ required: true }]}>
                                        <Input placeholder={t("kvSecrets.key")} data-testid={`kv-put-key-${f.name}`} />
                                    </Form.Item>
                                    <Form.Item name={[f.name, "value"]} rules={[{ required: true }]}>
                                        <Input.Password placeholder={t("kvSecrets.value")} data-testid={`kv-put-value-${f.name}`} />
                                    </Form.Item>
                                    {fields.length > 1 && <MinusCircleOutlined onClick={() => remove(f.name)} />}
                                </Space>
                            ))}
                            <Form.Item>
                                <Button type="dashed" icon={<PlusOutlined />} onClick={() => add()} data-testid="kv-put-add">
                                    {t("kvSecrets.addPair")}
                                </Button>
                            </Form.Item>
                        </>
                    )}
                </Form.List>
            )}
            <Form.Item name="ttl" label={t("kvSecrets.ttl")} extra={t("kvSecrets.ttlHelp")}>
                <Input placeholder="1h" data-testid="kv-put-ttl" />
            </Form.Item>
            <Form.Item name="expectedOwner" label={t("kvSecrets.expectedOwner")} extra={t("kvSecrets.expectedOwnerHelp")}>
                <Input data-testid="kv-put-expected-owner" />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} data-testid="submit-btn">
                {t("kvSecrets.put")}
            </Button>
            {putRes !== undefined && (
                <Alert
                    className="mt-4"
                    type="success"
                    showIcon
                    message={t("kvSecrets.putOk", { version: putRes })}
                    data-testid="kv-put-result"
                />
            )}
        </Form>
    );

    const getTab = (
        <Form form={getForm} layout="vertical" onFinish={(v: { path: string; version?: number }) => fetchSecret(v.path, v.version)}>
            <Form.Item name="path" label={t("kvSecrets.path")} rules={[{ required: true }]}>
                <Input placeholder="app/db" data-testid="kv-get-path" />
            </Form.Item>
            <Form.Item name="version" label={t("kvSecrets.version")}>
                <InputNumber min={1} data-testid="kv-get-version" />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} data-testid="submit-btn">
                {t("kvSecrets.get")}
            </Button>
            {secret && (
                <Card
                    className="mt-4"
                    title={t("kvSecrets.dataTitle")}
                    extra={
                        <Button
                            icon={reveal ? <EyeInvisibleOutlined /> : <EyeOutlined />}
                            onClick={() => setReveal(!reveal)}
                            data-testid="kv-reveal"
                        >
                            {t(reveal ? "kvSecrets.hide" : "kvSecrets.reveal")}
                        </Button>
                    }
                    data-testid="response-output"
                >
                    <Table
                        size="small"
                        pagination={false}
                        rowKey="key"
                        dataSource={Object.entries(secret.data).map(([key, value]) => ({ key, value }))}
                        columns={[
                            { title: t("kvSecrets.key"), dataIndex: "key" },
                            {
                                title: t("kvSecrets.value"),
                                dataIndex: "value",
                                render: (v: unknown) => (reveal ? (typeof v === "string" ? v : JSON.stringify(v)) : "••••••••"),
                            },
                        ]}
                    />
                    <pre className="mt-2 text-xs">{JSON.stringify(secret.metadata, null, 2)}</pre>
                </Card>
            )}
        </Form>
    );

    const listTab = (
        <Form form={listForm} layout="vertical" onFinish={(v: { prefix?: string }) => fetchList(v.prefix ?? "")}>
            <Form.Item name="prefix" label={t("kvSecrets.prefix")}>
                <Input placeholder="app" data-testid="kv-list-prefix" />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={loading} data-testid="submit-btn">
                {t("kvSecrets.list")}
            </Button>
            {keys && (
                <Card className="mt-4" title={t("kvSecrets.keysTitle")} data-testid="response-output">
                    {keys.length === 0 ? (
                        <p className="text-gray-500">{t("kvSecrets.noKeys")}</p>
                    ) : (
                        <Space direction="vertical">
                            {keys.map((k) => (
                                <Button key={k} type="link" onClick={() => openKey(k)} data-testid={`kv-key-${k}`}>
                                    {k}
                                </Button>
                            ))}
                        </Space>
                    )}
                </Card>
            )}
        </Form>
    );

    const deleteTab = (
        <Form form={delForm} layout="vertical">
            <Form.Item name="path" label={t("kvSecrets.path")} rules={[{ required: true }]}>
                <Input placeholder="app/db" data-testid="kv-delete-path" />
            </Form.Item>
            <Space>
                <Button loading={loading} onClick={() => delForm.validateFields().then(del(false))} data-testid="kv-delete-soft">
                    {t("kvSecrets.delete")}
                </Button>
                <Button danger loading={loading} onClick={() => delForm.validateFields().then(del(true))} data-testid="kv-delete-destroy">
                    {t("kvSecrets.destroy")}
                </Button>
            </Space>
            <p className="mt-2 text-gray-500">{t("kvSecrets.deleteHelp")}</p>
        </Form>
    );

    return (
        <div className="p-6">
            {contextHolder}
            {modalContext}
            <h1 className="text-2xl font-bold mb-2">{t("kvSecrets.title")}</h1>
            <p className="mb-6">{t("kvSecrets.intro")}</p>
            <div className="mb-4 max-w-xs">
                <label htmlFor="kv-mount" className="block mb-1">
                    {t("kvSecrets.mount")}
                </label>
                <Input
                    id="kv-mount"
                    value={mount}
                    onChange={(e) => {
                        setMount(e.target.value);
                        clearScope();
                    }}
                    placeholder={DEFAULT_KV_MOUNT}
                    data-testid="kv-mount"
                />
            </div>
            <Tabs
                activeKey={activeTab}
                onChange={changeTab}
                items={[
                    { key: "put", label: <span data-testid="kv-tab-put">{t("kvSecrets.put")}</span>, children: putTab },
                    { key: "get", label: <span data-testid="kv-tab-get">{t("kvSecrets.get")}</span>, children: getTab },
                    { key: "list", label: <span data-testid="kv-tab-list">{t("kvSecrets.list")}</span>, children: listTab },
                    { key: "delete", label: <span data-testid="kv-tab-delete">{t("kvSecrets.delete")}</span>, children: deleteTab },
                ]}
            />
            {error && <Alert className="mt-4" type="error" showIcon message={error} data-testid="kv-error" />}
        </div>
    );
};

export default KvSecrets;
