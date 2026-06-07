import { Button, Form, Modal, Select, Space, Table, Tag } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { SearchOutlined } from "@ant-design/icons";
import { sendKmipRequest } from "../../utils/utils";
import { useAuth } from "../../contexts/useAuth";
import * as wasm from "../../wasm/pkg";

/** Attribute keys to fetch for each located object. */
const ENRICH_KEYS = ["object_type", "state", "cryptographic_algorithm", "cryptographic_length", "key_format_type"];

interface LocateRow {
    object_id: string;
    objectType?: string;
    state?: string;
    algorithm?: string;
    length?: number;
    format?: string;
}

interface LocateButtonProps {
    /** Called when a row is selected. */
    onSelect: (uid: string) => void;
    /** Override button text (default: "Search Objects"). */
    buttonText?: string;
    /** Pre-filter by object type (e.g., "SplitKey"). */
    objectType?: string;
    /** Additional filter tags. */
    tags?: string[];
    /** CSS class for the button. */
    className?: string;
    /** Make the button full-width. */
    block?: boolean;
}

/** Normalise a state value coming from WASM (may be an enum number or a string). */
function normaliseState(v: unknown): string | undefined {
    if (v == null) return undefined;
    if (typeof v === "string") return v;
    if (typeof v === "number") {
        const MAP: Record<number, string> = {
            1: "PreActive",
            2: "Active",
            3: "Deactivated",
            4: "Compromised",
            5: "Destroyed",
            6: "Destroyed Compromised",
        };
        return MAP[v];
    }
    if (typeof v === "object") {
        const s = String((v as Record<string, unknown>).value ?? "");
        return s || undefined;
    }
    return String(v) || undefined;
}

function stateColor(state?: string): string {
    switch (state?.toLowerCase()) {
        case "active":
            return "green";
        case "preactive":
            return "blue";
        case "deactivated":
            return "orange";
        case "compromised":
        case "destroyed compromised":
            return "red";
        case "destroyed":
            return "default";
        default:
            return "default";
    }
}

/** Fetch Type/Algorithm/Length/Format/State attributes for a list of UIDs in parallel. */
async function enrichRows(uids: string[], serverUrl: string): Promise<LocateRow[]> {
    return Promise.all(
        uids.map(async (uid): Promise<LocateRow> => {
            try {
                const req = wasm.get_attributes_ttlv_request(uid);
                const respStr = await sendKmipRequest(req, serverUrl);
                if (respStr) {
                    const parsed = await wasm.parse_get_attributes_ttlv_response(respStr, ENRICH_KEYS);
                    const m: Record<string, unknown> =
                        parsed instanceof Map ? Object.fromEntries(parsed as Map<string, unknown>) : (parsed as Record<string, unknown>);
                    const lengthRaw = m["cryptographic_length"];
                    return {
                        object_id: uid,
                        objectType: m["object_type"] as string | undefined,
                        state: normaliseState(m["state"]) ?? (/^hsm[0-9]*::/.test(uid) ? "Active" : undefined),
                        algorithm: m["cryptographic_algorithm"] as string | undefined,
                        length: typeof lengthRaw === "number" ? lengthRaw : undefined,
                        format: m["key_format_type"] as string | undefined,
                    };
                }
            } catch {
                /* best-effort */
            }
            return { object_id: uid, state: /^hsm[0-9]*::/.test(uid) ? "Active" : undefined };
        }),
    );
}

const LocateButton: React.FC<LocateButtonProps> = ({ onSelect, buttonText, objectType, tags, className, block }) => {
    const [visible, setVisible] = useState(false);
    const [results, setResults] = useState<LocateRow[]>([]);
    const [loading, setLoading] = useState(false);
    const [searchTags, setSearchTags] = useState<string[]>(tags ?? []);
    const { serverUrl } = useAuth();
    const { t } = useTranslation("common");
    const finalButtonText = buttonText ?? t("searchObjects");

    const runSearch = async () => {
        setLoading(true);
        try {
            const req = wasm.locate_ttlv_request(
                searchTags.length > 0 ? searchTags : undefined,
                undefined as unknown as string | undefined,
                undefined,
                undefined as unknown as string | undefined,
                objectType,
                undefined,
                undefined,
                undefined,
            );
            const respStr = await sendKmipRequest(req, serverUrl);
            if (respStr) {
                const resp = await wasm.parse_locate_ttlv_response(respStr);
                const uids: string[] = Array.isArray(resp.UniqueIdentifier) ? (resp.UniqueIdentifier as string[]) : [];
                const rows = await enrichRows(uids, serverUrl);
                setResults(rows);
            }
        } catch {
            /* ignore */
        } finally {
            setLoading(false);
        }
    };

    const selectRow = (uid: string) => {
        onSelect(uid);
        setVisible(false);
        setResults([]);
    };

    return (
        <>
            <Button
                block={block}
                icon={<SearchOutlined />}
                onClick={() => {
                    setVisible(true);
                    setResults([]);
                }}
                className={className}
            >
                {finalButtonText}
            </Button>

            <Modal title={t("searchObjects")} open={visible} onCancel={() => setVisible(false)} footer={null} width={980}>
                <Space direction="vertical" style={{ width: "100%" }} size="middle">
                    <Form layout="inline" style={{ flexWrap: "nowrap", gap: 8 }}>
                        <Form.Item label="Tags" style={{ flex: 1 }}>
                            <Select
                                mode="tags"
                                placeholder="Enter tags"
                                value={searchTags}
                                onChange={setSearchTags}
                                open={false}
                                suffixIcon={null}
                                style={{ minWidth: 200 }}
                            />
                        </Form.Item>
                        <Form.Item>
                            <Button type="primary" icon={<SearchOutlined />} loading={loading} onClick={runSearch} data-testid="locate-btn">
                                {t("searchObjects")}
                            </Button>
                        </Form.Item>
                    </Form>

                    {results.length > 0 && (
                        <Table<LocateRow>
                            dataSource={results}
                            rowKey="object_id"
                            size="small"
                            pagination={{ pageSize: 25, size: "small", showSizeChanger: true, pageSizeOptions: [25, 50, 100] }}
                            scroll={{ x: "max-content" }}
                            onRow={(row) => ({
                                onClick: () => selectRow(row.object_id),
                                style: { cursor: "pointer" },
                            })}
                            columns={[
                                {
                                    title: "UID",
                                    dataIndex: "object_id",
                                    key: "object_id",
                                    ellipsis: true,
                                    width: 280,
                                },
                                {
                                    title: "Type",
                                    dataIndex: "objectType",
                                    key: "objectType",
                                    width: 110,
                                    render: (v?: string) => v ?? <span style={{ color: "#bbb" }}>—</span>,
                                },
                                {
                                    title: "Algorithm",
                                    dataIndex: "algorithm",
                                    key: "algorithm",
                                    width: 100,
                                    render: (v?: string) => v ?? <span style={{ color: "#bbb" }}>—</span>,
                                },
                                {
                                    title: "Length",
                                    dataIndex: "length",
                                    key: "length",
                                    width: 70,
                                    align: "right" as const,
                                    render: (v?: number) => (v != null ? v : <span style={{ color: "#bbb" }}>—</span>),
                                },
                                {
                                    title: "Format",
                                    dataIndex: "format",
                                    key: "format",
                                    width: 130,
                                    render: (v?: string) => v ?? <span style={{ color: "#bbb" }}>—</span>,
                                },
                                {
                                    title: "State",
                                    dataIndex: "state",
                                    key: "state",
                                    width: 110,
                                    render: (v?: string) =>
                                        v ? <Tag color={stateColor(v)}>{v}</Tag> : <span style={{ color: "#bbb" }}>—</span>,
                                },
                            ]}
                        />
                    )}
                </Space>
            </Modal>
        </>
    );
};

export default LocateButton;
