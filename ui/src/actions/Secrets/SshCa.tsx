import { Alert, Button, Card, Checkbox, Form, Input, Select, Space } from "antd";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { getTextRequest, putNoContentRequest, sendKmipRequest } from "../../utils/utils";
import * as wasm from "../../wasm/pkg";

interface CaForm {
    caKeyId?: string;
    curve?: string;
    sensitive?: boolean;
}

interface RoleForm {
    name: string;
    allowedPrincipals: string;
    allowedUsers?: string;
    defaultTtl: string;
    maxTtl: string;
}

type CreateKeyPairResponse = {
    PrivateKeyUniqueIdentifier: string;
};

const ROLE_NAME_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;

// The curves the server accepts for an SSH CA (Ed25519 only exists in non-FIPS builds).
const SSH_CA_CURVES = ["nist-p256", "nist-p384", "nist-p521", "ed25519"];

const splitList = (value?: string): string[] =>
    (value ?? "")
        .split(",")
        .map((item) => item.trim())
        .filter((item) => item.length > 0);

/** SSH CA and signing-role management; mirrors `ckms ssh ca` and `ckms ssh role`. */
const SshCa: React.FC = () => {
    const [caForm] = Form.useForm<CaForm>();
    const [roleForm] = Form.useForm<RoleForm>();
    const ca = useActionState();
    const role = useActionState();
    const { t } = useTranslation("actions");
    const [curveOptions, setCurveOptions] = useState<{ value: string; label: string }[]>([]);

    useEffect(() => {
        try {
            const w = wasm as unknown as { get_ec_algorithms?: () => { value: string; label: string }[] };
            const options = (w.get_ec_algorithms?.() ?? []).filter((o) => SSH_CA_CURVES.includes(o.value));
            setCurveOptions(options);
            if (options.length > 0 && !caForm.getFieldValue("curve")) {
                const preferred = options.find((o) => o.value === "nist-p256") ?? options[0];
                caForm.setFieldsValue({ curve: preferred.value });
            }
        } catch (e) {
            console.error("Error loading EC algorithms from WASM:", e);
        }
    }, [caForm]);

    const configureCa = async (values: CaForm) => {
        await ca.execute(async () => {
            let keyId = values.caKeyId?.trim();
            if (!keyId) {
                const request = wasm.create_ec_key_pair_ttlv_request(
                    undefined,
                    ["ssh-ca"],
                    values.curve ?? "",
                    values.sensitive ?? false,
                    undefined,
                );
                const result = await sendKmipRequest(request, ca.serverUrl);
                const parsed: CreateKeyPairResponse = await wasm.parse_create_keypair_ttlv_response(result);
                keyId = parsed.PrivateKeyUniqueIdentifier;
            }
            await putNoContentRequest("/v1/ssh/config/ca", { ca_key_uid: keyId }, ca.serverUrl);
            const publicKey = await getTextRequest("/v1/ssh/public_key", ca.serverUrl);
            return t("sshCa.caConfigured", { keyId, publicKey: publicKey.trim() });
        });
    };

    const showPublicKey = async () => {
        await ca.execute(async () => (await getTextRequest("/v1/ssh/public_key", ca.serverUrl)).trim());
    };

    const putRole = async (values: RoleForm) => {
        await role.execute(async () => {
            const body = {
                allowed_principals: splitList(values.allowedPrincipals),
                allowed_users: splitList(values.allowedUsers),
                default_ttl: values.defaultTtl.trim(),
                max_ttl: values.maxTtl.trim(),
            };
            await putNoContentRequest(`/v1/ssh/roles/${encodeURIComponent(values.name.trim())}`, body, role.serverUrl);
            return t("sshCa.roleSaved", { name: values.name.trim() });
        });
    };

    return (
        <Space direction="vertical" size="middle" style={{ display: "flex" }}>
            <Card title={t("sshCa.caTitle")}>
                <Alert type="info" showIcon className="mb-4" message={t("sshCa.caIntro")} />
                <Form form={caForm} layout="vertical" onFinish={configureCa}>
                    <Form.Item name="caKeyId" label={t("sshCa.caKeyId")} extra={t("sshCa.caKeyIdHelp")}>
                        <Input data-testid="ssh-ca-key-id" />
                    </Form.Item>
                    <Form.Item name="curve" label={t("sshCa.curve")} extra={t("sshCa.curveHelp")}>
                        <Select options={curveOptions} data-testid="ssh-ca-curve" />
                    </Form.Item>
                    <Form.Item name="sensitive" valuePropName="checked" help={t("ecKeysCreate.sensitiveHelp")}>
                        <Checkbox data-testid="ssh-ca-sensitive">{t("ecKeysCreate.sensitive")}</Checkbox>
                    </Form.Item>
                    <Space>
                        <Button type="primary" htmlType="submit" loading={ca.isLoading} data-testid="submit-ssh-ca">
                            {t("sshCa.configureCa")}
                        </Button>
                        <Button onClick={showPublicKey} data-testid="ssh-ca-public-key">
                            {t("sshCa.showPublicKey")}
                        </Button>
                    </Space>
                </Form>
                <div data-testid="ssh-ca-result" className="whitespace-pre-wrap">
                    <ActionResponse title={t("sshCa.caResponseTitle")} res={ca.res} responseRef={ca.responseRef} />
                </div>
            </Card>
            <Card title={t("sshCa.roleTitle")}>
                <Alert type="info" showIcon className="mb-4" message={t("sshCa.roleIntro")} />
                <Form form={roleForm} layout="vertical" onFinish={putRole} initialValues={{ defaultTtl: "15m", maxTtl: "1h" }}>
                    <Form.Item
                        name="name"
                        label={t("sshCa.roleName")}
                        extra={t("sshCa.roleNameHelp")}
                        rules={[{ required: true }, { pattern: ROLE_NAME_PATTERN, message: t("sshCa.roleNameInvalid") }]}
                    >
                        <Input data-testid="ssh-role-name" />
                    </Form.Item>
                    <Form.Item
                        name="allowedPrincipals"
                        label={t("sshCa.allowedPrincipals")}
                        extra={t("sshCa.allowedPrincipalsHelp")}
                        rules={[{ required: true }]}
                    >
                        <Input data-testid="ssh-role-principals" />
                    </Form.Item>
                    <Form.Item name="allowedUsers" label={t("sshCa.allowedUsers")} extra={t("sshCa.allowedUsersHelp")}>
                        <Input data-testid="ssh-role-users" />
                    </Form.Item>
                    <Form.Item name="defaultTtl" label={t("sshCa.defaultTtl")} rules={[{ required: true }]}>
                        <Input placeholder={t("sshCertificate.ttlPlaceholder")} data-testid="ssh-role-default-ttl" />
                    </Form.Item>
                    <Form.Item name="maxTtl" label={t("sshCa.maxTtl")} rules={[{ required: true }]}>
                        <Input placeholder={t("sshCa.maxTtlPlaceholder")} data-testid="ssh-role-max-ttl" />
                    </Form.Item>
                    <Button type="primary" htmlType="submit" loading={role.isLoading} data-testid="submit-ssh-role">
                        {t("sshCa.saveRole")}
                    </Button>
                </Form>
                <div data-testid="ssh-role-result">
                    <ActionResponse title={t("sshCa.roleResponseTitle")} res={role.res} responseRef={role.responseRef} />
                </div>
            </Card>
        </Space>
    );
};

export default SshCa;
