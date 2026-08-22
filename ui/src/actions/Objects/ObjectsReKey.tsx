import { Button, Card, Form, Select, Space } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import type { TFunction } from "i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { sendKmipRequest } from "../../utils/utils";
import KeyIdInput from "../../components/common/KeyIdInput";
import {
    parse_rekey_keypair_ttlv_response,
    parse_rekey_ttlv_response,
    rekey_keypair_ttlv_request,
    rekey_ttlv_request,
} from "../../wasm/pkg/cosmian_kms_client_wasm";

/** Key types supported by the ReKey operation. */
type ReKeyType = "symmetric" | "rsa" | "ec" | "pqc";

interface ReKeyFormData {
    keyId?: string;
    tags?: string[];
}

interface ReKeyKeyPairResponse {
    PrivateKeyUniqueIdentifier: string;
    PublicKeyUniqueIdentifier: string;
}

interface ReKeySymmetricResponse {
    UniqueIdentifier: string;
}

interface ReKeyConfig {
    titleKey: string;
    descriptionKey: string;
    bulletKeys: string[];
    keyLabelKey: string;
    isKeyPair: boolean;
}

const REKEY_CONFIG: Record<ReKeyType, ReKeyConfig> = {
    symmetric: {
        titleKey: "titleSymmetric",
        descriptionKey: "descSymmetric",
        bulletKeys: ["bulletSym1", "bulletSym2"],
        keyLabelKey: "keyLabelKeyId",
        isKeyPair: false,
    },
    rsa: {
        titleKey: "titleRsa",
        descriptionKey: "descRsa",
        bulletKeys: ["bulletRsa1", "bulletRsa2", "bulletRsa3"],
        keyLabelKey: "keyLabelPrivateKeyId",
        isKeyPair: true,
    },
    ec: {
        titleKey: "titleEc",
        descriptionKey: "descEc",
        bulletKeys: ["bulletEc1", "bulletEc2", "bulletEc3"],
        keyLabelKey: "keyLabelPrivateKeyId",
        isKeyPair: true,
    },
    pqc: {
        titleKey: "titlePqc",
        descriptionKey: "descPqc",
        bulletKeys: ["bulletPqc1", "bulletPqc2", "bulletPqc3"],
        keyLabelKey: "keyLabelPrivateKeyId",
        isKeyPair: true,
    },
};

function buildSuccessMessage(keyType: ReKeyType, response: ReKeySymmetricResponse | ReKeyKeyPairResponse, t: TFunction): string {
    if (keyType === "symmetric") {
        return t("objectsReKey.successSymmetric", { newKey: (response as ReKeySymmetricResponse).UniqueIdentifier });
    }
    const kpResponse = response as ReKeyKeyPairResponse;
    const typeLabel =
        keyType === "rsa" ? t("objectsReKey.typeRsa") : keyType === "ec" ? t("objectsReKey.typeEc") : t("objectsReKey.typePqc");
    return t("objectsReKey.successKeyPair", {
        typeLabel,
        privateKey: kpResponse.PrivateKeyUniqueIdentifier,
        publicKey: kpResponse.PublicKeyUniqueIdentifier,
    });
}

interface ObjectsReKeyProps {
    keyType: ReKeyType;
}

/**
 * Generic Re-Key form for symmetric keys and asymmetric key pairs.
 *
 * Renders appropriate titles, descriptions, and calls the correct WASM function
 * depending on the {@link ReKeyType} prop.
 */
const ObjectsReKeyForm: React.FC<ObjectsReKeyProps> = ({ keyType }) => {
    const [form] = Form.useForm<ReKeyFormData>();
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const config = REKEY_CONFIG[keyType];
    const title = t(`objectsReKey.${config.titleKey}`);
    const description = t(`objectsReKey.${config.descriptionKey}`);
    const bullets = config.bulletKeys.map((k) => t(`objectsReKey.${k}`));
    const keyLabel = t(`objectsReKey.${config.keyLabelKey}`);

    const onFinish = async (values: ReKeyFormData) => {
        const id = values.keyId || (values.tags?.length ? JSON.stringify(values.tags) : undefined);
        await execute(async () => {
            if (!id) {
                throw new Error(t("objectsReKey.missingIdentifier", { keyLabel }));
            }
            if (config.isKeyPair) {
                const request = rekey_keypair_ttlv_request(id);
                const resultStr = await sendKmipRequest(request, serverUrl);
                if (resultStr) {
                    const result = parse_rekey_keypair_ttlv_response(resultStr) as ReKeyKeyPairResponse;
                    return buildSuccessMessage(keyType, result, t);
                }
            } else {
                const request = rekey_ttlv_request(id);
                const resultStr = await sendKmipRequest(request, serverUrl);
                if (resultStr) {
                    const result = parse_rekey_ttlv_response(resultStr) as ReKeySymmetricResponse;
                    return buildSuccessMessage(keyType, result, t);
                }
            }
        });
    };

    return (
        <div className="p-6">
            <h1 className="text-2xl font-bold mb-6">{title}</h1>

            <div className="mb-8 space-y-2">
                <p>{description}</p>
                <ul className="list-disc pl-5 space-y-1">
                    {bullets.map((bullet) => (
                        <li key={bullet}>{bullet}</li>
                    ))}
                </ul>
            </div>

            <Form form={form} onFinish={onFinish} layout="vertical">
                <Space direction="vertical" size="middle" style={{ display: "flex" }}>
                    <Card>
                        <KeyIdInput
                            form={form}
                            fieldName="keyId"
                            label={keyLabel}
                            help={t("objectsReKey.keyIdHelp", { keyLabel })}
                            placeholder={t("objectsReKey.keyIdPlaceholder", { keyLabel })}
                            data-testid="rekey-key-id"
                        />
                        <Form.Item name="tags" label={t("common:tags")} help={t("objectsReKey.tagsHelp", { keyLabel })}>
                            <Select
                                mode="tags"
                                placeholder={t("objectsReKey.enterKeyId", { keyLabel })}
                                open={false}
                                data-testid="rekey-tags"
                            />
                        </Form.Item>
                    </Card>

                    <Form.Item>
                        <Button
                            type="primary"
                            htmlType="submit"
                            loading={isLoading}
                            className="w-full text-white font-medium"
                            data-testid="submit-btn"
                        >
                            {t("objectsReKey.submit")}
                        </Button>
                    </Form.Item>
                </Space>
                <ActionResponse res={res} responseRef={responseRef} title={t("objectsReKey.responseTitle")} />
            </Form>
        </div>
    );
};

export default ObjectsReKeyForm;
