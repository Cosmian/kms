import { Alert, Button, Card } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
import { useActionState } from "../../hooks/useActionState";
import { downloadFile } from "../../utils/utils";

const EstCaCertsForm: React.FC = () => {
    const { res, isLoading, responseRef, serverUrl, execute } = useActionState();
    const { t } = useTranslation("actions");

    const onDownload = async () => {
        await execute(async () => {
            const url = `${serverUrl}/.well-known/est/cacerts`;
            const response = await fetch(url, { method: "GET" });

            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error(t("estCaCerts.error404"));
                }
                const errorText = await response.text();
                throw new Error(`${response.status}: ${errorText}`);
            }

            // RFC 7030 §4.1.3: the body is base64 text wrapping a DER PKCS#7 bundle.
            const base64Body = (await response.text()).replace(/\s+/g, "");
            const der = Uint8Array.from(atob(base64Body), (c) => c.charCodeAt(0));
            downloadFile(der, "est-ca-certificates.p7b", "application/pkcs7-mime");

            return t("estCaCerts.success", { bytes: der.length });
        });
    };

    return (
        <Card title={t("estCaCerts.title")}>
            <Alert
                message={t("estCaCerts.alertMessage")}
                description={t("estCaCerts.alertDescription")}
                type="info"
                showIcon
                className="mb-4"
            />
            <Button
                type="primary"
                loading={isLoading}
                onClick={onDownload}
                className="w-full text-white font-medium"
                data-testid="submit-btn"
            >
                {t("estCaCerts.submit")}
            </Button>
            <ActionResponse title={t("estCaCerts.responseTitle")} res={res} responseRef={responseRef} />
        </Card>
    );
};

export default EstCaCertsForm;
