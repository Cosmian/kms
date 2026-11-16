import { Button, Card, Input } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";
import { useAuth } from "../../contexts/useAuth";
import { useActionState } from "../../hooks/useActionState";
import { postNoTTLVRequest } from "../../utils/utils";

interface PasswordResponse {
    data: {
        password: string;
    };
}

const GeneratePassword: React.FC = () => {
    const { serverUrl } = useAuth();
    const { res, isLoading, execute } = useActionState();
    const { t } = useTranslation("actions");

    const generate = async () => {
        await execute(async () => {
            const response = (await postNoTTLVRequest("/v1/secrets/password", {}, serverUrl)) as PasswordResponse;
            return response.data.password;
        });
    };

    return (
        <Card title={t("generatePassword.title")}>
            <p className="mb-4">{t("generatePassword.intro")}</p>
            <Button type="primary" onClick={generate} loading={isLoading} data-testid="generate-password">
                {t("generatePassword.submit")}
            </Button>
            {res && (
                <Input.Password
                    className="mt-4"
                    readOnly
                    value={res}
                    visibilityToggle
                    data-testid="generated-password"
                    aria-label={t("generatePassword.result")}
                />
            )}
        </Card>
    );
};

export default GeneratePassword;
