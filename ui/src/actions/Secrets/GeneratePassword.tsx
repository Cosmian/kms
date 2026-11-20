import { Button, Card, Input } from "antd";
import React, { useState } from "react";
import { useTranslation } from "react-i18next";
import { ActionResponse } from "../../components/common/ActionResponse";
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
    // Errors go to `res`; only a successful response fills the password field.
    const { res, isLoading, responseRef, execute } = useActionState();
    const [password, setPassword] = useState<string>();
    const { t } = useTranslation("actions");

    const generate = async () => {
        setPassword(undefined);
        await execute(async () => {
            const response = (await postNoTTLVRequest("/v1/secrets/password", {}, serverUrl)) as PasswordResponse;
            setPassword(response.data.password);
            return undefined;
        });
    };

    return (
        <Card title={t("generatePassword.title")}>
            <p className="mb-4">{t("generatePassword.intro")}</p>
            <Button type="primary" onClick={generate} loading={isLoading} data-testid="generate-password">
                {t("generatePassword.submit")}
            </Button>
            {password && (
                <Input.Password
                    className="mt-4"
                    readOnly
                    value={password}
                    visibilityToggle
                    data-testid="generated-password"
                    aria-label={t("generatePassword.result")}
                />
            )}
            <ActionResponse title={t("generatePassword.title")} res={res} responseRef={responseRef} />
        </Card>
    );
};

export default GeneratePassword;
