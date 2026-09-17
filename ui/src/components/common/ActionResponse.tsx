import { Card } from "antd";
import React from "react";
import { useTranslation } from "react-i18next";

interface ActionResponseProps {
    res: string | undefined;
    responseRef: React.RefObject<HTMLDivElement | null>;
    title: string;
}

export const ActionResponse: React.FC<ActionResponseProps> = ({ res, responseRef, title }) => {
    const { t } = useTranslation("common");
    if (!res) return null;
    const displayRes = /^[45]\d\d:/.test(res) ? `${t("errorPrefix")}${res}` : res;
    return (
        <div ref={responseRef} data-testid="response-output">
            <Card title={title}>{displayRes}</Card>
        </div>
    );
};
