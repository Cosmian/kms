import { CheckCircleFilled, DatabaseOutlined } from "@ant-design/icons";
import { Select } from "antd";
import React, { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { useBranding } from "../../contexts/useBranding";

export interface HsmSlotStatus {
    slot_id: number;
    accessible: boolean;
}

export interface HsmInstanceStatus {
    prefix: string;
    model: string;
    slots: HsmSlotStatus[];
}

export interface ServerInfo {
    version: string;
    fips_mode: boolean;
    hsm_instances: HsmInstanceStatus[];
    default_username: string;
}

type HeaderProps = {
    isDarkMode: boolean;
    serverInfo?: ServerInfo | null;
};

const Header: React.FC<HeaderProps> = ({ isDarkMode, serverInfo }) => {
    const branding = useBranding();
    const { t } = useTranslation("layout");
    const logoUrl = isDarkMode ? branding.logoDarkUrl : branding.logoLightUrl;

    const instances = serverInfo?.hsm_instances ?? [];
    const [selectedPrefix, setSelectedPrefix] = useState<string | undefined>(undefined);

    // Initialise selection once serverInfo arrives (it's null on first render).
    useEffect(() => {
        if (instances.length > 0 && selectedPrefix === undefined) {
            setSelectedPrefix(instances[0].prefix);
        }
    }, [instances, selectedPrefix]);

    // Compute label strings to derive a proper minWidth for the Select trigger.
    const hsmLabelTexts = instances.map((inst) => {
        const slotIds = inst.slots.map((s) => s.slot_id).join(", ");
        return `${inst.prefix}: ${inst.model}${slotIds ? ` (${t("header.hsmSlot")} ${slotIds})` : ""}`;
    });
    const longestLabel = hsmLabelTexts.reduce((max, s) => (s.length > max.length ? s : max), "");
    // Approx 8 px per character + 64 px for icon/padding/suffix.
    const hsmSelectWidth = longestLabel.length;

    const hsmOptions = instances.map((inst, idx) => ({
        value: inst.prefix,
        label: (
            <span className="flex items-center gap-1">
                <DatabaseOutlined />
                <span>{hsmLabelTexts[idx]}</span>
            </span>
        ),
    }));

    return (
        <div className="flex items-center h-full">
            {logoUrl && (
                <a href="https://docs.cosmian.com" target="_blank" rel="noreferrer">
                    <img src={logoUrl} alt={branding.logoAlt} className="h-16 mr-4 transition-opacity duration-300 hover:opacity-80" />
                </a>
            )}
            <h1 className="text-xl font-bold pl-10">{branding.logoAlt}</h1>
            {instances.length > 0 ? (
                <div className="ml-6 flex items-center gap-2">
                    <Select
                        value={selectedPrefix}
                        onChange={setSelectedPrefix}
                        options={hsmOptions}
                        style={{ minWidth: hsmSelectWidth }}
                        size="small"
                        variant="borderless"
                        suffixIcon={<CheckCircleFilled style={{ color: "#52c41a" }} />}
                        popupMatchSelectWidth={false}
                    />
                </div>
            ) : (
                serverInfo !== null &&
                serverInfo !== undefined && <span className="ml-6 text-gray-400 text-sm">{t("header.noHsmConfigured")}</span>
            )}
        </div>
    );
};

export default Header;
