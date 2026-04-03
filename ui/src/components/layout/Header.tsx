import { CheckCircleFilled } from "@ant-design/icons";
import { Tag } from "antd";
import React from "react";
import { useBranding } from "../../contexts/useBranding";

export interface HsmInfo {
    configured: boolean;
    model: string | null;
    slots: number[];
}

export interface ServerInfo {
    version: string;
    fips_mode: boolean;
    hsm: HsmInfo;
}

type HeaderProps = {
    isDarkMode: boolean;
    serverInfo?: ServerInfo | null;
};

const Header: React.FC<HeaderProps> = ({ isDarkMode, serverInfo }) => {
    const branding = useBranding();

    const logoUrl = isDarkMode ? branding.logoDarkUrl : branding.logoLightUrl;

    return (
        <div className="flex items-center h-full w-full">
            {logoUrl && <img src={logoUrl} alt={branding.logoAlt} className="h-7 mr-4 transition-opacity duration-300" />}
            <h1 className="text-xl font-bold pl-10">{branding.logoAlt}</h1>
            {serverInfo && (
                <div className="ml-6 flex items-center gap-2">
                    {serverInfo.hsm.configured ? (
                        <Tag icon={<CheckCircleFilled />} color="success" className="flex items-center gap-1">
                            HSM: {serverInfo.hsm.model ?? "configured"}
                            {serverInfo.hsm.slots.length > 0 &&
                                ` — slot${serverInfo.hsm.slots.length > 1 ? "s" : ""} ${serverInfo.hsm.slots.join(", ")}`}
                        </Tag>
                    ) : (
                        <span className="text-gray-400 text-sm">No HSM configured</span>
                    )}
                </div>
            )}
        </div>
    );
};

export default Header;
