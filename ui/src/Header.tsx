import React from "react";
import { useBranding } from "./BrandingContext";

type HeaderProps = {
    isDarkMode: boolean;
};

const Header: React.FC<HeaderProps> = ({ isDarkMode }) => {
    const branding = useBranding();

    const logoUrl = isDarkMode ? branding.logoDarkUrl : branding.logoLightUrl;

    return (
        <div className="flex items-center h-full w-full">
            {logoUrl && (
                <img
                    src={logoUrl}
                    alt={branding.logoAlt}
                    className="h-7 mr-4 transition-opacity duration-300"
                />
            )}
            <h1 className="text-xl font-bold pl-10">{branding.logoAlt}</h1>
        </div>
    );
};

export default Header;
