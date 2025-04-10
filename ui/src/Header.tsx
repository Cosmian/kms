import React from "react";

type HeaderProps = {
    isDarkMode: boolean;
};

const Header: React.FC<HeaderProps> = ({ isDarkMode }) => (
    <div className="flex items-center h-full w-full">
        <img
            src={isDarkMode ? "/ui/Cosmian-Logo-Dark.svg" : "/ui/Cosmian-Logo.svg"}
            alt="Cosmian Logo"
            className="h-7 mr-4 transition-opacity duration-300"
        />
        <h1 className="text-xl font-bold pl-10">Key Management System</h1>
    </div>
);

export default Header;
