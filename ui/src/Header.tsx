import React from 'react';

const Header: React.FC = () => (
    <div className="flex items-center shadow-md h-full px-4">
        <img src="/Cosmian-Logo.svg" alt="Cosmian Logo" className="h-8 mr-4" />
        <h1 style={{ color: '#9CA3AF' }} className="text-xl font-bold">KMS</h1>
    </div>
);

export default Header;