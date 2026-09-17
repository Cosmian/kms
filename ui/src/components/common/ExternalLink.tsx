import React from "react";

interface ExternalLinkProps {
    href: string;
    children: React.ReactNode;
    className?: string;
}

const ExternalLink: React.FC<ExternalLinkProps> = ({ href, children, className = "text-blue-600 dark:text-blue-400 hover:underline" }) => {
    return (
        <a href={href} target="_blank" rel="noopener noreferrer" className={className}>
            {children}
        </a>
    );
};

export default ExternalLink;
