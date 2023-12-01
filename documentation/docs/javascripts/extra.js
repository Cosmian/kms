const app = () => {

    const handleDarkmode = (e) => {
        const darkModeOn = e.matches; // true if dark mode is enabled
        const favicon = document.querySelector('link[rel="icon"]'); // get favicon.ico element
        if (!favicon) {
            return; // where are our favicon elements???
        }
        // replace icons with dark/light themes as appropriate
        if (darkModeOn) {
            favicon.href = "/images/favicon-white.png";
            document.body.classList.add("dark-mode");
        } else {
            favicon.href = "/images/favicon-black.png";
            document.body.classList.remove("dark-mode");
        }
    };

    const darkModeMediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    handleDarkmode(darkModeMediaQuery);
};
app();
