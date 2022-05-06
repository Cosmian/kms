const app = () => {
  var darkModeMediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
  const handleDarkmode = (e) => {
    var darkModeOn = e.matches; // true if dark mode is enabled
    console.log(darkModeOn);
    var favicon = document.querySelector('link[rel="icon"]'); // get favicon.ico element
    if (!favicon) {
      return; // where are our favicon elements???
    }
    // replace icons with dark/light themes as appropriate
    if (darkModeOn) {
      favicon.href = "/images/favicon-white.png";
    } else {
      favicon.href = "/images/favicon-black.png";
    }
  };
  handleDarkmode(darkModeMediaQuery);
};
app();
