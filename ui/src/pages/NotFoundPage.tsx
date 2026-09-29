import { useTranslation } from "react-i18next";
import { Link } from "react-router-dom";

const NotFoundPage = () => {
    const { t } = useTranslation("layout");
    return (
        <div style={{ textAlign: "center", marginTop: "50px" }}>
            <h1>{t("notFound.title")}</h1>
            <p>{t("notFound.message")}</p>
            <Link to="/">{t("notFound.goHome")}</Link>
        </div>
    );
};

export default NotFoundPage;
