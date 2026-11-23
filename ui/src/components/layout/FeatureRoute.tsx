import { Navigate, Outlet, useOutletContext } from "react-router-dom";
import type { UiFeature } from "../../utils/uiConfig";
import type { LayoutOutletContext } from "./NonFipsRoute";

export default function FeatureRoute({ feature }: { feature: UiFeature }) {
    const { features } = useOutletContext<LayoutOutletContext>();
    return features?.[feature] === false ? <Navigate to="/locate" replace /> : <Outlet />;
}
