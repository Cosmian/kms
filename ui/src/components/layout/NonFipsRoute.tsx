import React from "react";
import { Navigate, Outlet, useOutletContext } from "react-router-dom";

/** Context provided by `MainLayout` to its child routes. */
export type LayoutOutletContext = {
    /** True when the server runs in FIPS mode, or when that is not (yet) known: fail closed. */
    isFips: boolean;
};

/**
 * Layout route that only renders its children on a non-FIPS server.
 * Direct navigation (typed URL, bookmark) to a feature that is hidden from the
 * FIPS menu is redirected to the landing page instead of rendering the form.
 */
const NonFipsRoute: React.FC = () => {
    const { isFips } = useOutletContext<LayoutOutletContext>();
    return isFips ? <Navigate to="/locate" replace /> : <Outlet />;
};

export default NonFipsRoute;
