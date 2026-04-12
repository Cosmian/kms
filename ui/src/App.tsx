import { ConfigProvider, Result, theme } from "antd";
import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import AccessGrantForm from "./actions/Access/AccessGrant";
import AccessListForm from "./actions/Access/AccessList";
import AccessObtainedList from "./actions/Access/AccessObtained";
import AccessRevokeForm from "./actions/Access/AccessRevoke";
import AttributeDeleteForm from "./actions/Attributes/AttributeDelete";
import AttributeGetForm from "./actions/Attributes/AttributeGet";
import AttributeModifyForm from "./actions/Attributes/AttributeModify";
import AttributeSetForm from "./actions/Attributes/AttributeSet";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import ExportAzureBYOKForm from "./actions/CloudProviders/AzureExportByok";
import ImportAzureKekForm from "./actions/CloudProviders/AzureImportKek";
import CertificateCertifyForm from "./actions/Certificates/CertificateCertify";
import CertificateDecryptForm from "./actions/Certificates/CertificateDecrypt";
import CertificateEncryptForm from "./actions/Certificates/CertificateEncrypt";
import CertificateExportForm from "./actions/Certificates/CertificateExport";
import CertificateImportForm from "./actions/Certificates/CertificateImport";
import CertificateValidateForm from "./actions/Certificates/CertificateValidate";
import CCDecryptForm from "./actions/Covercrypt/CovercryptDecrypt";
import CCEncryptForm from "./actions/Covercrypt/CovercryptEncrypt";
import CovercryptMasterKeyForm from "./actions/Covercrypt/CovercryptMasterKey";
import CovercryptUserKeyForm from "./actions/Covercrypt/CovercryptUserKey";
import CseInfo from "./actions/Keys/CseInfo";
import ECDecryptForm from "./actions/EC/ECDecrypt";
import ECEncryptForm from "./actions/EC/ECEncrypt";
import ECKeyCreateForm from "./actions/EC/ECKeysCreate";
import ECSignForm from "./actions/EC/ECSign";
import ECVerifyForm from "./actions/EC/ECVerify";
import KeyExportForm from "./actions/Keys/KeysExport";
import KeyImportForm from "./actions/Keys/KeysImport";
import MacComputeForm from "./actions/MAC/MacCompute";
import MacVerifyForm from "./actions/MAC/MacVerify";
import LocateForm from "./components/common/Locate";
import LoginPage from "./pages/LoginPage";
import MainLayout from "./components/layout/MainLayout";
import NotFoundPage from "./pages/NotFoundPage";
import DestroyForm from "./actions/Objects/ObjectsDestroy";
import ObjectsOwnedList from "./actions/Objects/ObjectsOwned";
import RevokeForm from "./actions/Objects/ObjectsRevoke";
import OpaqueObjectForm from "./actions/Objects/OpaqueObject";
import PqcDecapsulateForm from "./actions/PQC/PqcDecapsulate";
import PqcEncapsulateForm from "./actions/PQC/PqcEncapsulate";
import PqcKeysCreateForm from "./actions/PQC/PqcKeysCreate";
import PqcSignForm from "./actions/PQC/PqcSign";
import PqcVerifyForm from "./actions/PQC/PqcVerify";
import RsaDecryptForm from "./actions/RSA/RsaDecrypt";
import RsaEncryptForm from "./actions/RSA/RsaEncrypt";
import RsaKeyCreateForm from "./actions/RSA/RsaKeysCreate";
import RsaSignForm from "./actions/RSA/RsaSign";
import RsaVerifyForm from "./actions/RSA/RsaVerify";
import SecretDataCreateForm from "./actions/Objects/SecretDataCreate";
import SymKeyCreateForm from "./actions/Keys/SymKeysCreate";
import SymmetricDecryptForm from "./actions/Symmetric/SymmetricDecrypt";
import SymmetricEncryptForm from "./actions/Symmetric/SymmetricEncrypt";
import SymmetricHashForm from "./actions/Symmetric/SymmetricHash";
import { useBranding } from "./contexts/useBranding";
import { AuthMethod, fetchAuthMethod, fetchIdToken, getNoTTLVRequest } from "./utils/utils";
import init, * as wasmModule from "./wasm/pkg";
import ImportAwsKekForm from "./actions/CloudProviders/AwsImportKek";
import AwsExportKeyMaterialForm from "./actions/CloudProviders/AwsExportKeyMaterial";
import DeriveKeyForm from "./actions/Keys/DeriveKey";

type AppContentProps = {
    isDarkMode: boolean;
    setIsDarkMode: (value: boolean) => void;
    wasmError: boolean;
};

const LS_DARKMODE_KEY = "darkMode";
const initialDarkMode = localStorage.getItem(LS_DARKMODE_KEY);

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

const isLoopbackHost = (host: string): boolean => LOOPBACK_HOSTS.has(host);

const resolveServerUrl = (): string => {
    const configuredUrl = (import.meta.env.VITE_KMS_URL as string | undefined)?.trim();
    const defaultDevUrl = `${window.location.protocol}//${window.location.hostname}:9998`;
    const fallbackUrl = import.meta.env.DEV ? defaultDevUrl : window.location.origin;
    const candidate = configuredUrl && configuredUrl.length > 0 ? configuredUrl : fallbackUrl;

    try {
        const target = new URL(candidate, window.location.origin);
        const current = new URL(window.location.origin);
        if (
            isLoopbackHost(target.hostname) &&
            isLoopbackHost(current.hostname) &&
            target.protocol === current.protocol &&
            target.port === current.port
        ) {
            return current.origin;
        }
        return target.origin;
    } catch {
        return fallbackUrl;
    }
};

const AppContent: React.FC<AppContentProps> = ({ isDarkMode, setIsDarkMode, wasmError }) => {
    const { serverUrl, setServerUrl, setIdToken, setUserId } = useAuth();
    const branding = useBranding();
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isAuthLoading, setIsAuthLoading] = useState(true);
    const [authMethod, setAuthMethod] = useState<AuthMethod>(undefined);
    const [loginError, setLoginError] = useState<string | undefined>(undefined);

    useEffect(() => {
        setIsDarkMode(initialDarkMode == "true" ? true : false);
    }, [setIsDarkMode]);

    useEffect(() => {
        localStorage.setItem(LS_DARKMODE_KEY, JSON.stringify(isDarkMode));
    }, [isDarkMode]);

    useEffect(() => {
        // Keep UI/backend on the same loopback origin when possible to avoid Firefox CORS noise.
        const location = resolveServerUrl();
        setServerUrl(location);

        // Query the server's vendor_identification via KMIP QueryServerInformation.
        // This ensures all subsequent WASM calls use the server-configured vendor
        // instead of the hardcoded default.
        const syncVendorId = async () => {
            try {
                const request = wasmModule.query_server_information_ttlv_request();
                const resp = await fetch(`${location}/kmip/2_1`, {
                    method: "POST",
                    credentials: "include",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(request),
                });
                if (resp.ok) {
                    const vendorId = wasmModule.parse_query_server_information_response(JSON.stringify(await resp.json())) as string;
                    wasmModule.set_vendor_id(vendorId);
                    console.info(`[KMS] vendor_id set to "${vendorId}"`);
                }
            } catch (e) {
                console.warn("[KMS] Could not query server vendor_id, using default:", e);
            }
        };
        void syncVendorId();

        const fetchUser = async () => {
            const authMethod = await fetchAuthMethod(location);
            setAuthMethod(authMethod);
            if (authMethod == "JWT") {
                const data = await fetchIdToken(location);
                if (data) {
                    try {
                        const version = await getNoTTLVRequest("/version", data.id_token, location);
                        if (version) {
                            setIdToken(data.id_token);
                            setUserId(data.user_id);
                            setIsAuthenticated(true);
                            setLoginError(undefined);
                        }
                    } catch (error) {
                        setLoginError(`An error occurred while fetching server information: ${String(error)}`);
                    }
                }
            } else if (authMethod === "CERT") {
                try {
                    // /version succeeds without a cert; /access/create returns 401 without one
                    await getNoTTLVRequest("/access/create", null, location);
                    setIsAuthenticated(true);
                } catch {
                    // Cert failed — try JWT as fallback (both may be configured)
                    const data = await fetchIdToken(location);
                    if (data) {
                        try {
                            const version = await getNoTTLVRequest("/version", data.id_token, location);
                            if (version) {
                                // Valid JWT session found — switch to JWT mode
                                setAuthMethod("JWT");
                                setIdToken(data.id_token);
                                setUserId(data.user_id);
                                setIsAuthenticated(true);
                                setLoginError(undefined);
                            }
                        } catch (error) {
                            console.log("JWT fallback failed:", error);
                            setIsAuthenticated(false);
                        }
                    } else {
                        // No cert, no JWT — block access
                        setIsAuthenticated(false);
                    }
                }
            }
            setIsAuthLoading(false);
        };
        setIsAuthLoading(true);
        fetchUser();
        // Intentionally run once on mount - dependencies stable
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    if (isAuthLoading) {
        return <></>;
    }
    // Error: couldn't reach server or determine auth method
    if (authMethod === undefined) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50">
                <Result
                    status="error"
                    title={
                        <div>
                            <div>Cannot connect to KMS server</div>
                        </div>
                    }
                    subTitle={
                        <span>
                            Could not reach Cosmian KMS server, please ensure it's running and is reachable at{" "}
                            <strong>{serverUrl || "the expected address"}</strong>.
                        </span>
                    }
                />
            </div>
        );
    }

    return (
        <Routes>
            {!isAuthenticated && (authMethod === "JWT" || authMethod === "CERT") ? (
                <>
                    <Route path="/login" element={<LoginPage auth={authMethod === "JWT"} authMethod={authMethod} error={loginError} />} />
                    <Route path="*" element={<Navigate to="/login" replace />} />
                </>
            ) : (
                <>
                    <Route index element={<Navigate to="/locate" replace />} />
                    <Route path="/login" element={<Navigate to="/locate" replace />} />
                    <Route
                        path="/"
                        element={
                            <MainLayout
                                isDarkMode={isDarkMode}
                                setIsDarkMode={setIsDarkMode}
                                authMethod={authMethod}
                                wasmError={wasmError}
                            />
                        }
                    >
                        <Route path="locate" element={<LocateForm />} />
                        <Route path="sym">
                            <Route path="keys/create" element={<SymKeyCreateForm />} />
                            <Route path="keys/export" element={<KeyExportForm key_type={"symmetric"} />} />
                            <Route path="keys/import" element={<KeyImportForm key_type="symmetric" />} />
                            <Route path="keys/revoke" element={<RevokeForm objectType="symmetric" />} />
                            <Route path="keys/destroy" element={<DestroyForm objectType="symmetric" />} />
                            <Route path="encrypt" element={<SymmetricEncryptForm />} />
                            <Route path="decrypt" element={<SymmetricDecryptForm />} />
                            <Route path="hash" element={<SymmetricHashForm />} />
                        </Route>
                        <Route path="rsa">
                            <Route path="keys/create" element={<RsaKeyCreateForm />} />
                            <Route path="keys/export" element={<KeyExportForm key_type={"rsa"} />} />
                            <Route path="keys/import" element={<KeyImportForm key_type="rsa" />} />
                            <Route path="keys/revoke" element={<RevokeForm objectType="rsa" />} />
                            <Route path="keys/destroy" element={<DestroyForm objectType="rsa" />} />
                            <Route path="encrypt" element={<RsaEncryptForm />} />
                            <Route path="decrypt" element={<RsaDecryptForm />} />
                            <Route path="sign" element={<RsaSignForm />} />
                            <Route path="verify" element={<RsaVerifyForm />} />
                        </Route>
                        <Route path="ec">
                            <Route path="keys/create" element={<ECKeyCreateForm />} />
                            <Route path="keys/export" element={<KeyExportForm key_type={"ec"} />} />
                            <Route path="keys/import" element={<KeyImportForm key_type="ec" />} />
                            <Route path="keys/revoke" element={<RevokeForm objectType="ec" />} />
                            <Route path="keys/destroy" element={<DestroyForm objectType="ec" />} />
                            <Route path="encrypt" element={<ECEncryptForm />} />
                            <Route path="decrypt" element={<ECDecryptForm />} />
                            <Route path="sign" element={<ECSignForm />} />
                            <Route path="verify" element={<ECVerifyForm />} />
                        </Route>
                        <Route path="pqc">
                            <Route path="keys/create" element={<PqcKeysCreateForm />} />
                            <Route path="keys/export" element={<KeyExportForm key_type={"pqc"} />} />
                            <Route path="keys/import" element={<KeyImportForm key_type="pqc" />} />
                            <Route path="keys/revoke" element={<RevokeForm objectType="pqc" />} />
                            <Route path="keys/destroy" element={<DestroyForm objectType="pqc" />} />
                            <Route path="encapsulate" element={<PqcEncapsulateForm />} />
                            <Route path="decapsulate" element={<PqcDecapsulateForm />} />
                            <Route path="sign" element={<PqcSignForm />} />
                            <Route path="verify" element={<PqcVerifyForm />} />
                        </Route>
                        <Route path="mac">
                            <Route path="compute" element={<MacComputeForm />} />
                            <Route path="verify" element={<MacVerifyForm />} />
                        </Route>
                        {branding.enableCovercrypt !== false && (
                            <Route path="cc">
                                <Route path="keys/create-master-key-pair" element={<CovercryptMasterKeyForm />} />
                                <Route path="keys/create-user-key" element={<CovercryptUserKeyForm />} />
                                <Route path="keys/export" element={<KeyExportForm key_type={"covercrypt"} />} />
                                <Route path="keys/import" element={<KeyImportForm key_type={"covercrypt"} />} />
                                <Route path="keys/revoke" element={<RevokeForm objectType="covercrypt" />} />
                                <Route path="keys/destroy" element={<DestroyForm objectType="covercrypt" />} />
                                <Route path="encrypt" element={<CCEncryptForm />} />
                                <Route path="decrypt" element={<CCDecryptForm />} />
                            </Route>
                        )}
                        <Route path="secret-data">
                            <Route path="create" element={<SecretDataCreateForm />} />
                            <Route path="export" element={<KeyExportForm key_type={"secret-data"} />} />
                            <Route path="import" element={<KeyImportForm key_type={"secret-data"} />} />
                            <Route path="revoke" element={<RevokeForm objectType="secret-data" />} />
                            <Route path="destroy" element={<DestroyForm objectType="secret-data" />} />
                        </Route>
                        <Route path="opaque-object">
                            <Route path="create" element={<OpaqueObjectForm />} />
                            <Route path="export" element={<KeyExportForm key_type={"opaque-object"} />} />
                            <Route path="import" element={<KeyImportForm key_type={"opaque-object"} />} />
                            <Route path="revoke" element={<RevokeForm objectType="opaque-object" />} />
                            <Route path="destroy" element={<DestroyForm objectType="opaque-object" />} />
                        </Route>
                        <Route path="derive-key" element={<DeriveKeyForm />} />
                        <Route path="access-rights">
                            <Route path="grant" element={<AccessGrantForm />} />
                            <Route path="revoke" element={<AccessRevokeForm />} />
                            <Route path="list" element={<AccessListForm />} />
                            <Route path="owned" element={<ObjectsOwnedList />} />
                            <Route path="obtained" element={<AccessObtainedList />} />
                        </Route>
                        <Route path="certificates">
                            <Route path="certs/import" element={<CertificateImportForm />} />
                            <Route path="certs/export" element={<CertificateExportForm />} />
                            <Route path="certs/revoke" element={<RevokeForm objectType="certificate" />} />
                            <Route path="certs/destroy" element={<DestroyForm objectType="certificate" />} />
                            <Route path="certs/validate" element={<CertificateValidateForm />} />
                            <Route path="encrypt" element={<CertificateEncryptForm />} />
                            <Route path="decrypt" element={<CertificateDecryptForm />} />
                            <Route path="certs/certify" element={<CertificateCertifyForm />} />
                        </Route>
                        <Route path="attributes">
                            <Route path="get" element={<AttributeGetForm />} />
                            <Route path="set" element={<AttributeSetForm />} />
                            <Route path="modify" element={<AttributeModifyForm />} />
                            <Route path="delete" element={<AttributeDeleteForm />} />
                        </Route>
                        <Route path="azure">
                            <Route path="import-kek" element={<ImportAzureKekForm />} />
                            <Route path="export-byok" element={<ExportAzureBYOKForm />} />
                        </Route>
                        <Route path="aws">
                            <Route path="import-kek" element={<ImportAwsKekForm />} />
                            <Route path="export-key-material" element={<AwsExportKeyMaterialForm />} />
                        </Route>
                        <Route path="google-cse" element={<CseInfo />} />
                    </Route>
                    <Route path="*" element={<NotFoundPage />} />
                </>
            )}
        </Routes>
    );
};

function App() {
    const [isDarkMode, setIsDarkMode] = useState(false);
    const [isWasmReady, setIsWasmReady] = useState(false);
    const [wasmError, setWasmError] = useState(false);
    const branding = useBranding();

    useEffect(() => {
        async function loadWasm() {
            try {
                await init();
            } catch (e) {
                // Avoid unhandled promise rejections; UI may still render but
                // any WASM-backed actions will fail and surface their own errors.
                console.error("WASM init failed:", e);
                setWasmError(true);
            } finally {
                setIsWasmReady(true);
            }
        }

        loadWasm();
    }, []);

    if (!isWasmReady) {
        return null;
    }

    const lightTheme = {
        token: {
            colorPrimary: "#e34319",
            colorText: "#292f52",
        },
        components: {
            Layout: {
                headerBg: "#ffffff",
                footerPadding: "5px 50px",
            },
            Card: {
                colorBgContainer: "#ffffff",
                borderRadiusLG: 8,
            },
            Form: {
                itemMarginBottom: 40,
            },
            Switch: {
                trackHeight: 32,
                handleSize: 28,
            },
            Button: {
                defaultHoverBorderColor: "#6e31e8",
                defaultHoverColor: "#6e31e8",
            },
        },
    };

    const darkTheme = {
        token: {
            colorPrimary: "#9e6eff",
            colorText: "#e4dddd",
            colorBgBase: "#2a2d30",
            colorTextPlaceholder: "#b9b9b9",
            colorError: "#e23030",
            colorBorder: "#4d4b4b",
            colorSplit: "#4d4b4b",
            colorBorderSecondary: "#4d4b4b",
        },
        components: {
            Layout: {
                headerBg: "#272d33",
                footerPadding: "5px 50px",
            },
            Menu: {
                itemSelectedBg: "#393E46",
                itemSelectedColor: "#9e6eff",
                itemHoverBg: "#2e3238",
                itemActiveBg: "#393E46",
                itemActiveColor: "#9e6eff",
            },
            Form: {
                colorError: "#FD7014",
                colorTextDescription: "#b9b9b9",
                itemMarginBottom: 40,
            },
            Button: {
                primaryShadow: "None",
                dangerShadow: "None,",
                defaultBorderColor: "#e4dddd",
            },
            Select: {
                selectorBg: "#2f3239",
                colorBorder: "#34383f",
                optionActiveBg: "#9e6eff",
                optionActiveColor: "#2a2d30",
                optionSelectedBg: "#9e6eff",
                optionSelectedColor: "#2a2d30",
                colorIcon: "#9e6eff",
            },
            Input: {
                selectorBg: "#2f3239",
                colorBorder: "#34383f",
            },
            InputNumber: {
                colorIcon: "#9e6eff",
                colorBorder: "#9e6eff",
            },
            Card: {
                colorBgContainer: "#393E46",
                borderRadiusLG: 8,
            },
            Switch: {
                trackHeight: 32,
                handleSize: 28,
            },
        },
    };

    return (
        <BrowserRouter basename="/ui">
            <ConfigProvider
                theme={{
                    ...theme.defaultConfig,
                    ...(isDarkMode ? darkTheme : lightTheme),
                    token: {
                        ...((isDarkMode ? darkTheme : lightTheme).token ?? {}),
                        ...(isDarkMode ? branding.tokens?.dark : branding.tokens?.light),
                    },
                }}
            >
                <AuthProvider>
                    <AppContent isDarkMode={isDarkMode} setIsDarkMode={setIsDarkMode} wasmError={wasmError} />
                </AuthProvider>
            </ConfigProvider>
        </BrowserRouter>
    );
}

export default App;
