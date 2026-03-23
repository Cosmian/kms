import { ConfigProvider, theme } from "antd";
import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import AccessGrantForm from "./views/Access/AccessGrant";
import AccessListForm from "./views/Access/AccessList";
import AccessObtainedList from "./views/Access/AccessObtained";
import AccessRevokeForm from "./views/Access/AccessRevoke";
import AttributeDeleteForm from "./views/Attributes/AttributeDelete";
import AttributeGetForm from "./views/Attributes/AttributeGet";
import AttributeModifyForm from "./views/Attributes/AttributeModify";
import AttributeSetForm from "./views/Attributes/AttributeSet";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import ExportAzureBYOKForm from "./views/CloudProviders/AzureExportByok";
import ImportAzureKekForm from "./views/CloudProviders/AzureImportKek";
import CertificateCertifyForm from "./views/Certificates/CertificateCertify";
import CertificateDecryptForm from "./views/Certificates/CertificateDecrypt";
import CertificateEncryptForm from "./views/Certificates/CertificateEncrypt";
import CertificateExportForm from "./views/Certificates/CertificateExport";
import CertificateImportForm from "./views/Certificates/CertificateImport";
import CertificateValidateForm from "./views/Certificates/CertificateValidate";
import CCDecryptForm from "./views/Covercrypt/CovercryptDecrypt";
import CCEncryptForm from "./views/Covercrypt/CovercryptEncrypt";
import CovercryptMasterKeyForm from "./views/Covercrypt/CovercryptMasterKey";
import CovercryptUserKeyForm from "./views/Covercrypt/CovercryptUserKey";
import CseInfo from "./views/Keys/CseInfo";
import ECDecryptForm from "./views/EC/ECDecrypt";
import ECEncryptForm from "./views/EC/ECEncrypt";
import ECKeyCreateForm from "./views/EC/ECKeysCreate";
import ECSignForm from "./views/EC/ECSign";
import ECVerifyForm from "./views/EC/ECVerify";
import KeyExportForm from "./views/Keys/KeysExport";
import KeyImportForm from "./views/Keys/KeysImport";
import MacComputeForm from "./views/MAC/MacCompute";
import MacVerifyForm from "./views/MAC/MacVerify";
import LocateForm from "./components/common/Locate";
import LoginPage from "./pages/LoginPage";
import MainLayout from "./components/layout/MainLayout";
import NotFoundPage from "./pages/NotFoundPage";
import DestroyForm from "./views/Objects/ObjectsDestroy";
import ObjectsOwnedList from "./views/Objects/ObjectsOwned";
import RevokeForm from "./views/Objects/ObjectsRevoke";
import OpaqueObjectForm from "./views/Objects/OpaqueObject";
import PqcDecapsulateForm from "./views/PQC/PqcDecapsulate";
import PqcEncapsulateForm from "./views/PQC/PqcEncapsulate";
import PqcKeysCreateForm from "./views/PQC/PqcKeysCreate";
import PqcSignForm from "./views/PQC/PqcSign";
import PqcVerifyForm from "./views/PQC/PqcVerify";
import RsaDecryptForm from "./views/RSA/RsaDecrypt";
import RsaEncryptForm from "./views/RSA/RsaEncrypt";
import RsaKeyCreateForm from "./views/RSA/RsaKeysCreate";
import RsaSignForm from "./views/RSA/RsaSign";
import RsaVerifyForm from "./views/RSA/RsaVerify";
import SecretDataCreateForm from "./views/Objects/SecretDataCreate";
import SymKeyCreateForm from "./views/Keys/SymKeysCreate";
import SymmetricDecryptForm from "./views/Symmetric/SymmetricDecrypt";
import SymmetricEncryptForm from "./views/Symmetric/SymmetricEncrypt";
import SymmetricHashForm from "./views/Symmetric/SymmetricHash";
import { useBranding } from "./contexts/useBranding";
import { AuthMethod, fetchAuthMethod, fetchIdToken, getNoTTLVRequest } from "./utils/utils";
import init, * as wasmModule from "./wasm/pkg";
import ImportAwsKekForm from "./views/CloudProviders/AwsImportKek";
import AwsExportKeyMaterialForm from "./views/CloudProviders/AwsExportKeyMaterial";

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
    const { setServerUrl, setIdToken, setUserId } = useAuth();
    const branding = useBranding();
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isAuthLoading, setIsAuthLoading] = useState(false);
    const [authMethod, setAuthMethod] = useState<AuthMethod>("None");
    const [loginError, setLoginError] = useState<undefined | string>(undefined);

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
    return (
        <Routes>
            {!isAuthenticated && authMethod === "JWT" ? (
                <>
                    <Route path="/login" element={<LoginPage auth={true} error={loginError} />} />
                    <Route path="*" element={<Navigate to="/login" replace />} />
                </>
            ) : (
                <>
                    <Route index element={<LoginPage auth={false} />} />
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
