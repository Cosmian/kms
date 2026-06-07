import { ConfigProvider, Result, theme } from "antd";
import type { ThemeConfig } from "antd";
import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import AccessGrantForm from "./actions/Access/AccessGrant";
import AccessListForm from "./actions/Access/AccessList";
import AccessObtainedList from "./actions/Access/AccessObtained";
import AccessRevokeForm from "./actions/Access/AccessRevoke";
import CryptoOfficerRole from "./actions/Access/CryptoOfficerRole";
import AttributeDeleteForm from "./actions/Attributes/AttributeDelete";
import AttributeGetForm from "./actions/Attributes/AttributeGet";
import AttributeModifyForm from "./actions/Attributes/AttributeModify";
import AttributeSetForm from "./actions/Attributes/AttributeSet";
import CertificateCertifyForm from "./actions/Certificates/CertificateCertify";
import CertificateDecryptForm from "./actions/Certificates/CertificateDecrypt";
import CertificateEncryptForm from "./actions/Certificates/CertificateEncrypt";
import CertificateExportForm from "./actions/Certificates/CertificateExport";
import CertificateGenerateCrlForm from "./actions/Certificates/CertificateGenerateCrl";
import CertificateImportForm from "./actions/Certificates/CertificateImport";
import CertificateReCertifyForm from "./actions/Certificates/CertificateReCertify";
import CertificateValidateForm from "./actions/Certificates/CertificateValidate";
import AwsExportKeyMaterialForm from "./actions/CloudProviders/AwsExportKeyMaterial";
import ImportAwsKekForm from "./actions/CloudProviders/AwsImportKek";
import ExportAzureBYOKForm from "./actions/CloudProviders/AzureExportByok";
import ImportAzureKekForm from "./actions/CloudProviders/AzureImportKek";
import CCDecryptForm from "./actions/Covercrypt/CovercryptDecrypt";
import CCEncryptForm from "./actions/Covercrypt/CovercryptEncrypt";
import CovercryptMasterKeyForm from "./actions/Covercrypt/CovercryptMasterKey";
import CovercryptUserKeyForm from "./actions/Covercrypt/CovercryptUserKey";
import ECDecryptForm from "./actions/EC/ECDecrypt";
import ECEncryptForm from "./actions/EC/ECEncrypt";
import ECKeyCreateForm from "./actions/EC/ECKeysCreate";
import ECSignForm from "./actions/EC/ECSign";
import ECVerifyForm from "./actions/EC/ECVerify";
import FpeDecryptForm from "./actions/FPE/FpeDecrypt";
import FpeEncryptForm from "./actions/FPE/FpeEncrypt";
import FpeKeyCreateForm from "./actions/FPE/FpeKeysCreate";
import CseInfo from "./actions/Keys/CseInfo";
import DeriveKeyForm from "./actions/Keys/DeriveKey";
import KeyExportForm from "./actions/Keys/KeysExport";
import KeyImportForm from "./actions/Keys/KeysImport";
import JoinSplitKeyForm from "./actions/Keys/JoinSplitKey";
import SplitKeyForm from "./actions/Keys/SplitKey";
import SymKeyCreateForm from "./actions/Keys/SymKeysCreate";
import MacComputeForm from "./actions/MAC/MacCompute";
import MacVerifyForm from "./actions/MAC/MacVerify";
import HsmStatus from "./actions/Objects/HsmStatus";
import DestroyForm from "./actions/Objects/ObjectsDestroy";
import ObjectsReKeyForm from "./actions/Objects/ObjectsReKey";
import ObjectsOwnedList from "./actions/Objects/ObjectsOwned";
import RevokeForm from "./actions/Objects/ObjectsRevoke";
import OpaqueObjectForm from "./actions/Objects/OpaqueObject";
import SecretDataCreateForm from "./actions/Objects/SecretDataCreate";
import PqcDecapsulateForm from "./actions/PQC/PqcDecapsulate";
import PqcEncapsulateForm from "./actions/PQC/PqcEncapsulate";
import PqcKeysCreateForm from "./actions/PQC/PqcKeysCreate";
import PqcSignForm from "./actions/PQC/PqcSign";
import PqcVerifyForm from "./actions/PQC/PqcVerify";
import GetRotationPolicyForm from "./actions/RotationPolicy/GetRotationPolicy";
import SetRotationPolicyForm from "./actions/RotationPolicy/SetRotationPolicy";
import RsaDecryptForm from "./actions/RSA/RsaDecrypt";
import RsaEncryptForm from "./actions/RSA/RsaEncrypt";
import RsaKeyCreateForm from "./actions/RSA/RsaKeysCreate";
import RsaSignForm from "./actions/RSA/RsaSign";
import RsaVerifyForm from "./actions/RSA/RsaVerify";
import SymmetricDecryptForm from "./actions/Symmetric/SymmetricDecrypt";
import SymmetricEncryptForm from "./actions/Symmetric/SymmetricEncrypt";
import SymmetricHashForm from "./actions/Symmetric/SymmetricHash";
import TokenizeAggregateDate from "./actions/Tokenize/TokenizeAggregateDate";
import TokenizeAggregateNumber from "./actions/Tokenize/TokenizeAggregateNumber";
import TokenizeHash from "./actions/Tokenize/TokenizeHash";
import TokenizeNoise from "./actions/Tokenize/TokenizeNoise";
import TokenizeScaleNumber from "./actions/Tokenize/TokenizeScaleNumber";
import TokenizeWordMask from "./actions/Tokenize/TokenizeWordMask";
import TokenizeWordPatternMask from "./actions/Tokenize/TokenizeWordPatternMask";
import TokenizeWordTokenize from "./actions/Tokenize/TokenizeWordTokenize";
import LocateForm from "./components/common/Locate";
import MainLayout from "./components/layout/MainLayout";
import { AuthProvider, useAuth } from "./contexts/AuthContext";
import { useBranding } from "./contexts/useBranding";
import { useAppLocale } from "./i18n/useAppLocale";
import LoginPage from "./pages/LoginPage";
import NotFoundPage from "./pages/NotFoundPage";
import { AuthMethod, fetchAuthMethods, fetchWhoAmI, getNoTTLVRequest, shouldAutoLoginWithCert } from "./utils/utils";
import init, * as wasmModule from "./wasm/pkg";

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
    const { serverUrl, setServerUrl, setUserId } = useAuth();
    const branding = useBranding();
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isAuthLoading, setIsAuthLoading] = useState(true);
    const [authMethod, setAuthMethod] = useState<AuthMethod>(undefined);
    const [configuredMethods, setConfiguredMethods] = useState<AuthMethod[]>([]);
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
            const methods = await fetchAuthMethods(location);
            // `undefined` means the server was unreachable or the response could not
            // be parsed: leave `authMethod` undefined so the error UI is shown.
            if (methods === undefined) {
                setIsAuthLoading(false);
                return;
            }
            setConfiguredMethods(methods);

            // No authentication configured: render the app directly (MainLayout shows
            // the "authentication disabled" banner).
            if (methods.length === 0) {
                setAuthMethod("None");
                setIsAuthLoading(false);
                return;
            }

            const primary = methods[0];

            // Resolve the active method for an already-authenticated returning user.
            // Session first: a plain cookie check that never triggers a client
            // certificate prompt. Only if there is no session do we probe the cert.
            const sessionMethod: AuthMethod = methods.includes("JWT")
                ? "JWT"
                : methods.includes("AUTH_VERIFIER")
                  ? "AUTH_VERIFIER"
                  : undefined;

            if (sessionMethod) {
                const data = await fetchWhoAmI(location);
                if (data) {
                    try {
                        const version = await getNoTTLVRequest("/version", location);
                        if (version) {
                            setUserId(data.user_id);
                            setAuthMethod(sessionMethod);
                            setIsAuthenticated(true);
                            setLoginError(undefined);
                            setIsAuthLoading(false);
                            return;
                        }
                    } catch (error) {
                        setLoginError(`An error occurred while fetching server information: ${String(error)}`);
                    }
                }
            }

            // Auto-probe only when CERT is the sole method; with multiple methods the
            // user must choose explicitly so the cert cannot preempt OIDC or auth-verifier.
            if (shouldAutoLoginWithCert(methods)) {
                try {
                    // /version succeeds without a cert; /access/create returns 401 without one
                    await getNoTTLVRequest("/access/create", location);
                    setAuthMethod("CERT");
                    setIsAuthenticated(true);
                    setIsAuthLoading(false);
                    return;
                } catch {
                    // No valid cert — fall through to the login page.
                }
            }

            // Not authenticated: show the login page with the configured methods.
            setAuthMethod(primary);
            setIsAuthenticated(false);
            setIsAuthLoading(false);
        };
        setIsAuthLoading(true);
        fetchUser();
        // Intentionally run once on mount - dependencies stable
        // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    const handleCertLogout =
        authMethod === "CERT" && configuredMethods.length > 1
            ? () => {
                  setAuthMethod(configuredMethods[0]);
                  setIsAuthenticated(false);
              }
            : undefined;

    if (isAuthLoading) {
        return <></>;
    }
    // Error: couldn't reach server or determine auth method
    if (authMethod === undefined) {
        return (
            <div className="min-h-screen flex items-center justify-center bg-gray-50 dark:bg-gray-800">
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
            {!isAuthenticated && configuredMethods.length > 0 ? (
                <>
                    <Route
                        path="/login"
                        element={
                            <LoginPage
                                auth={configuredMethods[0] === "JWT"}
                                authMethods={configuredMethods}
                                error={loginError}
                                onCertAuthenticated={() => {
                                    setAuthMethod("CERT");
                                    setIsAuthenticated(true);
                                }}
                            />
                        }
                    />
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
                                onCertLogout={handleCertLogout}
                            />
                        }
                    >
                        <Route path="locate" element={<LocateForm />} />
                        <Route path="sym">
                            <Route path="keys/create" element={<SymKeyCreateForm />} />
                            <Route path="keys/split" element={<SplitKeyForm />} />
                            <Route path="keys/join" element={<JoinSplitKeyForm />} />
                            <Route path="keys/export" element={<KeyExportForm key_type={"symmetric"} />} />
                            <Route path="keys/import" element={<KeyImportForm key_type="symmetric" />} />
                            <Route path="keys/rekey" element={<ObjectsReKeyForm keyType="symmetric" />} />
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
                            <Route path="keys/rekey" element={<ObjectsReKeyForm keyType="rsa" />} />
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
                            <Route path="keys/rekey" element={<ObjectsReKeyForm keyType="ec" />} />
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
                            <Route path="keys/rekey" element={<ObjectsReKeyForm keyType="pqc" />} />
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
                        <Route path="rotation-policy">
                            <Route path="sym">
                                <Route path="set" element={<SetRotationPolicyForm />} />
                                <Route path="get" element={<GetRotationPolicyForm />} />
                            </Route>
                            <Route path="rsa">
                                <Route path="set" element={<SetRotationPolicyForm />} />
                                <Route path="get" element={<GetRotationPolicyForm />} />
                            </Route>
                            <Route path="ec">
                                <Route path="set" element={<SetRotationPolicyForm />} />
                                <Route path="get" element={<GetRotationPolicyForm />} />
                            </Route>
                            <Route path="pqc">
                                <Route path="set" element={<SetRotationPolicyForm />} />
                                <Route path="get" element={<GetRotationPolicyForm />} />
                            </Route>
                        </Route>
                        <Route path="fpe">
                            <Route path="keys/create" element={<FpeKeyCreateForm />} />
                            <Route path="keys/export" element={<KeyExportForm key_type={"fpe"} />} />
                            <Route path="keys/import" element={<KeyImportForm key_type="fpe" />} />
                            <Route path="keys/revoke" element={<RevokeForm objectType="fpe" />} />
                            <Route path="keys/destroy" element={<DestroyForm objectType="fpe" />} />
                            <Route path="encrypt" element={<FpeEncryptForm />} />
                            <Route path="decrypt" element={<FpeDecryptForm />} />
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
                            <Route path="crypto-officer" element={<CryptoOfficerRole />} />
                        </Route>
                        <Route path="hsm-status" element={<HsmStatus />} />
                        <Route path="certificates">
                            <Route path="certs/import" element={<CertificateImportForm />} />
                            <Route path="certs/export" element={<CertificateExportForm />} />
                            <Route path="certs/revoke" element={<RevokeForm objectType="certificate" />} />
                            <Route path="certs/destroy" element={<DestroyForm objectType="certificate" />} />
                            <Route path="certs/validate" element={<CertificateValidateForm />} />
                            <Route path="certs/generate-crl" element={<CertificateGenerateCrlForm />} />
                            <Route path="encrypt" element={<CertificateEncryptForm />} />
                            <Route path="decrypt" element={<CertificateDecryptForm />} />
                            <Route path="certs/certify" element={<CertificateCertifyForm />} />
                            <Route path="certs/recertify" element={<CertificateReCertifyForm />} />
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
                        <Route path="tokenize">
                            <Route path="hash" element={<TokenizeHash />} />
                            <Route path="noise" element={<TokenizeNoise />} />
                            <Route path="word-mask" element={<TokenizeWordMask />} />
                            <Route path="word-tokenize" element={<TokenizeWordTokenize />} />
                            <Route path="word-pattern-mask" element={<TokenizeWordPatternMask />} />
                            <Route path="aggregate-number" element={<TokenizeAggregateNumber />} />
                            <Route path="aggregate-date" element={<TokenizeAggregateDate />} />
                            <Route path="scale-number" element={<TokenizeScaleNumber />} />
                        </Route>
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
    const { antdLocale } = useAppLocale();

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

    // Keep the <html> element's `.dark` class (drives Tailwind `dark:` variants)
    // and the CSS `color-scheme` in sync with the app's theme switch, so dark mode
    // is consistent across AntD components and raw utility classes.
    useEffect(() => {
        document.documentElement.classList.toggle("dark", isDarkMode);
    }, [isDarkMode]);

    if (!isWasmReady) {
        return null;
    }

    const lightTheme: ThemeConfig = {
        algorithm: theme.defaultAlgorithm,
        token: {
            colorPrimary: "#c73f1b" /* Cosmian brand orange — eviden.css --cosmian-accent-dark (>= 4.5:1 on white) */,
            colorText: "#1a1a1a" /* Eviden brand ink — matches eviden.css --cosmian-dark */,
            fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        },
        components: {
            Layout: {
                headerBg: "#ffffff",
                footerPadding: "5px 50px",
                /* Sider collapse trigger: light gray bg + accessible dark icon (≥4.5:1) */
                triggerBg: "#e8eaed",
                triggerColor: "#595959",
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
                defaultHoverBorderColor: "#50767a" /* darkened teal (>= 4.5:1 on white) */,
                defaultHoverColor: "#50767a",
            },
        },
    };

    const darkTheme: ThemeConfig = {
        algorithm: theme.darkAlgorithm,
        token: {
            colorPrimary: "#f14611" /* Cosmian primary orange — eviden.css --cosmian-accent (bright accent on dark) */,
            colorInfo: "#4fa8d8" /* mdBook dark-theme link blue — ≥ 4.5:1 on #161923 (WCAG AA) */,
            colorTextBase: "#bcbdd0" /* mdBook navy --fg */,
            colorTextSecondary: "#9fa0b8" /* explicit — prevents algorithm deriving ~#666979 (only 2.84:1 on card bg) */,
            colorBgBase: "#161923" /* mdBook navy --bg hsl(226,23%,11%) — black background */,
            colorBgLayout: "#161923",
            colorBgContainer: "#1f2432" /* elevated card surface */,
            colorBgElevated: "#282d3f" /* mdBook navy --sidebar-bg */,
            colorBorder: "#5a6278",
            colorSplit: "#3a4155",
            colorError: "#ff6b6b" /* light red (>= 4.5:1 on #161923) */,
            fontFamily: "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif",
        },
        components: {
            Layout: {
                headerBg: "#161923",
                footerPadding: "5px 50px",
                /* Sider collapse trigger: matches sidebar surface with readable icon (≥4.5:1 on #282d3f) */
                triggerBg: "#282d3f",
                triggerColor: "#c8c9db",
            },
            Menu: {
                darkItemBg: "#282d3f" /* mdBook navy --sidebar-bg */,
                darkItemColor: "#c8c9db" /* mdBook navy --sidebar-fg */,
                darkItemHoverBg: "#2d334f",
                darkItemHoverColor: "#f14611",
                darkItemSelectedBg: "#3a4155",
                darkItemSelectedColor: "#f97850" /* lighter orange for contrast on selected bg */,
                darkSubMenuItemBg: "#1f2432",
            },
            Form: {
                itemMarginBottom: 40,
            },
            Button: {
                primaryShadow: "none",
                dangerShadow: "none",
            },
            Select: {
                optionSelectedBg: "#f14611",
                optionSelectedColor: "#161923" /* dark ink on bright orange (>= 4.5:1) */,
                colorIcon: "#f14611",
            },
            Card: {
                colorBgContainer: "#1f2432",
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
                locale={antdLocale}
                theme={{
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
