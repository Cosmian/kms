import { ConfigProvider, theme } from "antd";
import { useEffect, useState } from "react";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import AccessGrantForm from "./AccessGrant";
import AccessListForm from "./AccessList";
import AccessObtainedList from "./AccessObtained";
import AccessRevokeForm from "./AccessRevoke";
import AttributeDeleteForm from "./AttributeDelete";
import AttributeGetForm from "./AttributeGet";
import AttributeSetForm from "./AttributeSet";
import { AuthProvider, useAuth } from "./AuthContext";
import CertificateCertifyForm from "./CertificateCertify";
import CertificateDecryptForm from "./CertificateDecrypt";
import CertificateEncryptForm from "./CertificateEncrypt";
import CertificateExportForm from "./CertificateExport";
import CertificateImportForm from "./CertificateImport";
import CertificateValidateForm from "./CertificateValidate";
import CCDecryptForm from "./CovercryptDecrypt";
import CCEncryptForm from "./CovercryptEncrypt";
import CovercryptMasterKeyForm from "./CovercryptMasterKey";
import CovercryptUserKeyForm from "./CovercryptUserKey";
import ECDecryptForm from "./ECDecrypt";
import ECEncryptForm from "./ECEncrypt";
import ECKeyCreateForm from "./ECKeysCreate";
import KeyExportForm from "./KeysExport";
import KeyImportForm from "./KeysImport";
import LocateForm from "./Locate";
import LoginPage from "./LoginPage";
import MainLayout from "./MainLayout";
import NotFoundPage from "./NotFoundPage";
import DestroyForm from "./ObjectsDestroy";
import ObjectsOwnedList from "./ObjectsOwned";
import RevokeForm from "./ObjectsRevoke";
import RsaDecryptForm from "./RsaDecrypt";
import RsaEncryptForm from "./RsaEncrypt";
import RsaKeyCreateForm from "./RsaKeysCreate";
import SymKeyCreateForm from "./SymKeysCreate";
import SymmetricDecryptForm from "./SymmetricDecrypt";
import SymmetricEncryptForm from "./SymmetricEncrypt";
import { AuthMethod, fetchAuthMethod, fetchIdToken } from "./utils";
import init from "./wasm/pkg";

type AppContentProps = {
    isDarkMode: boolean;
    setIsDarkMode: (value: boolean) => void;
};

const AppContent: React.FC<AppContentProps> = ({ isDarkMode, setIsDarkMode }) => {
    const { setServerUrl, setIdToken } = useAuth();
    const [isAuthenticated, setIsAuthenticated] = useState(false);
    const [isAuthLoading, setIsAuthLoading] = useState(false);
    const [authMethod, setAuthMethod] = useState<AuthMethod>("None");

    useEffect(() => {
        const location = window.location.origin; // WHEN USING REAL URL/IP
        // const location = "https://0.0.0.0:9998"; // ONLY FOR DEV MODE
        setServerUrl(location);

        const fetchUser = async () => {
            const authMethod = await fetchAuthMethod(location);
            setAuthMethod(authMethod);
            if (authMethod == "JWT") {
                const token = await fetchIdToken(location);
                if (token) {
                    setIdToken(token);
                    setIsAuthenticated(true);
                }
            }
            setIsAuthLoading(false);
        };
        setIsAuthLoading(true);
        fetchUser();
    }, []);

    if (isAuthLoading) {
        return <></>;
    }
    return (
        <Routes>
            {!isAuthenticated && authMethod === "JWT" ? (
                <>
                    <Route path="/login" element={<LoginPage />} />
                    <Route path="*" element={<Navigate to="/login" replace />} />
                </>
            ) : (
                <>
                    <Route path="/" element={<MainLayout isDarkMode={isDarkMode} setIsDarkMode={setIsDarkMode} authMethod={authMethod} />}>
                        <Route index element={<Navigate to="/locate" replace />} />
                        <Route path="locate" element={<LocateForm />} />
                        <Route path="sym">
                            <Route path="keys/create" element={<SymKeyCreateForm />} />
                            <Route path="keys/export" element={<KeyExportForm key_type={"symmetric"} />} />
                            <Route path="keys/import" element={<KeyImportForm key_type="symmetric" />} />
                            <Route path="keys/revoke" element={<RevokeForm objectType="symmetric" />} />
                            <Route path="keys/destroy" element={<DestroyForm objectType="symmetric" />} />
                            <Route path="encrypt" element={<SymmetricEncryptForm />} />
                            <Route path="decrypt" element={<SymmetricDecryptForm />} />
                        </Route>
                        <Route path="rsa">
                            <Route path="keys/create" element={<RsaKeyCreateForm />} />
                            <Route path="keys/export" element={<KeyExportForm key_type={"rsa"} />} />
                            <Route path="keys/import" element={<KeyImportForm key_type="rsa" />} />
                            <Route path="keys/revoke" element={<RevokeForm objectType="rsa" />} />
                            <Route path="keys/destroy" element={<DestroyForm objectType="rsa" />} />
                            <Route path="encrypt" element={<RsaEncryptForm />} />
                            <Route path="decrypt" element={<RsaDecryptForm />} />
                        </Route>
                        <Route path="ec">
                            <Route path="keys/create" element={<ECKeyCreateForm />} />
                            <Route path="keys/export" element={<KeyExportForm key_type={"ec"} />} />
                            <Route path="keys/import" element={<KeyImportForm key_type="ec" />} />
                            <Route path="keys/revoke" element={<RevokeForm objectType="ec" />} />
                            <Route path="keys/destroy" element={<DestroyForm objectType="ec" />} />
                            <Route path="encrypt" element={<ECEncryptForm />} />
                            <Route path="decrypt" element={<ECDecryptForm />} />
                        </Route>
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
                            <Route path="delete" element={<AttributeDeleteForm />} />
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

    useEffect(() => {
        async function loadWasm() {
            await init();
        }

        loadWasm();
    }, []);

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
            <ConfigProvider theme={{ ...theme.defaultConfig, ...(isDarkMode ? darkTheme : lightTheme) }}>
                <AuthProvider>
                    <AppContent isDarkMode={isDarkMode} setIsDarkMode={setIsDarkMode} />
                </AuthProvider>
            </ConfigProvider>
        </BrowserRouter>
    );
}

export default App;
