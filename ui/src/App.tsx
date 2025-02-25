import { ConfigProvider, theme } from 'antd'
import { useEffect, useState } from "react"
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import AccessGrantForm from './AccessGrant'
import AccessListForm from './AccessList'
import AccessObtainedList from './AccessObtained'
import AccessRevokeForm from './AccessRevoke'
import CertificateCertifyForm from './CertificateCertify'
import CertificateDecryptForm from './CertificateDecrypt'
import CertificateEncryptForm from './CertificateEncrypt'
import CertificateExportForm from './CertificateExport'
import CertificateImportForm from './CertificateImport'
import CertificateValidateForm from './CertificateValidate'
import CCDecryptForm from './CovercryptDecrypt'
import CCEncryptForm from './CovercryptEncrypt'
import CovercryptMasterKeyForm from './CovercryptMasterKey'
import CovercryptUserKeyForm from './CovercryptUserKey'
import ECDecryptForm from './ECDecrypt'
import ECEncryptForm from './ECEncrypt'
import ECKeyCreateForm from './ECKeysCreate'
import KeyExportForm from './KeysExport'
import KeyImportForm from './KeysImport'
import LocateForm from './Locate'
import MainLayout from './MainLayout'
import DestroyForm from './ObjectsDestroy'
import ObjectsOwnedList from './ObjectsOwned'
import RevokeForm from './ObjectsRevoke'
import RsaDecryptForm from './RsaDecrypt'
import RsaEncryptForm from './RsaEncrypt'
import RsaKeyCreateForm from './RsaKeysCreate'
import SymKeyCreateForm from './SymKeysCreate'
import SymmetricDecryptForm from './SymmetricDecrypt'
import SymmetricEncryptForm from './SymmetricEncrypt'

import init from "./wasm/pkg"

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
        footerPadding: '5px 50px',
      },
      Card: {
        colorBgContainer: "#ffffff",
        borderRadiusLG: 8,
      },
      Form: {
        itemMarginBottom: 40,
      }
    },
  };

  const darkTheme = {
    token: {
      colorPrimary: "#9e6eff",
      colorText: "#e4dddd",
      colorBgBase: "#2a2d30",
      colorTextPlaceholder: "#b9b9b9",
      colorError: '#e23030',
    },
    components: {
      Layout: {
        headerBg: "#272d33",
        footerPadding: '5px 50px',
      },
      Menu: {
        itemSelectedBg: "#393E46",
        itemSelectedColor: '#9e6eff',
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
        primaryShadow: 'None',
        dangerShadow: 'None,'
      },
      Select: {
        selectorBg: '#2f3239',
        colorBorder: '#34383f',
        optionActiveBg: '#9e6eff',
        optionActiveColor: '#2a2d30',
        optionSelectedBg: '#9e6eff',
        optionSelectedColor: '#2a2d30',
        colorIcon: '#9e6eff',
      },
      Input: {
        selectorBg: '#2f3239',
        colorBorder: '#34383f',
      },
      InputNumber: {
        colorIcon: '#9e6eff',
        colorBorder: '#9e6eff',
      },
      Card: {
        colorBgContainer: "#393E46",
        borderRadiusLG: 8,
      },
    },
  };

  return (
    <ConfigProvider
      theme={{ ...theme.defaultConfig, ... (isDarkMode ? darkTheme : lightTheme) }}
    >
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Navigate to="/locate" replace />} />
          <Route path="/" element={<MainLayout isDarkMode={isDarkMode} setIsDarkMode={setIsDarkMode} />}>
            <Route path="locate" element={<LocateForm />} />
            <Route path="sym/keys/create" element={<SymKeyCreateForm />} />
            <Route path="sym/keys/export" element={<KeyExportForm key_type={'symmetric'} />} />
            <Route path="sym/keys/import" element={<KeyImportForm key_type='symmetric' />} />
            <Route path="sym/keys/revoke" element={<RevokeForm objectType='symmetric' />} />
            <Route path="sym/keys/destroy" element={<DestroyForm objectType='symmetric' />} />
            <Route path="sym/encrypt" element={<SymmetricEncryptForm />} />
            <Route path="sym/decrypt" element={<SymmetricDecryptForm />} />
            <Route path="rsa/keys/create" element={<RsaKeyCreateForm />} />
            <Route path="rsa/keys/export" element={<KeyExportForm key_type={'rsa'} />} />
            <Route path="rsa/keys/import" element={<KeyImportForm key_type='rsa' />} />
            <Route path="rsa/keys/revoke" element={<RevokeForm objectType='rsa' />} />
            <Route path="rsa/keys/destroy" element={<DestroyForm objectType='rsa' />} />
            <Route path="rsa/encrypt" element={<RsaEncryptForm />} />
            <Route path="rsa/decrypt" element={<RsaDecryptForm />} />
            <Route path="ec/keys/create" element={<ECKeyCreateForm />} />
            <Route path="ec/keys/export" element={<KeyExportForm key_type={'ec'} />} />
            <Route path="ec/keys/import" element={<KeyImportForm key_type='ec' />} />
            <Route path="ec/keys/revoke" element={<RevokeForm objectType='ec' />} />
            <Route path="ec/keys/destroy" element={<DestroyForm objectType='ec' />} />
            <Route path="ec/encrypt" element={<ECEncryptForm />} />
            <Route path="ec/decrypt" element={<ECDecryptForm />} />
            <Route path="cc/keys/create-master-key-pair" element={<CovercryptMasterKeyForm />} />
            <Route path="cc/keys/create-user-key" element={<CovercryptUserKeyForm />} />
            <Route path="cc/keys/export" element={<KeyExportForm key_type={'covercrypt'} />} />
            <Route path="cc/keys/import" element={<KeyImportForm key_type={'covercrypt'} />} />
            <Route path="cc/keys/revoke" element={<RevokeForm objectType='covercrypt' />} />
            <Route path="cc/keys/destroy" element={<DestroyForm objectType='covercrypt' />} />
            <Route path="cc/encrypt" element={<CCEncryptForm />} />
            <Route path="cc/decrypt" element={<CCDecryptForm />} />
            <Route path="access-rights/grant" element={<AccessGrantForm />} />
            <Route path="access-rights/revoke" element={<AccessRevokeForm />} />
            <Route path="access-rights/list" element={<AccessListForm />} />
            <Route path="access-rights/owned" element={<ObjectsOwnedList />} />
            <Route path="access-rights/obtained" element={<AccessObtainedList />} />
            <Route path="certificates/import" element={<CertificateImportForm />} />
            <Route path="certificates/export" element={<CertificateExportForm />} />
            <Route path="certificates/revoke" element={<RevokeForm objectType='certificate' />} />
            <Route path="certificates/destroy" element={<DestroyForm objectType='certificate' />} />
            <Route path="certificates/validate" element={<CertificateValidateForm />} />
            <Route path="certificates/encrypt" element={<CertificateEncryptForm />} />
            <Route path="certificates/decrypt" element={<CertificateDecryptForm />} />
            <Route path="certificates/certify" element={<CertificateCertifyForm />} />
          </Route>
        </Routes>
      </BrowserRouter>
      </ConfigProvider>
  )
}

export default App
