import { ConfigProvider } from 'antd'
import { useEffect } from "react"
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import AccessGrantForm from './AccessGrant'
import AccessListForm from './AccessList'
import AccessObtainedList from './AccessObtained'
import AccessRevokeForm from './AccessRevoke'
import CovercryptRevokeForm from './CovercryptKeysRevoke'
import CovercryptMasterKeyForm from './CovercryptMasterKey'
import CovercryptUserKeyForm from './CovercryptUserKey'
import ECDecryptForm from './ECDecrypt'
import ECEncryptForm from './ECEncrypt'
import ECKeyCreateForm from './ECKeysCreate'
import KeyDestroyForm from './KeysDestroy'
import KeyExportForm from './KeysExport'
import KeyImportForm from './KeysImport'
import KeyRevokeForm from './KeysRevoke'
import LocateForm from './Locate'
import MainLayout from './MainLayout'
import ObjectsOwnedList from './ObjectsOwned'
import RsaDecryptForm from './RsaDecrypt'
import RsaEncryptForm from './RsaEncrypt'
import RsaKeyCreateForm from './RsaKeysCreate'
import SymKeyCreateForm from './SymKeysCreate'
import SymmetricDecryptForm from './SymmetricDecrypt'
import SymmetricEncryptForm from './SymmetricEncrypt'
import init from "./wasm/pkg"




function App() {
  useEffect(() => {
    async function loadWasm() {
        await init();
    }

    loadWasm();
}, []);

  return (
    <ConfigProvider
      theme={{
        token: {
          colorPrimary: '#e34319',
          colorText: '#292f52',
        },
        components: {
          Layout: {
            headerBg: '#ffffff',
            siderBg: '#f4f4f5',
          }
        }
      }}
    >
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<MainLayout />}>
            <Route path="locate" element={<LocateForm />} />
            <Route path="sym/keys/create" element={<SymKeyCreateForm />} />
            <Route path="sym/keys/export" element={<KeyExportForm key_type={'symmetric'} />} />
            <Route path="sym/keys/import" element={<KeyImportForm key_type='symmetric' />} />
            <Route path="sym/keys/revoke" element={<KeyRevokeForm key_type='symmetric' />} />
            <Route path="sym/keys/destroy" element={<KeyDestroyForm key_type='symmetric' />} />
            <Route path="sym/encrypt" element={<SymmetricEncryptForm />} />
            <Route path="sym/decrypt" element={<SymmetricDecryptForm />} />
            <Route path="rsa/keys/create" element={<RsaKeyCreateForm />} />
            <Route path="rsa/keys/export" element={<KeyExportForm key_type={'rsa'} />} />
            <Route path="rsa/keys/import" element={<KeyImportForm key_type='rsa' />} />
            <Route path="rsa/keys/revoke" element={<KeyRevokeForm key_type='rsa' />} />
            <Route path="rsa/keys/destroy" element={<KeyDestroyForm key_type='rsa' />} />
            <Route path="rsa/encrypt" element={<RsaEncryptForm />} />
            <Route path="rsa/decrypt" element={<RsaDecryptForm />} />
            <Route path="ec/keys/create" element={<ECKeyCreateForm />} />
            <Route path="ec/keys/export" element={<KeyExportForm key_type={'ec'} />} />
            <Route path="ec/keys/import" element={<KeyImportForm key_type='ec' />} />
            <Route path="ec/keys/revoke" element={<KeyRevokeForm key_type='ec' />} />
            <Route path="ec/keys/destroy" element={<KeyDestroyForm key_type='ec' />} />
            <Route path="ec/encrypt" element={<ECEncryptForm />} />
            <Route path="ec/decrypt" element={<ECDecryptForm />} />
            <Route path="cc/keys/create-master-key-pair" element={<CovercryptMasterKeyForm />} />
            <Route path="cc/keys/create-user-key" element={<CovercryptUserKeyForm />} />
            <Route path="cc/keys/export" element={<KeyExportForm key_type={'covercrypt'} />} />
            <Route path="cc/keys/import" element={<KeyImportForm key_type={'covercrypt'} />} />
            <Route path="cc/keys/revoke" element={<CovercryptRevokeForm />} />
            <Route path="cc/keys/destroy" element={<KeyDestroyForm key_type='covercrypt' />} />
            <Route path="access-rights/grant" element={<AccessGrantForm />} />
            <Route path="access-rights/revoke" element={<AccessRevokeForm />} />
            <Route path="access-rights/list" element={<AccessListForm />} />
            <Route path="access-rights/owned" element={<ObjectsOwnedList />} />
            <Route path="access-rights/obtained" element={<AccessObtainedList />} />
          </Route>
        </Routes>
      </BrowserRouter>
      </ConfigProvider>
  )
}

export default App
