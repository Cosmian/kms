import { BrowserRouter, Routes, Route } from 'react-router-dom';
import MainLayout from './MainLayout';
import KeyExportForm from './KeysExport';
import RsaKeyCreateForm from './RsaKeysCreate';
import KeyImportForm from './KeysImport';
import KeyRevokeForm from './KeysRevoke';
import KeyDestroyForm from './KeysDestroy';
import SymKeyCreateForm from './SymKeysCreate';
import ECKeyCreateForm from './ECKeysCreate';

function App() {

  return (
    <>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<MainLayout />}>
            <Route path="sym/keys/create" element={<SymKeyCreateForm />} />
            <Route path="sym/keys/export" element={<KeyExportForm key_type={'symmetric'} />} />
            <Route path="sym/keys/import" element={<KeyImportForm key_type='symmetric' />} />
            <Route path="sym/keys/revoke" element={<KeyRevokeForm key_type='symmetric' />} />
            <Route path="sym/keys/destroy" element={<KeyDestroyForm key_type='symmetric' />} />
            <Route path="rsa/keys/create" element={<RsaKeyCreateForm />} />
            <Route path="rsa/keys/export" element={<KeyExportForm key_type={'rsa'} />} />
            <Route path="rsa/keys/import" element={<KeyImportForm key_type='rsa' />} />
            <Route path="rsa/keys/revoke" element={<KeyRevokeForm key_type='rsa' />} />
            <Route path="rsa/keys/destroy" element={<KeyDestroyForm key_type='rsa' />} />
            <Route path="ec/keys/create" element={<ECKeyCreateForm />} />
            <Route path="ec/keys/export" element={<KeyExportForm key_type={'ec'} />} />
            <Route path="ec/keys/import" element={<KeyImportForm key_type='ec' />} />
            <Route path="ec/keys/revoke" element={<KeyRevokeForm key_type='ec' />} />
            <Route path="ec/keys/destroy" element={<KeyDestroyForm key_type='ec' />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </>
  )
}

export default App
