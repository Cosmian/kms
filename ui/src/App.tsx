import { BrowserRouter, Routes, Route } from 'react-router-dom';
import MainLayout from './MainLayout';
import RsaKeyCreate from './RsaKeyCreate';

function App() {

  return (
    <>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<MainLayout />}>
            <Route path="rsa/keys/create" element={<RsaKeyCreate />} />

          </Route>
        </Routes>
      </BrowserRouter>
    </>
  )
}

export default App
