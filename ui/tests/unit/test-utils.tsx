import { render, type RenderResult } from '@testing-library/react'
import React from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { BrandingProvider } from "../../src/BrandingContext";
import type { Branding } from "../../src/branding";

import { AuthProvider } from '../../src/AuthContext'

export type SmokeRenderOptions = {
  route?: string
  withRoutes?: boolean
  path?: string
  outlet?: React.ReactElement
}

const mockBranding = {
  title: "Key Management System",
  logoAlt: "Key Management System",
  logoLightUrl: "",
  logoDarkUrl: "",
  loginTitle: "",
  backgroundImageUrl: "",
};

export function smokeRender(element: React.ReactElement, options: SmokeRenderOptions = {}): RenderResult {
  const route = options.route ?? '/'

  const routedElement = options.withRoutes ? (
    <Routes>
      <Route path={options.path ?? '/'} element={element}>
        <Route index element={options.outlet ?? <div data-testid="outlet" />} />
      </Route>
    </Routes>
  ) : (
    element
  )

  return render(
    <AuthProvider>
      <MemoryRouter initialEntries={[route]}>
        <BrandingProvider branding={mockBranding}>
          {routedElement}
        </BrandingProvider>
      </MemoryRouter>
    </AuthProvider>,
  )
}