import { render, type RenderResult } from '@testing-library/react'
import React from 'react'
import { MemoryRouter, Route, Routes } from 'react-router-dom'

import { AuthProvider } from '../../src/AuthContext'

export type SmokeRenderOptions = {
  route?: string
  withRoutes?: boolean
  path?: string
  outlet?: React.ReactElement
}

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
      <MemoryRouter initialEntries={[route]}>{routedElement}</MemoryRouter>
    </AuthProvider>,
  )
}
