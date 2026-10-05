import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

import '@fontsource/orbitron/500.css'
import '@fontsource/orbitron/700.css'
import '@fontsource/orbitron/800.css'
import '@fontsource/share-tech-mono/400.css'
import './index.css'

import App from './App'
import { AuthProvider } from './lib/auth'
import { HostModalProvider } from './components/HostModal'
import { ExploreProvider } from './components/ExploreModal'
import { AppearanceProvider } from './lib/appearance'

const qc = new QueryClient({
  defaultOptions: {
    queries: {
      // The SSE stream is what triggers refreshes, so polling would be pure
      // waste. staleTime keeps a tab switch from refetching needlessly.
      refetchOnWindowFocus: false,
      staleTime: 30_000,
      retry: 1,
    },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={qc}>
      <AppearanceProvider>
        <AuthProvider>
          <HostModalProvider>
            <ExploreProvider>
              <App />
            </ExploreProvider>
          </HostModalProvider>
        </AuthProvider>
      </AppearanceProvider>
    </QueryClientProvider>
  </StrictMode>,
)
