import { useState, useRef } from 'react'
import type { Credentials, Page } from './types'
import { AuthContext } from './auth'
import LoginPage from './components/LoginPage'
import CatalogPage from './components/CatalogPage'
import RepoPage from './components/RepoPage'

export default function App() {
  const [creds, setCreds] = useState<Credentials | null>(null)
  const [page, setPage] = useState<Page>({ kind: 'login' })
  const tokenCache = useRef<Map<string, string>>(new Map())

  function handleSetCreds(c: Credentials | null) {
    setCreds(c)
    tokenCache.current.clear()
    if (c === null) setPage({ kind: 'login' })
  }

  return (
    <AuthContext.Provider
      value={{ creds, tokenCache: tokenCache.current, setCreds: handleSetCreds }}
    >
      <div className="app">
        {page.kind === 'login' && (
          <LoginPage onLogin={() => setPage({ kind: 'catalog' })} />
        )}
        {page.kind === 'catalog' && (
          <CatalogPage
            onSelectRepo={(repo) => setPage({ kind: 'repo', repo })}
            onLogout={() => { handleSetCreds(null) }}
          />
        )}
        {page.kind === 'repo' && (
          <RepoPage
            repo={page.repo}
            onBack={() => setPage({ kind: 'catalog' })}
          />
        )}
      </div>
    </AuthContext.Provider>
  )
}
