import { useState, useRef, useEffect } from 'react'
import type { Credentials, TagInfo, Page } from './types'
import { AuthContext } from './auth'
import { login } from './api'
import LoginPage from './components/LoginPage'
import CatalogPage from './components/CatalogPage'
import RepoPage from './components/RepoPage'

export default function App() {
  const [creds, setCreds] = useState<Credentials | null>(null)
  const [page, setPage] = useState<Page>({ kind: 'login' })
  const tokenCache = useRef<Map<string, string>>(new Map())
  const repoCache = useRef<Map<string, { tagNames: string[]; tagInfos: Map<string, TagInfo> }>>(new Map())
  const [catalogRepos, setCatalogRepos] = useState<string[] | null>(null)

  // On mount, attempt an anonymous token. If it succeeds the registry has
  // public repos — go straight to the catalog without requiring login.
  useEffect(() => {
    login(null, 'registry:catalog:*')
      .then(jwt => {
        tokenCache.current.set('registry:catalog:*', jwt)
        setPage({ kind: 'catalog' })
      })
      .catch(() => {
        // Anonymous access not available — stay on login page.
      })
  }, [])

  function handleSetCreds(c: Credentials | null) {
    setCreds(c)
    if (c === null) {
      tokenCache.current.clear()
      setCatalogRepos(null)
      setPage({ kind: 'login' })
    }
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
            cachedRepos={catalogRepos}
            onReposLoaded={setCatalogRepos}
            onSelectRepo={(repo) => setPage({ kind: 'repo', repo })}
            onLogout={() => { handleSetCreds(null) }}
          />
        )}
        {page.kind === 'repo' && (
          <RepoPage
            repo={page.repo}
            onBack={() => setPage({ kind: 'catalog' })}
            cachedData={repoCache.current.get(page.repo)}
            onDataLoaded={(tagNames, tagInfos) => {
              repoCache.current.set(page.repo, { tagNames, tagInfos })
            }}
          />
        )}
      </div>
    </AuthContext.Provider>
  )
}
