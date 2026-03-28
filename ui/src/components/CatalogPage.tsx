import { useState, useEffect, useMemo } from 'react'
import { useAuth } from '../auth'
import { getCatalog } from '../api'

interface Props {
  onSelectRepo: (repo: string) => void
  onLogout: () => void
}

export default function CatalogPage({ onSelectRepo, onLogout }: Props) {
  const { creds, tokenCache } = useAuth()
  const [repos, setRepos] = useState<string[]>([])
  const [filter, setFilter] = useState('')
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!creds) return
    setLoading(true)
    setError(null)
    getCatalog(creds, tokenCache)
      .then(r => {
        setRepos(r.sort())
        setLoading(false)
      })
      .catch(err => {
        setError(err instanceof Error ? err.message : String(err))
        setLoading(false)
      })
  }, [creds, tokenCache])

  const filtered = useMemo(() => {
    const q = filter.toLowerCase()
    return q ? repos.filter(r => r.toLowerCase().includes(q)) : repos
  }, [repos, filter])

  return (
    <div className="page">
      <header className="page-header">
        <div className="header-left">
          <svg className="header-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <path d="M3 9h18M9 21V9" />
          </svg>
          <h1>Registry</h1>
        </div>
        <div className="header-right">
          <span className="username-badge">{creds?.username}</span>
          <button className="btn btn-ghost" onClick={onLogout}>Sign out</button>
        </div>
      </header>

      <main className="page-content">
        <div className="catalog-toolbar">
          <h2>Repositories</h2>
          <div className="search-wrap">
            <svg className="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8" /><path d="m21 21-4.35-4.35" />
            </svg>
            <input
              type="search"
              className="search-input"
              placeholder="Filter repositories…"
              value={filter}
              onChange={e => setFilter(e.target.value)}
            />
          </div>
        </div>

        {loading && <div className="loading-state">Loading repositories…</div>}
        {error && <div className="error-banner">{error}</div>}

        {!loading && !error && (
          <>
            <p className="repo-count">
              {filtered.length} {filtered.length === 1 ? 'repository' : 'repositories'}
              {filter && ` matching "${filter}"`}
            </p>

            {filtered.length === 0 ? (
              <div className="empty-state">No repositories found.</div>
            ) : (
              <ul className="repo-list">
                {filtered.map(repo => (
                  <li key={repo} className="repo-item">
                    <button className="repo-btn" onClick={() => onSelectRepo(repo)}>
                      <svg className="repo-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
                      </svg>
                      <span className="repo-name">{repo}</span>
                      <svg className="chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="9 18 15 12 9 6" />
                      </svg>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </>
        )}
      </main>
    </div>
  )
}
