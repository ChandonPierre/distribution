import { useState } from 'react'
import type { FormEvent } from 'react'
import { useAuth } from '../auth'
import { login } from '../api'

interface Props {
  onLogin: () => void
}

export default function LoginPage({ onLogin }: Props) {
  const { setCreds, tokenCache } = useAuth()
  const [username, setUsername] = useState('')
  const [token, setToken] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    setError(null)
    setLoading(true)
    try {
      const creds = { username: username.trim(), token: token.trim() }
      const jwt = await login(creds)
      // Seed the token cache with the initial (no-scope) token so the first
      // /v2/_catalog request can skip the 401 round-trip when possible.
      if (jwt) tokenCache.set('', jwt)
      setCreds(creds)
      onLogin()
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <svg className="login-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <rect x="3" y="3" width="18" height="18" rx="2" />
            <path d="M3 9h18M9 21V9" />
          </svg>
          <h1>Docker Registry</h1>
          <p className="login-subtitle">Sign in to browse your registry</p>
        </div>

        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="username">Username</label>
            <input
              id="username"
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="your-username"
              autoComplete="username"
              required
              disabled={loading}
            />
          </div>

          <div className="form-group">
            <label htmlFor="token">OIDC Token</label>
            <textarea
              id="token"
              value={token}
              onChange={e => setToken(e.target.value)}
              placeholder="Paste your OIDC token here…"
              rows={5}
              required
              disabled={loading}
              spellCheck={false}
              autoComplete="off"
            />
          </div>

          {error && <div className="error-banner">{error}</div>}

          <button type="submit" className="btn btn-primary btn-full" disabled={loading}>
            {loading ? 'Signing in…' : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  )
}
