import { useState, useEffect, useCallback } from 'react'
import type { TagInfo } from '../types'
import { useAuth } from '../auth'
import { getTags, resolveTagInfo } from '../api'
import TagDetailModal from './TagDetailModal'
import DeleteConfirmModal from './DeleteConfirmModal'

interface Props {
  repo: string
  onBack: () => void
}

function shortDigest(digest: string): string {
  const colon = digest.indexOf(':')
  const hex = colon >= 0 ? digest.slice(colon + 1) : digest
  return hex.slice(0, 12)
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(2)} ${units[i]}`
}

function formatDate(iso?: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

export default function RepoPage({ repo, onBack }: Props) {
  const { creds, tokenCache } = useAuth()

  const [tagNames, setTagNames] = useState<string[]>([])
  const [tagInfos, setTagInfos] = useState<Map<string, TagInfo>>(new Map())
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [detailTag, setDetailTag] = useState<TagInfo | null>(null)
  const [showDelete, setShowDelete] = useState(false)

  const loadTags = useCallback(async () => {
    setLoading(true)
    setError(null)
    setSelected(new Set())
    try {
      const names = await getTags(repo, creds, tokenCache)
      setTagNames(names.sort())
      setLoading(false)

      // Load tag details concurrently (up to 6 at a time)
      const concurrency = 6
      const queue = [...names]
      const infos = new Map<string, TagInfo>()

      async function worker() {
        while (queue.length > 0) {
          const tag = queue.shift()
          if (!tag) break
          try {
            const info = await resolveTagInfo(repo, tag, creds!, tokenCache)
            infos.set(tag, info)
            setTagInfos(new Map(infos))
          } catch {
            // Leave the tag in the list without detail
            infos.set(tag, { name: tag, digest: '', size: 0 })
            setTagInfos(new Map(infos))
          }
        }
      }

      await Promise.all(Array.from({ length: concurrency }, worker))
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err))
      setLoading(false)
    }
  }, [creds, tokenCache, repo])

  useEffect(() => {
    loadTags()
  }, [loadTags])

  const allChecked = tagNames.length > 0 && tagNames.every(t => selected.has(t))
  const someChecked = tagNames.some(t => selected.has(t))

  function toggleAll() {
    if (allChecked) {
      setSelected(new Set())
    } else {
      setSelected(new Set(tagNames))
    }
  }

  function toggleOne(tag: string) {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(tag)) next.delete(tag)
      else next.add(tag)
      return next
    })
  }

  function handleDeleteDone(deletedTags: string[]) {
    setShowDelete(false)
    if (deletedTags.length > 0) {
      setTagNames(prev => prev.filter(t => !deletedTags.includes(t)))
      setTagInfos(prev => {
        const next = new Map(prev)
        deletedTags.forEach(t => next.delete(t))
        return next
      })
      setSelected(new Set())
    }
  }

  const selectedTagInfos = tagNames
    .filter(t => selected.has(t))
    .map(t => tagInfos.get(t) ?? { name: t, digest: '', size: 0 })

  return (
    <div className="page">
      <header className="page-header">
        <div className="header-left">
          <button className="btn btn-ghost btn-icon-only" onClick={onBack} aria-label="Back to catalog">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <polyline points="15 18 9 12 15 6" />
            </svg>
          </button>
          <div>
            <h1 className="repo-page-title">{repo}</h1>
            <p className="repo-page-sub">Tags</p>
          </div>
        </div>
        <div className="header-right">
          {creds && (
          <button
            className="btn btn-danger"
            disabled={!someChecked}
            onClick={() => setShowDelete(true)}
          >
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="btn-icon">
              <polyline points="3 6 5 6 21 6" />
              <path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6" />
              <path d="M10 11v6M14 11v6" />
              <path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2" />
            </svg>
            Delete ({selected.size})
          </button>
          )}
        </div>
      </header>

      <main className="page-content">
        {loading && <div className="loading-state">Loading tags…</div>}
        {error && <div className="error-banner">{error}</div>}

        {!loading && !error && tagNames.length === 0 && (
          <div className="empty-state">No tags found in this repository.</div>
        )}

        {tagNames.length > 0 && (
          <div className="table-wrap">
            <table className="data-table tags-table">
              <thead>
                <tr>
                  <th className="col-check">
                    <input
                      type="checkbox"
                      checked={allChecked}
                      ref={el => {
                        if (el) el.indeterminate = someChecked && !allChecked
                      }}
                      onChange={toggleAll}
                      aria-label="Select all"
                    />
                  </th>
                  <th>Tag</th>
                  <th>Digest</th>
                  <th className="col-right">Size</th>
                  <th>Created</th>
                  <th>OS / Arch</th>
                </tr>
              </thead>
              <tbody>
                {tagNames.map(tag => {
                  const info = tagInfos.get(tag)
                  const resolving = !info
                  return (
                    <tr
                      key={tag}
                      className={selected.has(tag) ? 'row-selected' : ''}
                      onClick={(e) => {
                        const target = e.target as HTMLElement
                        if (target.tagName === 'INPUT') return
                        if (info) setDetailTag(info)
                      }}
                      style={{ cursor: info ? 'pointer' : 'default' }}
                    >
                      <td className="col-check" onClick={e => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={selected.has(tag)}
                          onChange={() => toggleOne(tag)}
                          aria-label={`Select ${tag}`}
                        />
                      </td>
                      <td className="tag-name-cell">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="tag-icon-sm">
                          <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z" />
                          <line x1="7" y1="7" x2="7.01" y2="7" />
                        </svg>
                        {tag}
                      </td>
                      <td className="mono col-muted">
                        {resolving ? <span className="skeleton" style={{ width: '8ch' }} /> : shortDigest(info.digest)}
                      </td>
                      <td className="col-right">
                        {resolving ? <span className="skeleton" style={{ width: '5ch' }} /> : formatBytes(info.size)}
                      </td>
                      <td>
                        {resolving ? <span className="skeleton" style={{ width: '12ch' }} /> : formatDate(info.created)}
                      </td>
                      <td className="col-muted">
                        {resolving ? (
                          <span className="skeleton" style={{ width: '8ch' }} />
                        ) : (
                          [info.os, info.architecture].filter(Boolean).join(' / ') || '—'
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}
      </main>

      {detailTag && (
        <TagDetailModal
          repo={repo}
          tagInfo={detailTag}
          onClose={() => setDetailTag(null)}
        />
      )}

      {showDelete && (
        <DeleteConfirmModal
          repo={repo}
          selected={selectedTagInfos}
          onDone={handleDeleteDone}
          onCancel={() => setShowDelete(false)}
        />
      )}
    </div>
  )
}
