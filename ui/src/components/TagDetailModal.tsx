import { useState } from 'react'
import type { MouseEvent } from 'react'
import type { TagInfo } from '../types'

interface Props {
  repo: string
  tagInfo: TagInfo
  onClose: () => void
}

function shortDigest(digest: string): string {
  const colon = digest.indexOf(':')
  const hex = colon >= 0 ? digest.slice(colon + 1) : digest
  return hex.slice(0, 12)
}

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
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

export default function TagDetailModal({ repo, tagInfo, onClose }: Props) {
  const host = window.location.host
  const pullCmd = `docker pull ${host}/${repo}:${tagInfo.name}`
  const [copied, setCopied] = useState(false)

  function handleCopy() {
    navigator.clipboard.writeText(pullCmd).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  function handleBackdrop(e: MouseEvent<HTMLDivElement>) {
    if (e.target === e.currentTarget) onClose()
  }

  return (
    <div className="modal-backdrop" onClick={handleBackdrop}>
      <div className="modal" role="dialog" aria-modal="true">
        <div className="modal-header">
          <div>
            <h2 className="modal-title">{tagInfo.name}</h2>
            <p className="modal-subtitle">{repo}</p>
          </div>
          <button className="modal-close" onClick={onClose} aria-label="Close">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        <div className="modal-body">
          <section className="detail-section">
            <h3>Image details</h3>
            <dl className="detail-grid">
              <dt>Digest</dt>
              <dd className="mono">{tagInfo.digest}</dd>

              <dt>Total size</dt>
              <dd>{formatBytes(tagInfo.size)}</dd>

              <dt>Created</dt>
              <dd>{formatDate(tagInfo.created)}</dd>

              <dt>OS / Arch</dt>
              <dd>{[tagInfo.os, tagInfo.architecture].filter(Boolean).join(' / ') || '—'}</dd>
            </dl>
          </section>

          <section className="detail-section">
            <h3>Pull command</h3>
            <div className="pull-cmd-wrap">
              <code className="pull-cmd">{pullCmd}</code>
              <button className="btn btn-ghost btn-sm" onClick={handleCopy}>
                {copied ? (
                  <>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="btn-icon">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                    Copied
                  </>
                ) : (
                  <>
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="btn-icon">
                      <rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                    </svg>
                    Copy
                  </>
                )}
              </button>
            </div>
          </section>

          {tagInfo.layers && tagInfo.layers.length > 0 && (
            <section className="detail-section">
              <h3>Layers ({tagInfo.layers.length})</h3>
              <div className="table-wrap">
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Digest</th>
                      <th className="col-right">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {tagInfo.layers.map((layer, i) => (
                      <tr key={layer.digest}>
                        <td className="col-muted">{i + 1}</td>
                        <td className="mono">{shortDigest(layer.digest)}</td>
                        <td className="col-right">{formatBytes(layer.size)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}
        </div>
      </div>
    </div>
  )
}
