import { useState } from 'react'
import type { MouseEvent } from 'react'
import type { TagInfo } from '../types'
import { useAuth } from '../auth'
import { deleteManifest } from '../api'

interface Props {
  repo: string
  selected: TagInfo[]
  onDone: (deletedTags: string[]) => void
  onCancel: () => void
}

type Status = 'idle' | 'running' | 'done'

export default function DeleteConfirmModal({ repo, selected, onDone, onCancel }: Props) {
  const { creds, tokenCache } = useAuth()
  const [status, setStatus] = useState<Status>('idle')
  const [progress, setProgress] = useState<string[]>([])
  const [errors, setErrors] = useState<string[]>([])

  async function handleConfirm() {
    setStatus('running')
    const deleted: string[] = []
    const errs: string[] = []

    for (const tag of selected) {
      setProgress(p => [...p, `Deleting ${tag.name}…`])
      try {
        await deleteManifest(repo, tag.digest, creds, tokenCache)
        deleted.push(tag.name)
        setProgress(p => [...p.slice(0, -1), `Deleted ${tag.name}`])
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err)
        errs.push(`${tag.name}: ${msg}`)
        setProgress(p => [...p.slice(0, -1), `Failed ${tag.name}: ${msg}`])
      }
    }

    setErrors(errs)
    setStatus('done')

    if (errs.length === 0) {
      // Auto-close after short delay when everything succeeded
      setTimeout(() => onDone(deleted), 800)
    }
  }

  function handleClose() {
    const deleted = selected
      .filter(t => progress.some(p => p.startsWith(`Deleted ${t.name}`)))
      .map(t => t.name)
    onDone(deleted)
  }

  function handleBackdrop(e: MouseEvent<HTMLDivElement>) {
    if (e.target === e.currentTarget && status !== 'running') {
      onCancel()
    }
  }

  return (
    <div className="modal-backdrop" onClick={handleBackdrop}>
      <div className="modal modal-sm" role="dialog" aria-modal="true">
        <div className="modal-header">
          <h2 className="modal-title">
            {status === 'idle' && 'Confirm deletion'}
            {status === 'running' && 'Deleting…'}
            {status === 'done' && (errors.length === 0 ? 'Done' : 'Completed with errors')}
          </h2>
          {status !== 'running' && (
            <button className="modal-close" onClick={status === 'done' ? handleClose : onCancel} aria-label="Close">
              <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
              </svg>
            </button>
          )}
        </div>

        <div className="modal-body">
          {status === 'idle' && (
            <>
              <p className="delete-warning">
                You are about to permanently delete {selected.length}{' '}
                {selected.length === 1 ? 'tag' : 'tags'} from <strong>{repo}</strong>. This cannot be undone.
              </p>
              <ul className="delete-tag-list">
                {selected.map(t => (
                  <li key={t.digest} className="delete-tag-item">
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="tag-icon">
                      <path d="M20.59 13.41l-7.17 7.17a2 2 0 0 1-2.83 0L2 12V2h10l8.59 8.59a2 2 0 0 1 0 2.82z" />
                      <line x1="7" y1="7" x2="7.01" y2="7" />
                    </svg>
                    {t.name}
                  </li>
                ))}
              </ul>
            </>
          )}

          {(status === 'running' || status === 'done') && (
            <div className="progress-log">
              {progress.map((line, i) => (
                <div
                  key={i}
                  className={`progress-line ${
                    line.startsWith('Deleted') ? 'line-ok' :
                    line.startsWith('Failed') ? 'line-err' : 'line-running'
                  }`}
                >
                  {line.startsWith('Deleted') && (
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="progress-icon">
                      <polyline points="20 6 9 17 4 12" />
                    </svg>
                  )}
                  {line.startsWith('Failed') && (
                    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" className="progress-icon">
                      <circle cx="12" cy="12" r="10" /><line x1="15" y1="9" x2="9" y2="15" /><line x1="9" y1="9" x2="15" y2="15" />
                    </svg>
                  )}
                  {!line.startsWith('Deleted') && !line.startsWith('Failed') && (
                    <span className="spinner-sm" />
                  )}
                  {line}
                </div>
              ))}
            </div>
          )}
        </div>

        <div className="modal-footer">
          {status === 'idle' && (
            <>
              <button className="btn btn-ghost" onClick={onCancel}>Cancel</button>
              <button className="btn btn-danger" onClick={handleConfirm}>
                Delete {selected.length} {selected.length === 1 ? 'tag' : 'tags'}
              </button>
            </>
          )}
          {status === 'done' && errors.length > 0 && (
            <button className="btn btn-primary" onClick={handleClose}>Close</button>
          )}
        </div>
      </div>
    </div>
  )
}
