import { useState, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import { submitScan } from '../api'

const MAX_MB = 650

export default function UploadPage() {
  const [file, setFile] = useState(null)
  const [dragging, setDragging] = useState(false)
  const [purpose, setPurpose] = useState('')
  const [scope, setScope] = useState('')
  const [allowPublic, setAllowPublic] = useState(false)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')
  const fileInputRef = useRef()
  const navigate = useNavigate()

  function handleFilePick(f) {
    if (!f) return
    if (f.size > MAX_MB * 1024 * 1024) {
      setError(`File is ${(f.size / 1024 / 1024).toFixed(1)} MB — maximum is ${MAX_MB} MB.`)
      return
    }
    setError('')
    setFile(f)
  }

  function onDrop(e) {
    e.preventDefault()
    setDragging(false)
    handleFilePick(e.dataTransfer.files[0])
  }

  async function handleSubmit(e) {
    e.preventDefault()
    if (!file) { setError('Please select a file.'); return }
    if (!purpose.trim()) { setError('Purpose comment is required.'); return }

    setSubmitting(true)
    setError('')
    try {
      const fd = new FormData()
      fd.append('file', file)
      fd.append('purpose_comment', purpose.trim())
      fd.append('deployment_scope', scope.trim())
      fd.append('allow_public_sandbox_sharing', String(allowPublic))

      const { scan_id } = await submitScan(fd)
      navigate(`/results/${scan_id}`)
    } catch (err) {
      setError(err.message || 'Submission failed.')
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div className="page">
      <header className="site-header">
        <h1>VetBinary</h1>
        <span className="tagline">Pre-Deployment File Vetting</span>
      </header>

      <div className="disclaimer-bar">
        ⚠ VetBinary supports a deployment decision and does not replace enterprise endpoint security controls
        (EDR, application allow-listing, etc.).
      </div>

      <form onSubmit={handleSubmit}>
        {/* File drop zone */}
        <div className="form-group">
          <label>File to Vet *</label>
          <div
            className={`file-drop${dragging ? ' dragging' : ''}`}
            onClick={() => fileInputRef.current.click()}
            onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
            onDragLeave={() => setDragging(false)}
            onDrop={onDrop}
          >
            <div className="drop-icon">📁</div>
            <div className="drop-text">Click to browse or drag &amp; drop a file here</div>
            <div className="drop-text" style={{ marginTop: 4 }}>
              .exe · .msi · .dll · .zip · any binary — max {MAX_MB} MB
            </div>
            {file && (
              <div className="file-selected">
                ✓ {file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)
              </div>
            )}
          </div>
          <input
            ref={fileInputRef}
            type="file"
            style={{ display: 'none' }}
            onChange={(e) => handleFilePick(e.target.files[0])}
          />
        </div>

        {/* Purpose */}
        <div className="form-group">
          <label>Purpose / Reason for Testing *</label>
          <textarea
            rows={3}
            placeholder="e.g. Evaluating as a Postman replacement, internal dev team request"
            value={purpose}
            onChange={(e) => setPurpose(e.target.value)}
            required
          />
          <div className="hint">
            Describe why this file is being vetted. This appears in the report.
          </div>
        </div>

        {/* Deployment scope */}
        <div className="form-group">
          <label>Deployment Scope <span className="muted">(optional)</span></label>
          <input
            type="text"
            placeholder="e.g. developer laptops only, finance department PCs"
            value={scope}
            onChange={(e) => setScope(e.target.value)}
          />
          <div className="hint">
            Used to tailor remediation steps in the report.
          </div>
        </div>

        {/* Public sandbox consent */}
        <div className="form-group">
          <label>Sandbox Sharing</label>
          <div className="checkbox-row">
            <input
              type="checkbox"
              id="allowPublic"
              checked={allowPublic}
              onChange={(e) => setAllowPublic(e.target.checked)}
            />
            <div>
              <label className="cb-label" htmlFor="allowPublic">
                I consent to submitting this file to public sandboxes (Hybrid Analysis, ANY.RUN if configured)
              </label>
              <div className="cb-warn">
                ⚠ Free-tier sandboxes often make submitted samples <strong>publicly visible</strong>.
                Do not check this box for confidential or proprietary files.
                If unchecked, sandboxes are skipped and the report states why.
              </div>
            </div>
          </div>
        </div>

        {error && <div className="error-bar">❌ {error}</div>}

        <button
          type="submit"
          className="btn btn-primary"
          disabled={submitting || !file || !purpose.trim()}
          id="submit-scan-btn"
        >
          {submitting ? 'Submitting…' : 'Start Vetting'}
        </button>
      </form>
    </div>
  )
}
