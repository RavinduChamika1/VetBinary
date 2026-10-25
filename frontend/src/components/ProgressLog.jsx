const STANDARD_STAGES = [
  { key: 'sha', label: 'Computing SHA-256 hash & file integrity' },
  { key: 'identity', label: 'Extracting file identity & Authenticode signatures' },
  { key: 'vt', label: 'Querying VirusTotal multi-engine detection' },
  { key: 'sandbox', label: 'Evaluating dynamic sandbox eligibility' },
  { key: 'cve', label: 'Researching public vulnerabilities (NVD & OSV.dev)' },
  { key: 'kev', label: 'Checking CISA Known Exploited Vulnerabilities (KEV)' },
  { key: 'gemini', label: 'Running Gemini AI false-positive audit' },
  { key: 'verdict', label: 'Applying verdict correlation & risk scoring' },
  { key: 'report', label: 'Finalizing comprehensive vetting report' },
]

export default function ProgressLog({ currentStep, steps = [] }) {
  // Determine stage progression
  const lowerCurrent = (currentStep || '').toLowerCase()
  const allText = steps.join(' ').toLowerCase() + ' ' + lowerCurrent

  return (
    <div className="card" style={{ border: '1px solid var(--accent)' }}>
      <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span>Pre-Deployment Vetting In Progress</span>
        <span className="badge badge-high" style={{ animation: 'pulse 1.5s infinite' }}>Analyzing Telemetry</span>
      </div>
      <div className="card-body">
        {/* Active step banner */}
        <div style={{ background: 'var(--surface2)', padding: '14px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', marginBottom: '16px', display: 'flex', alignItems: 'center', gap: '12px' }}>
          <span className="spinner" style={{ width: '16px', height: '16px', borderWidth: '2px' }} />
          <div>
            <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--accent)', fontWeight: 700, letterSpacing: '0.6px' }}>Current Phase</div>
            <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text)' }}>
              {currentStep || 'Initializing vetting pipeline…'}
            </div>
          </div>
        </div>

        {/* Pipeline Stage Checklist */}
        <div style={{ marginBottom: '16px' }}>
          <div style={{ fontSize: '0.78rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700, letterSpacing: '0.8px', marginBottom: '8px' }}>
            Analysis Pipeline Steps
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
            {STANDARD_STAGES.map((st) => {
              const isMatch = (
                (st.key === 'sha' && allText.includes('sha-256')) ||
                (st.key === 'identity' && allText.includes('identity')) ||
                (st.key === 'vt' && allText.includes('virustotal')) ||
                (st.key === 'sandbox' && (allText.includes('sandbox') || allText.includes('hybrid') || allText.includes('any.run'))) ||
                (st.key === 'cve' && (allText.includes('nvd') || allText.includes('osv'))) ||
                (st.key === 'kev' && allText.includes('cisa')) ||
                (st.key === 'gemini' && allText.includes('gemini')) ||
                (st.key === 'verdict' && (allText.includes('verdict') || allText.includes('scoring'))) ||
                (st.key === 'report' && allText.includes('report'))
              )

              const isCurrent = (
                (st.key === 'sha' && lowerCurrent.includes('sha-256')) ||
                (st.key === 'identity' && lowerCurrent.includes('identity')) ||
                (st.key === 'vt' && lowerCurrent.includes('virustotal')) ||
                (st.key === 'sandbox' && (lowerCurrent.includes('sandbox') || lowerCurrent.includes('hybrid') || lowerCurrent.includes('any.run'))) ||
                (st.key === 'cve' && (lowerCurrent.includes('nvd') || lowerCurrent.includes('osv'))) ||
                (st.key === 'kev' && lowerCurrent.includes('cisa')) ||
                (st.key === 'gemini' && lowerCurrent.includes('gemini')) ||
                (st.key === 'verdict' && (lowerCurrent.includes('verdict') || lowerCurrent.includes('scoring'))) ||
                (st.key === 'report' && lowerCurrent.includes('report'))
              )

              return (
                <div
                  key={st.key}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '10px',
                    padding: '6px 10px',
                    borderRadius: '4px',
                    fontSize: '0.82rem',
                    background: isCurrent ? 'rgba(79, 142, 247, 0.1)' : 'transparent',
                    color: isMatch ? (isCurrent ? 'var(--accent)' : 'var(--safe-text)') : 'var(--text-muted)',
                    fontWeight: isCurrent ? 600 : 400,
                  }}
                >
                  <span style={{ width: '16px', textAlign: 'center' }}>
                    {isCurrent ? '⏳' : isMatch ? '✓' : '○'}
                  </span>
                  <span>{st.label}</span>
                </div>
              )
            })}
          </div>
        </div>

        {/* Raw progress events log */}
        {steps.length > 0 && (
          <div>
            <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', color: 'var(--text-muted)', fontWeight: 700, letterSpacing: '0.6px', marginBottom: '6px' }}>
              Execution Log ({steps.length})
            </div>
            <div className="progress-log" style={{ maxHeight: '150px', overflowY: 'auto' }}>
              {steps.map((s, idx) => (
                <div key={idx} className="step-line step-done">
                  <span>✓</span>
                  <span>{s}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
