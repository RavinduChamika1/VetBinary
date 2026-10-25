export default function VirusTotalSection({ vtResult }) {
  if (!vtResult) {
    return (
      <div className="card">
        <div className="card-header">VirusTotal Multi-Engine Reputation</div>
        <div className="card-body">
          <p className="no-data">VirusTotal telemetry was not available or skipped for this file.</p>
        </div>
      </div>
    )
  }

  const { detections = 0, total_engines = 0, engine_names_that_flagged = [], popular_threat_category } = vtResult
  const isFlagged = detections > 0

  return (
    <div className="card">
      <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span>VirusTotal Multi-Engine Reputation</span>
        <span className={`badge ${isFlagged ? (detections >= 2 ? 'badge-danger' : 'badge-review') : 'badge-ok'}`}>
          {detections} / {total_engines} Engines Flagged
        </span>
      </div>
      <div className="card-body">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '12px', marginBottom: isFlagged ? '16px' : '0' }}>
          <div style={{ background: 'var(--surface2)', padding: '10px 14px', borderRadius: 'var(--radius)' }}>
            <span className="muted" style={{ fontSize: '0.75rem', textTransform: 'uppercase', display: 'block' }}>Detection Ratio</span>
            <span style={{ fontSize: '1.2rem', fontWeight: 700, color: isFlagged ? 'var(--danger-text)' : 'var(--safe-text)' }}>
              {detections} / {total_engines}
            </span>
          </div>
          <div style={{ background: 'var(--surface2)', padding: '10px 14px', borderRadius: 'var(--radius)' }}>
            <span className="muted" style={{ fontSize: '0.75rem', textTransform: 'uppercase', display: 'block' }}>Threat Category</span>
            <span style={{ fontSize: '1rem', fontWeight: 600 }}>
              {popular_threat_category || (isFlagged ? 'Uncategorized' : 'None Detected')}
            </span>
          </div>
        </div>

        {engine_names_that_flagged.length > 0 && (
          <div>
            <h5 style={{ fontSize: '0.78rem', textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: '8px' }}>
              Engines That Flagged This File ({engine_names_that_flagged.length})
            </h5>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {engine_names_that_flagged.map((eng, idx) => (
                <span key={idx} className="badge badge-danger mono" style={{ fontSize: '0.75rem' }}>
                  {eng}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
