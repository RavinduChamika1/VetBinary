export default function FindingsSection({ confirmed = [], needsReview = [] }) {
  const hasFindings = confirmed.length > 0 || needsReview.length > 0

  return (
    <div className="card">
      <div className="card-header">Security Findings & Corroborated Evidence</div>
      <div className="card-body">
        {!hasFindings && (
          <p className="no-data">No malicious indicators or threats detected across active sources.</p>
        )}

        {confirmed.length > 0 && (
          <div style={{ marginBottom: 16 }}>
            <h4 style={{ color: 'var(--danger-text)', marginBottom: 8, fontSize: '0.85rem', textTransform: 'uppercase' }}>
              Confirmed Malicious Findings ({confirmed.length})
            </h4>
            {confirmed.map((f, idx) => (
              <div key={idx} className="finding">
                <div className="finding-title">{f.finding}</div>
                <div className="finding-evidence">
                  Source: <strong>{f.source}</strong> | Evidence: {f.evidence}
                </div>
              </div>
            ))}
          </div>
        )}

        {needsReview.length > 0 && (
          <div>
            <h4 style={{ color: 'var(--review-text)', marginBottom: 8, fontSize: '0.85rem', textTransform: 'uppercase' }}>
              Items Requiring Manual Review ({needsReview.length})
            </h4>
            {needsReview.map((nr, idx) => (
              <div key={idx} className="finding review-finding">
                <div className="finding-title">{nr.finding}</div>
                <div className="finding-evidence">
                  Source: <strong>{nr.source}</strong> | Reason: {nr.reasoning}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
