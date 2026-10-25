export default function SandboxSection({ sandboxResults = [] }) {
  if (!sandboxResults || sandboxResults.length === 0) {
    return (
      <div className="card">
        <div className="card-header">Dynamic Sandbox Telemetry</div>
        <div className="card-body">
          <p className="no-data">No dynamic sandbox execution was performed (sandboxes were skipped or file not submitted).</p>
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-header">Dynamic Sandbox Telemetry ({sandboxResults.length} Environment{sandboxResults.length > 1 ? 's' : ''})</div>
      <div className="card-body">
        {sandboxResults.map((sb, idx) => {
          const isMal = (sb.verdict || '').toLowerCase().includes('malicious')
          const isSusp = (sb.verdict || '').toLowerCase().includes('suspicious')

          return (
            <div key={idx} style={{ background: 'var(--surface2)', borderRadius: 'var(--radius)', padding: '14px', marginBottom: idx < sandboxResults.length - 1 ? '14px' : '0' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                <span style={{ fontSize: '1rem', fontWeight: 700 }}>{sb.service}</span>
                <div>
                  <span className={`badge ${isMal ? 'badge-danger' : isSusp ? 'badge-review' : 'badge-ok'}`} style={{ marginRight: '8px' }}>
                    Verdict: {sb.verdict}
                  </span>
                  <span className="badge badge-skip">
                    Score: {sb.score ?? 0} / 100
                  </span>
                </div>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '10px', fontSize: '0.82rem' }}>
                <div>
                  <strong className="muted">Network Activity:</strong>
                  {sb.indicators?.network?.length > 0 ? (
                    <ul style={{ paddingLeft: '16px', marginTop: '4px' }}>
                      {sb.indicators.network.slice(0, 5).map((n, i) => (
                        <li key={i} className="mono" style={{ wordBreak: 'break-all' }}>{n}</li>
                      ))}
                    </ul>
                  ) : <div className="muted" style={{ fontStyle: 'italic', marginTop: '2px' }}>None recorded</div>}
                </div>

                <div>
                  <strong className="muted">Dropped Files:</strong>
                  {sb.indicators?.filesystem?.length > 0 ? (
                    <ul style={{ paddingLeft: '16px', marginTop: '4px' }}>
                      {sb.indicators.filesystem.slice(0, 5).map((f, i) => (
                        <li key={i} className="mono" style={{ wordBreak: 'break-all' }}>{f}</li>
                      ))}
                    </ul>
                  ) : <div className="muted" style={{ fontStyle: 'italic', marginTop: '2px' }}>None recorded</div>}
                </div>

                <div>
                  <strong className="muted">Registry Modifications:</strong>
                  {sb.indicators?.registry?.length > 0 ? (
                    <ul style={{ paddingLeft: '16px', marginTop: '4px' }}>
                      {sb.indicators.registry.slice(0, 5).map((r, i) => (
                        <li key={i} className="mono" style={{ wordBreak: 'break-all' }}>{r}</li>
                      ))}
                    </ul>
                  ) : <div className="muted" style={{ fontStyle: 'italic', marginTop: '2px' }}>None recorded</div>}
                </div>

                <div>
                  <strong className="muted">Process & Persistence:</strong>
                  {sb.indicators?.persistence?.length > 0 ? (
                    <ul style={{ paddingLeft: '16px', marginTop: '4px' }}>
                      {sb.indicators.persistence.slice(0, 5).map((p, i) => (
                        <li key={i} className="mono" style={{ wordBreak: 'break-all' }}>{p}</li>
                      ))}
                    </ul>
                  ) : <div className="muted" style={{ fontStyle: 'italic', marginTop: '2px' }}>None recorded</div>}
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
