export default function SourcesTable({ sources = [] }) {
  if (!sources || sources.length === 0) {
    return null
  }

  return (
    <div className="card">
      <div className="card-header">Sources Consulted & Audit Trail</div>
      <div className="card-body" style={{ padding: 0 }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Source / API</th>
              <th>Status</th>
              <th>Checked At</th>
              <th>Details / Reason</th>
            </tr>
          </thead>
          <tbody>
            {sources.map((s, idx) => {
              let badgeClass = 'badge-skip'
              if (s.status === 'ok') badgeClass = 'badge-ok'
              else if (s.status === 'unavailable') badgeClass = 'badge-unavail'

              return (
                <tr key={idx}>
                  <td><strong>{s.source}</strong></td>
                  <td>
                    <span className={`badge ${badgeClass}`}>{s.status}</span>
                  </td>
                  <td className="muted mono" style={{ fontSize: '0.75rem' }}>
                    {s.checked_at ? new Date(s.checked_at).toLocaleTimeString() : 'N/A'}
                  </td>
                  <td className="muted">{s.reason_if_not_ok || 'OK / Response parsed'}</td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
