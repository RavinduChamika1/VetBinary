export default function ApiCallLogSection({ callLog = [] }) {
  if (!callLog || callLog.length === 0) {
    return null
  }

  return (
    <div className="card">
      <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span>API Call Audit Log</span>
        <span className="badge badge-skip">{callLog.length} Requests Logged</span>
      </div>
      <div className="card-body" style={{ padding: 0 }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>Endpoint</th>
              <th>Called At</th>
              <th>HTTP</th>
              <th>Outcome</th>
              <th>Details / Note</th>
            </tr>
          </thead>
          <tbody>
            {callLog.map((c, idx) => {
              let badgeClass = 'badge-skip'
              if (c.outcome === 'ok') badgeClass = 'badge-ok'
              else if (c.outcome === 'error') badgeClass = 'badge-danger'

              return (
                <tr key={idx}>
                  <td><strong>{c.source}</strong></td>
                  <td className="mono" style={{ fontSize: '0.75rem', wordBreak: 'break-all', maxWidth: 220 }}>
                    {c.endpoint}
                  </td>
                  <td className="muted mono" style={{ fontSize: '0.75rem', whiteSpace: 'nowrap' }}>
                    {c.called_at ? new Date(c.called_at).toLocaleTimeString() : 'N/A'}
                  </td>
                  <td>
                    {c.http_status ? (
                      <span className={`badge ${c.http_status >= 400 ? 'badge-danger' : 'badge-ok'}`}>
                        {c.http_status}
                      </span>
                    ) : '—'}
                  </td>
                  <td>
                    <span className={`badge ${badgeClass}`}>{c.outcome}</span>
                  </td>
                  <td className="muted" style={{ fontSize: '0.78rem', maxWidth: 280 }}>
                    {c.reason || c.response_summary || '—'}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}
