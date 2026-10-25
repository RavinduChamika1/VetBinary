export default function EligibilityTable({ entries = [] }) {
  if (!entries || entries.length === 0) {
    return <p className="no-data">No sandbox eligibility evaluation recorded.</p>
  }

  return (
    <div className="card">
      <div className="card-header">Sandbox Eligibility & Constraints</div>
      <div className="card-body" style={{ padding: 0 }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>Service</th>
              <th>File Size Limit</th>
              <th>Actual Size</th>
              <th>Monthly Quota</th>
              <th>Status</th>
              <th>Details / Reason</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, idx) => (
              <tr key={idx}>
                <td><strong>{entry.service}</strong></td>
                <td>{entry.file_size_limit_mb ? `${entry.file_size_limit_mb} MB` : 'N/A'}</td>
                <td>{entry.file_size_actual_mb != null ? `${entry.file_size_actual_mb} MB` : 'N/A'}</td>
                <td>
                  {entry.monthly_quota_limit != null
                    ? `${entry.monthly_quota_used_this_month || 0} / ${entry.monthly_quota_limit}`
                    : 'Unlimited / N/A'}
                </td>
                <td>
                  {entry.eligible ? (
                    <span className="badge badge-ok">Eligible</span>
                  ) : (
                    <span className="badge badge-skip">Skipped</span>
                  )}
                </td>
                <td className="muted">{entry.skip_reason || 'Eligible and evaluated'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
