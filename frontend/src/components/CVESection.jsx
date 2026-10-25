export default function CVESection({ cves = [], note = '' }) {
  if (!cves || cves.length === 0) {
    return (
      <div className="card">
        <div className="card-header">Public Vulnerability History (NVD, OSV.dev, CISA KEV)</div>
        <div className="card-body">
          {note && <p className="muted" style={{ fontStyle: 'italic', marginBottom: '8px' }}>{note}</p>}
          <p className="no-data">No known public CVEs identified for this software release in NVD or OSV.dev.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span>Public Vulnerability History</span>
        <span className="badge badge-high">{cves.length} Candidate CVEs Found</span>
      </div>
      <div className="card-body" style={{ padding: 0 }}>
        {note && (
          <div style={{ padding: '12px 16px', background: 'var(--surface2)', borderBottom: '1px solid var(--border)', fontSize: '0.82rem', fontStyle: 'italic', color: 'var(--text-muted)' }}>
            ℹ {note}
          </div>
        )}
        <table className="data-table">
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>CVSS</th>
              <th>Source</th>
              <th>KEV Exploited?</th>
              <th>Confidence</th>
              <th>Summary</th>
            </tr>
          </thead>
          <tbody>
            {cves.map((cve, idx) => (
              <tr key={idx}>
                <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                  <a
                    href={`https://nvd.nist.gov/vuln/detail/${cve.cve_id}`}
                    target="_blank"
                    rel="noreferrer"
                  >
                    {cve.cve_id}
                  </a>
                </td>
                <td>
                  <strong>{cve.cvss_score != null ? cve.cvss_score.toFixed(1) : '—'}</strong>
                </td>
                <td style={{ fontSize: '0.78rem', color: 'var(--text-muted)' }}>
                  {cve.source || 'NVD'}
                </td>
                <td>
                  {(cve.is_known_exploited || cve.actively_exploited_kev_listed) ? (
                    <span className="badge badge-danger">⚠ YES (KEV)</span>
                  ) : (
                    <span className="badge badge-skip">No</span>
                  )}
                </td>
                <td>
                  <span className={`badge ${(cve.confidence === 'high' || cve.match_confidence === 'high') ? 'badge-high' : 'badge-low'}`}>
                    {cve.confidence || cve.match_confidence || 'medium'}
                  </span>
                </td>
                <td style={{ maxWidth: 360, fontSize: '0.8rem', lineHeight: 1.4 }}>
                  {cve.summary}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
