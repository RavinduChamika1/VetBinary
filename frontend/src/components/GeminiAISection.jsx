export default function GeminiAISection({ aiAssessment }) {
  if (!aiAssessment || !aiAssessment.consulted) {
    return (
      <div className="card">
        <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span>Gemini AI — False-Positive & Vulnerability Audit</span>
          <span className="badge badge-skip">Inactive</span>
        </div>
        <div className="card-body">
          <p className="muted" style={{ fontSize: '0.85rem' }}>
            Gemini AI false-positive elimination is inactive. Configure <code>GEMINI_API_KEY</code> in <code>.env</code> (free key from <a href="https://aistudio.google.com" target="_blank" rel="noreferrer">aistudio.google.com</a>) to automatically audit CVEs, eliminate false positives, and verify antivirus heuristics.
          </p>
        </div>
      </div>
    )
  }

  const {
    assessment_summary,
    verdict_adjustment,
    reasoning,
    verified_cves = [],
    behavioral_risk_evaluation,
    model,
  } = aiAssessment

  let adjBadgeClass = 'badge-skip'
  if (verdict_adjustment === 'CONFIRM') adjBadgeClass = 'badge-danger'
  else if (verdict_adjustment === 'MARK_SAFE') adjBadgeClass = 'badge-safe'
  else if (verdict_adjustment === 'DOWNGRADE_TO_REVIEW') adjBadgeClass = 'badge-review'

  return (
    <div className="card" style={{ borderColor: 'var(--accent)' }}>
      <div className="card-header" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', background: 'rgba(79, 142, 247, 0.1)' }}>
        <span style={{ color: 'var(--accent)', fontWeight: 700 }}>
          ✨ Gemini AI — False-Positive & Vulnerability Audit
        </span>
        <span className="badge badge-high" style={{ textTransform: 'uppercase' }}>
          {model || 'gemini-2.5-flash'}
        </span>
      </div>
      <div className="card-body">
        {/* Executive summary & verdict adjustment */}
        <div style={{ background: 'var(--surface2)', padding: '14px', borderRadius: 'var(--radius)', border: '1px solid var(--border)', marginBottom: '16px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
            <span style={{ fontSize: '0.78rem', textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--text-muted)', fontWeight: 700 }}>
              AI Executive Assessment
            </span>
            <span className={`badge ${adjBadgeClass}`}>
              Adjustment: {verdict_adjustment}
            </span>
          </div>
          <div style={{ fontSize: '0.95rem', fontWeight: 600, color: 'var(--text)', marginBottom: '6px' }}>
            {assessment_summary}
          </div>
          {reasoning && (
            <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', lineHeight: 1.5, marginTop: '8px' }}>
              {reasoning}
            </div>
          )}
          {aiAssessment.initial_cve_intel && (
            <div style={{ background: 'rgba(255, 193, 7, 0.1)', border: '1px solid rgba(255, 193, 7, 0.3)', padding: '10px 12px', borderRadius: '4px', marginTop: '10px', fontSize: '0.85rem' }}>
              <strong style={{ color: 'var(--review)' }}>🛡️ Pre-Flight Threat & Breach Intelligence:</strong>
              <div style={{ marginTop: '4px', color: 'var(--text)' }}>{aiAssessment.initial_cve_intel}</div>
            </div>
          )}
          {behavioral_risk_evaluation && (
            <div style={{ fontSize: '0.82rem', color: 'var(--text-muted)', fontStyle: 'italic', marginTop: '10px', borderTop: '1px solid var(--border)', paddingTop: '8px' }}>
              <strong>Dynamic Behavior:</strong> {behavioral_risk_evaluation}
            </div>
          )}
          {aiAssessment.recommended_remediation && aiAssessment.recommended_remediation.length > 0 && (
            <div style={{ marginTop: '12px', borderTop: '1px solid var(--border)', paddingTop: '10px' }}>
              <div style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--accent)', fontWeight: 700, marginBottom: '6px' }}>
                🔧 Tailored PC & Firewall Remediation Rules
              </div>
              <ul style={{ paddingLeft: '20px', margin: 0, fontSize: '0.84rem', lineHeight: 1.5 }}>
                {aiAssessment.recommended_remediation.map((rem, i) => (
                  <li key={i} style={{ marginBottom: '4px' }}>{rem}</li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Audited candidate CVEs */}
        {verified_cves.length > 0 && (
          <div>
            <h4 style={{ fontSize: '0.8rem', textTransform: 'uppercase', letterSpacing: '0.8px', color: 'var(--text-muted)', marginBottom: '10px' }}>
              Audited Candidate Vulnerabilities ({verified_cves.length})
            </h4>
            <div style={{ overflowX: 'auto' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>CVE ID</th>
                    <th>Audit Verdict</th>
                    <th>Confidence</th>
                    <th>Technical Justification</th>
                  </tr>
                </thead>
                <tbody>
                  {verified_cves.map((vc, idx) => (
                    <tr key={idx}>
                      <td className="mono" style={{ whiteSpace: 'nowrap' }}>
                        <a href={`https://nvd.nist.gov/vuln/detail/${vc.cve_id}`} target="_blank" rel="noreferrer">
                          {vc.cve_id}
                        </a>
                      </td>
                      <td>
                        {vc.is_true_positive ? (
                          <span className="badge badge-danger">TRUE POSITIVE</span>
                        ) : (
                          <span className="badge badge-safe">FALSE POSITIVE (FILTERED)</span>
                        )}
                      </td>
                      <td>
                        <span className={`badge ${vc.confidence === 'HIGH' ? 'badge-high' : 'badge-low'}`}>
                          {vc.confidence}
                        </span>
                      </td>
                      <td style={{ fontSize: '0.82rem', lineHeight: 1.4 }}>
                        {vc.technical_justification}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
