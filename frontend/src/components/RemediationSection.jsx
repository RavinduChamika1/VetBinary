export default function RemediationSection({ remediation = [] }) {
  if (!remediation || remediation.length === 0) {
    return null
  }

  return (
    <div className="card">
      <div className="card-header">IT Pre-Deployment Remediation Actions</div>
      <div className="card-body">
        <ol style={{ paddingLeft: '20px', lineHeight: 1.6, fontSize: '0.88rem' }}>
          {remediation.map((step, idx) => (
            <li key={idx} style={{ marginBottom: '6px' }}>
              {step}
            </li>
          ))}
        </ol>
      </div>
    </div>
  )
}
