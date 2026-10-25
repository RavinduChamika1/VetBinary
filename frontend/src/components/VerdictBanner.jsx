export default function VerdictBanner({ verdict, riskScore, oneLineReason }) {
  let styleClass = 'safe'
  let label = 'SAFE TO DEPLOY'

  if (verdict === 'DO_NOT_DEPLOY') {
    styleClass = 'danger'
    label = 'DO NOT DEPLOY'
  } else if (verdict === 'NEEDS_MANUAL_REVIEW') {
    styleClass = 'review'
    label = 'NEEDS MANUAL REVIEW'
  }

  return (
    <div className={`verdict-banner ${styleClass}`}>
      <div className="verdict-label">{label}</div>
      <div className="risk-score">
        Risk Score: <strong>{riskScore != null ? Math.round(Number(riskScore) || 0) : 0}</strong> / 100
      </div>
      {oneLineReason && <div className="one-line">{oneLineReason}</div>}
    </div>
  )
}
