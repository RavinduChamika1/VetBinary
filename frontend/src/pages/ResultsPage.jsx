import { useEffect, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { getScanStatus, getScanReport, streamScan, openHtmlReport, openPdfReport } from '../api'
import VerdictBanner from '../components/VerdictBanner'
import ProgressLog from '../components/ProgressLog'
import FindingsSection from '../components/FindingsSection'
import CVESection from '../components/CVESection'
import EligibilityTable from '../components/EligibilityTable'
import SourcesTable from '../components/SourcesTable'
import GeminiAISection from '../components/GeminiAISection'
import VirusTotalSection from '../components/VirusTotalSection'
import SandboxSection from '../components/SandboxSection'
import RemediationSection from '../components/RemediationSection'
import ApiCallLogSection from '../components/ApiCallLogSection'

export default function ResultsPage() {
  const { scanId, id } = useParams()
  const effectiveId = scanId || id
  const navigate = useNavigate()

  const [scan, setScan] = useState(null)
  const [report, setReport] = useState(null)
  const [currentStep, setCurrentStep] = useState('Initializing scan…')
  const [steps, setSteps] = useState([])
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!effectiveId) return
    let es = null
    let pollInterval = null
    let isDone = false

    async function loadData() {
      try {
        const initialStatus = await getScanStatus(effectiveId)
        setScan(initialStatus)

        if (initialStatus.current_step) {
          setCurrentStep(initialStatus.current_step)
          setSteps((prev) => (prev.includes(initialStatus.current_step) ? prev : [...prev, initialStatus.current_step]))
        }

        if (initialStatus.status === 'completed') {
          isDone = true
          const rep = await getScanReport(effectiveId)
          setReport(rep)
          return
        }

        if (initialStatus.status === 'error' || initialStatus.status === 'failed') {
          isDone = true
          setError(initialStatus.error_message || 'Scan failed')
          return
        }

        // Active polling every 1000ms for rock-solid step updates
        pollInterval = setInterval(async () => {
          if (isDone) return
          try {
            const s = await getScanStatus(effectiveId)
            setScan(s)
            if (s.current_step) {
              setCurrentStep(s.current_step)
              setSteps((prev) => (prev.includes(s.current_step) ? prev : [...prev, s.current_step]))
            }
            if (s.status === 'completed') {
              isDone = true
              clearInterval(pollInterval)
              es?.close()
              const rep = await getScanReport(effectiveId)
              setReport(rep)
            } else if (s.status === 'error' || s.status === 'failed') {
              isDone = true
              clearInterval(pollInterval)
              es?.close()
              setError(s.error_message || 'Scan encountered an error')
            }
          } catch (_) {}
        }, 1000)

        // SSE streaming for real-time push events
        es = streamScan(
          effectiveId,
          async (msg) => {
            if (isDone) return
            const stepName = msg.current_step || msg.step
            if (stepName) {
              setCurrentStep(stepName)
              setSteps((prev) => (prev.includes(stepName) ? prev : [...prev, stepName]))
            }
            if (msg.status === 'completed') {
              isDone = true
              clearInterval(pollInterval)
              es?.close()
              const rep = await getScanReport(effectiveId)
              setReport(rep)
              const updated = await getScanStatus(effectiveId)
              setScan(updated)
            } else if (msg.status === 'error' || msg.status === 'failed') {
              isDone = true
              clearInterval(pollInterval)
              es?.close()
              setError(msg.error_message || 'Scan failed')
            }
          },
          () => {}
        )
      } catch (err) {
        setError(err.message || 'Failed to connect to scan')
      }
    }

    loadData()

    return () => {
      isDone = true
      if (pollInterval) clearInterval(pollInterval)
      es?.close()
    }
  }, [effectiveId])

  // Extract properties safely from report (supporting both nested schema and flat fallbacks)
  const verdict = report?.at_a_glance?.verdict || report?.verdict || scan?.verdict || 'SAFE_TO_DEPLOY'
  const riskScore = report?.at_a_glance?.risk_score ?? report?.risk_score ?? scan?.risk_score ?? 0
  const oneLineReason = report?.at_a_glance?.one_line_reason || report?.one_line_reason || ''

  const confirmedFindings = report?.file_reputation?.confirmed_findings || report?.confirmed_findings || []
  const needsReviewFindings = report?.file_reputation?.needs_review_findings || report?.needs_review_findings || []
  const vtResult = report?.file_reputation?.virustotal
  const sandboxResults = report?.file_reputation?.sandbox_results || []
  const cves = report?.public_vulnerability_history?.cves || report?.cves || []
  const aiAssessment = report?.ai_assessment
  const remediation = report?.remediation || []
  const sourcesConsulted = report?.sources_consulted || []
  const eligibilityTable = report?.eligibility_table || []
  const apiCallLog = report?.api_call_log || []

  const sw = report?.identified_software
  const isSigned = sw?.is_signed ?? report?.digital_signature?.is_signed
  const signerName = sw?.signer || report?.digital_signature?.signer

  return (
    <div className="page">
      <header className="site-header">
        <h1 style={{ cursor: 'pointer' }} onClick={() => navigate('/')}>
          VetBinary
        </h1>
        <div className="tagline">Pre-Deployment File Vetting Report</div>
      </header>

      {error && (
        <div className="error-bar">
          <div style={{ fontWeight: 700, marginBottom: '6px' }}>❌ Vetting Error Encountered</div>
          <div style={{ fontSize: '0.82rem', fontFamily: 'monospace', whiteSpace: 'pre-wrap', maxHeight: '180px', overflowY: 'auto' }}>
            {error}
          </div>
          <div style={{ marginTop: 12 }}>
            <button className="btn btn-ghost" onClick={() => navigate('/')}>
              ← Return to Upload
            </button>
          </div>
        </div>
      )}

      {!report && !error && (
        <div>
          <ProgressLog currentStep={currentStep} steps={steps} />
        </div>
      )}

      {report && (
        <div>
          {/* Top Verdict Banner */}
          <VerdictBanner
            verdict={verdict}
            riskScore={riskScore}
            oneLineReason={oneLineReason}
          />

          {/* Action buttons */}
          <div className="section-actions">
            <button className="btn btn-primary" onClick={() => openPdfReport(effectiveId)}>
              📥 Download Report (.pdf)
            </button>
            <button className="btn btn-ghost" onClick={() => openHtmlReport(effectiveId)}>
              🌐 View HTML Report
            </button>
            <button className="btn btn-ghost" onClick={() => navigate('/')}>
              ➕ Vet Another File
            </button>
          </div>

          <div className="disclaimer-bar">
            ℹ <strong>Pre-Deployment Disclaimer:</strong> This vetting report is based strictly on current,
            verified telemetry from public intelligence, dynamic sandboxes, and AI verification.
            It does not replace internal enterprise endpoint security controls (EDR, AppLocker, etc.).
          </div>

          {/* Binary Identity & Signatures */}
          <div className="card">
            <div className="card-header">Binary Identity & Authenticode Signatures</div>
            <div className="card-body">
              <table className="data-table">
                <tbody>
                  <tr>
                    <td style={{ width: '25%' }}><strong>File Name</strong></td>
                    <td>{report.file_name}</td>
                  </tr>
                  <tr>
                    <td><strong>File Size</strong></td>
                    <td>
                      {report.file_size_bytes
                        ? `${(report.file_size_bytes / (1024 * 1024)).toFixed(2)} MB (${report.file_size_bytes.toLocaleString()} bytes)`
                        : 'N/A'}
                    </td>
                  </tr>
                  <tr>
                    <td><strong>SHA-256</strong></td>
                    <td className="mono" style={{ wordBreak: 'break-all' }}>{report.sha256}</td>
                  </tr>
                  <tr>
                    <td><strong>Identified Software</strong></td>
                    <td>
                      {sw?.product || 'Unknown'} {sw?.version || ''}
                      {sw?.vendor ? ` by ${sw.vendor}` : ''}
                      {sw?.identification_confidence && (
                        <span
                          className={`badge ${sw.identification_confidence === 'high' ? 'badge-high' : 'badge-low'}`}
                          style={{ marginLeft: 8 }}
                        >
                          {sw.identification_confidence} confidence ({sw.identification_method || 'heuristic'})
                        </span>
                      )}
                    </td>
                  </tr>
                  <tr>
                    <td><strong>Digital Signature</strong></td>
                    <td>
                      {isSigned ? (
                        <span className="badge badge-safe">Signed: {signerName || 'Valid'}</span>
                      ) : (
                        <span className="badge badge-skip">Unsigned</span>
                      )}
                    </td>
                  </tr>
                  {report.purpose_comment && (
                    <tr>
                      <td><strong>Vetting Purpose</strong></td>
                      <td>{report.purpose_comment}</td>
                    </tr>
                  )}
                  {report.deployment_scope && (
                    <tr>
                      <td><strong>Deployment Scope</strong></td>
                      <td>{report.deployment_scope}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Gemini AI False-Positive & Vulnerability Audit */}
          <GeminiAISection aiAssessment={aiAssessment} />

          {/* Confirmed & Needs-Review Findings */}
          <FindingsSection
            confirmed={confirmedFindings}
            needsReview={needsReviewFindings}
          />

          {/* VirusTotal Telemetry */}
          <VirusTotalSection vtResult={vtResult} />

          {/* Dynamic Sandbox Telemetry */}
          <SandboxSection sandboxResults={sandboxResults} />

          {/* Public Vulnerability History (CVEs) */}
          <CVESection cves={cves} note={report?.public_vulnerability_history?.note} />

          {/* IT Remediation Steps */}
          <RemediationSection remediation={remediation} />

          {/* Sandbox Eligibility & Constraints */}
          <EligibilityTable entries={eligibilityTable} />

          {/* Sources Consulted */}
          <SourcesTable sources={sourcesConsulted} />

          {/* Complete External API Audit Trail */}
          <ApiCallLogSection callLog={apiCallLog} />
        </div>
      )}
    </div>
  )
}
