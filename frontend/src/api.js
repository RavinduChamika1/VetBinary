/**
 * api.js — all fetch calls to the VetBinary backend.
 * /api/* is proxied to the FastAPI backend by Vite (dev) or Nginx (prod).
 */

const BASE = '/api'

export async function submitScan(formData) {
  const resp = await fetch(`${BASE}/scans`, {
    method: 'POST',
    body: formData, // multipart/form-data built by caller
  })
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ detail: resp.statusText }))
    throw new Error(err.detail || `HTTP ${resp.status}`)
  }
  return resp.json() // { scan_id, message }
}

export async function getScanStatus(scanId) {
  const resp = await fetch(`${BASE}/scans/${scanId}`)
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json()
}

export async function getScanReport(scanId) {
  const resp = await fetch(`${BASE}/scans/${scanId}/report`)
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`)
  return resp.json()
}

export function openHtmlReport(scanId) {
  window.open(`${BASE}/scans/${scanId}/report.html`, '_blank')
}

export function downloadPdfReport(scanId) {
  const link = document.createElement('a')
  link.href = `${BASE}/scans/${scanId}/report.pdf`
  link.setAttribute('download', `vetbinary_scan_${scanId}.pdf`)
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
}

export function openPdfReport(scanId) {
  downloadPdfReport(scanId)
}

/**
 * Subscribe to SSE progress events for a scan.
 * Returns an EventSource instance; caller should .close() when done.
 */
export function streamScan(scanId, onMessage, onError) {
  const es = new EventSource(`${BASE}/scans/${scanId}/stream`)
  es.onmessage = (e) => {
    try {
      onMessage(JSON.parse(e.data))
    } catch (_) {}
  }
  es.onerror = (e) => {
    onError && onError(e)
    es.close()
  }
  return es
}
