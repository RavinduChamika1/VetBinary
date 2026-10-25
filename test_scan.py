import httpx, time

client = httpx.Client(base_url="http://127.0.0.1:8000", timeout=60.0)
r = client.post(
    "/scans",
    data={
        "purpose_comment": "Testing false-positive detection & elimination engine",
        "deployment_scope": "Engineering developer workstation",
        "allow_public_sandbox_sharing": "false",
    },
    files={"file": ("test_tool.exe", b"MZ\x90\x00" + b"A" * 1024, "application/octet-stream")},
)
print("Create response:", r.status_code, r.text)
sid = r.json().get("scan_id")

for i in range(25):
    time.sleep(1)
    s = client.get(f"/scans/{sid}").json()
    print(f"Step {i}: status={s.get('status')} | step={s.get('current_step')}")
    if s.get("status") in ("completed", "error"):
        break

if s.get("status") == "completed":
    rep = client.get(f"/scans/{sid}/report").json()
    print("\n--- FINAL REPORT ---")
    print("Verdict:", rep.get("at_a_glance", {}).get("verdict"))
    print("Risk Score:", rep.get("at_a_glance", {}).get("risk_score"))
    print("One line:", rep.get("at_a_glance", {}).get("one_line_reason"))
    print("AI Model:", rep.get("ai_assessment", {}).get("model"))
    print("AI Summary:", rep.get("ai_assessment", {}).get("assessment_summary"))
    print("AI Adjustment:", rep.get("ai_assessment", {}).get("verdict_adjustment"))
    print("Verified CVEs:", len(rep.get("ai_assessment", {}).get("verified_cves", [])))
    print("Confirmed findings:", len(rep.get("file_reputation", {}).get("confirmed_findings", [])))
    print("Needs review findings:", len(rep.get("file_reputation", {}).get("needs_review_findings", [])))

    pdf_resp = client.get(f"/scans/{sid}/report.pdf")
    print("PDF Status:", pdf_resp.status_code, "Size bytes:", len(pdf_resp.content))
