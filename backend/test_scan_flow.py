import asyncio
import httpx
import json

async def run_scan_test():
    filepath = r'C:\Users\Chamika\Downloads\npp.8.9.8.Installer.x64.exe'
    async with httpx.AsyncClient(timeout=180) as client:
        with open(filepath, 'rb') as f:
            files = {'file': ('npp.8.9.8.Installer.x64.exe', f, 'application/octet-stream')}
            data = {
                'purpose_comment': 'Evaluating Notepad++ 8.9.8 text editor for developer workstations',
                'deployment_scope': 'All developer workstations',
                'allow_public_sandbox_sharing': 'true',
            }
            print('Submitting scan...')
            resp = await client.post('http://127.0.0.1:8000/scans', files=files, data=data)
            print('Submit response:', resp.status_code, resp.json())
            scan_id = resp.json()['scan_id']

        # Poll status
        while True:
            await asyncio.sleep(2)
            s_resp = await client.get(f'http://127.0.0.1:8000/scans/{scan_id}')
            s_data = s_resp.json()
            status = s_data.get('status')
            step = s_data.get('current_step')
            print(f'Scan {scan_id} [{status}]: {step}')
            if status in ('completed', 'error', 'failed'):
                break

        if status == 'completed':
            rep_resp = await client.get(f'http://127.0.0.1:8000/scans/{scan_id}/report')
            rep = rep_resp.json()
            print('\n=== VETTING REPORT SUMMARY ===')
            print('Verdict:', rep['at_a_glance']['verdict'])
            print('Risk Score:', rep['at_a_glance']['risk_score'])
            print('One Line Reason:', rep['at_a_glance']['one_line_reason'])
            
            fr = rep.get('file_reputation', {})
            confirmed_list = fr.get('confirmed_findings', [])
            print(f'\nConfirmed Findings count: {len(confirmed_list)}')
            for cf in confirmed_list:
                print('  - [CONFIRMED]', cf.get('finding'), '| Evidence:', str(cf.get('evidence'))[:100])
                
            review_list = fr.get('needs_review_findings', [])
            print(f'Needs Review count: {len(review_list)}')
            for nr in review_list:
                print('  - [REVIEW]', nr.get('finding'), '| Reason:', str(nr.get('reasoning'))[:100])
                
            print('\nSandbox Results:')
            for sb in fr.get('sandbox_results', []):
                print(f"  Sandbox: {sb.get('service')} | Verdict: {sb.get('verdict')} | Score: {sb.get('score')}")
                inds = sb.get('indicators', {})
                net = inds.get('network', [])
                files = inds.get('filesystem', [])
                persist = inds.get('persistence', [])
                print(f"    Network ({len(net)}): {net[:3]}")
                print(f"    Files ({len(files)}): {files[:3]}")
                print(f"    Persistence/Signatures ({len(persist)}): {persist[:3]}")
                
            cves = rep.get('public_vulnerability_history', {}).get('cves', [])
            print(f'\nCVEs Queried count: {len(cves)}')
            for c in cves[:3]:
                print(f"  - {c.get('cve_id')} (CVSS {c.get('cvss_score')}) | Source: {c.get('source')} | KEV: {c.get('actively_exploited_kev_listed')}")
                
            ai = rep.get('ai_assessment', {})
            print(f"\nGemini AI Assessment ({ai.get('model')}): Adjustment = {ai.get('verdict_adjustment')}")
            print('Summary:', ai.get('assessment_summary'))
            v_cves = ai.get('verified_cves', [])
            print(f'Verified CVEs: {len(v_cves)}')
            fps = [vc for vc in v_cves if not vc.get('is_true_positive')]
            print(f'Filtered False Positives: {len(fps)}')
            
            # Test PDF download
            pdf_resp = await client.get(f'http://127.0.0.1:8000/scans/{scan_id}/report.pdf')
            print(f'\nPDF Generation Status: {pdf_resp.status_code}, length: {len(pdf_resp.content)} bytes')
            print(f'Scan ID {scan_id} is ready for browser inspection!')
        else:
            print('Scan Error:', s_data.get('error_message'))

if __name__ == '__main__':
    asyncio.run(run_scan_test())
