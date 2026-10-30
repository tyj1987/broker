import json,subprocess,os
from pathlib import Path
ctl=Path(r'E:\Workspaces\_control')
report=ctl/'52trz-rescan-findings.json'
summary=json.loads((ctl/'52trz-rescan-summary.json').read_text(encoding='utf-8-sig'))
findings=json.loads(report.read_text(encoding='utf-8-sig'))
reasons={
 'docs/PLATFORM_SOURCE_MANIFEST.md':'container image SHA256 digest in documentation',
 'notes/phase-4/PHASE-4-SUMMARY.md':'container image tag / image identifier in historical notes',
 'ops/deploy/docker-compose-pre-healthcheck-only.yml':'container image tag',
 'ops/deploy/docker-compose-20260801-pre-healthcheck.yml':'container image tag',
 'ops/monitor/collect-metrics.py':'public service hostname list, not a credential',
 'ops/probe/r3_apply.sh':'container image tag in deployment probe',
 'ops/probe/r3_fix_p.sh':'container image tag in deployment probe',
 'ops/probe/r3_recover.sh':'container image identifier mapping in recovery probe',
 'ops/probe/r3_recover2.sh':'container image tag in recovery probe',
 'ops/security/tests/test_tracked_secret_scanner.py':'synthetic credential test fixture explicitly marked secret-scan: allow-test-fixture',
}
paths=[f.get('File','') for f in findings]
if len(findings)!=10 or set(paths)!=set(reasons):
    raise SystemExit('unexpected finding set; manual review required')
if any(f.get('RuleID')!='generic-api-key' for f in findings):
    raise SystemExit('unexpected rule type')
review=[]
fps=[]
for f in findings:
    fp=f.get('Fingerprint')
    if not fp:
        raise SystemExit('finding missing fingerprint')
    fps.append(fp)
    review.append({'file':f['File'],'line':f.get('StartLine'),'rule':f['RuleID'],'fingerprint':fp,'classification':'reviewed_false_positive','reason':reasons[f['File']]})
ignore=ctl/'52trz-reviewed-false-positives.gitleaksignore'
ignore.write_text('\n'.join(fps)+'\n',encoding='utf-8')
assessment={
 'project':'52trz-platform','tree':summary['tree'],'temporary_commit':summary['temporary_commit'],
 'real_credential_findings_remediated':[
  'apps/business-service/api/database.py',
  'apps/business-service/api/database.py.orig',
  'notes/phase-13/W13.5-SECURITY-P0.md',
  'ops/blog/fix-fs-method.py'
 ],
 'reviewed_false_positives':review,
 'review_complete':True,
 'ignore_file':str(ignore)
}
(ctl/'52trz-gitleaks-review-20260923.json').write_text(json.dumps(assessment,ensure_ascii=False,indent=2),encoding='utf-8')
gitleaks=r'D:\03_Data\ROG-Migration-Audit\20260923-033102\tools\gitleaks.exe'
config=r'D:\03_Data\ROG-Migration-Audit\20260923-033102\gitleaks-default.toml'
root=r'E:\Workspaces\52trz-platform\repo'
out=ctl/'52trz-reviewed-rescan-findings.json'
cmd=[gitleaks,'git',root,'--config',config,'--gitleaks-ignore-path',str(ignore),'--ignore-gitleaks-allow','--log-opts='+summary['temporary_commit'],'--redact=100','--no-banner','--no-color','--report-format','json','--report-path',str(out),'--timeout','180']
z=subprocess.run(cmd,capture_output=True,timeout=240,env=dict(os.environ,GIT_TERMINAL_PROMPT='0'))
remaining=json.loads(out.read_text(encoding='utf-8-sig')) if out.exists() and out.stat().st_size else []
result={'tree':summary['tree'],'reviewed_findings':len(review),'rescan_rc':z.returncode,'remaining_findings':len(remaining),'safe_to_publish_tree':z.returncode==0 and len(remaining)==0}
(ctl/'52trz-reviewed-rescan-summary.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(result,ensure_ascii=True))
