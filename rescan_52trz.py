import json,os,subprocess,hashlib
from pathlib import Path
root=Path(r'E:\Workspaces\52trz-platform\repo')
ctl=Path(r'E:\Workspaces\_control')
manifest=Path(r'D:\03_Data\ROG-Migration-Audit\20260923-033102\round2\52trz-stage\filtered-manifest.json')
gitleaks=Path(r'D:\03_Data\ROG-Migration-Audit\20260923-033102\tools\gitleaks.exe')
config=Path(r'D:\03_Data\ROG-Migration-Audit\20260923-033102\gitleaks-default.toml')
git=r'C:\Program Files\Git\cmd\git.exe'
m=json.loads(manifest.read_text(encoding='utf-8-sig'))
files=[p for p in m['files'] if (root/p).is_file()]
missing=[p for p in m['files'] if not (root/p).is_file()]
idx=ctl/'52trz-rescan.index'
if idx.exists(): idx.unlink()
env=dict(os.environ,GIT_INDEX_FILE=str(idx),GIT_TERMINAL_PROMPT='0')
def run(args,input=None,timeout=120):
    return subprocess.run(args,input=input,capture_output=True,env=env,timeout=timeout)
z=run([git,'-C',str(root),'read-tree','--empty'])
if z.returncode: raise SystemExit('read-tree failed')
payload=b'\0'.join(p.encode('utf-8') for p in files)+b'\0'
z=run([git,'-C',str(root),'add','-A','-f','--pathspec-from-file=-','--pathspec-file-nul'],input=payload,timeout=180)
if z.returncode: raise SystemExit('git add failed: '+z.stderr.decode('utf-8','replace')[:500])
z=run([git,'-C',str(root),'write-tree'])
if z.returncode: raise SystemExit('write-tree failed')
tree=z.stdout.decode().strip()
z=run([git,'-C',str(root),'commit-tree',tree,'-m','temporary scan root'])
if z.returncode: raise SystemExit('commit-tree failed')
commit=z.stdout.decode().strip()
report=ctl/'52trz-rescan-findings.json'
log=ctl/'52trz-rescan.log'
cmd=[str(gitleaks),'git',str(root),'--config',str(config),'--gitleaks-ignore-path',str(ctl),'--ignore-gitleaks-allow','--log-opts='+commit,'--redact=100','--no-banner','--no-color','--report-format','json','--report-path',str(report),'--timeout','180']
z=run(cmd,timeout=240)
log.write_bytes(z.stdout+z.stderr)
findings=json.loads(report.read_text(encoding='utf-8-sig')) if report.exists() and report.stat().st_size else []
summary={'tree':tree,'temporary_commit':commit,'files':len(files),'missing':missing,'scan_rc':z.returncode,'findings':len(findings),'finding_paths':sorted(set(f.get('File','') for f in findings))}
(ctl/'52trz-rescan-summary.json').write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(summary,ensure_ascii=True))
