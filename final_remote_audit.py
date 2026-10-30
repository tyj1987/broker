import os,subprocess,json,datetime
from pathlib import Path
git=r'C:\Program Files\Git\cmd\git.exe'
env=dict(os.environ,GIT_TERMINAL_PROMPT='0',GCM_INTERACTIVE='Never')
repos=[
 ('desktop-link',r'E:\Workspaces\chatlink\repositories\desktop-link'),
 ('woai-download',r'E:\Workspaces\woai-download\repo'),
 ('lumia950-linux-desktop',r'E:\Workspaces\lumia950-linux-desktop\repo'),
 ('broker',r'E:\Workspaces\broker\repo'),
 ('moxian-terminal',r'E:\Workspaces\moxian-terminal\repo'),
 ('jianglanlu',r'E:\Workspaces\jianglanlu\repo'),
 ('52trz-platform',r'E:\Workspaces\52trz-platform\repo'),
]
def run(args,timeout=60):
    try:
        z=subprocess.run(args,capture_output=True,timeout=timeout,env=env)
        return z.returncode,z.stdout.decode('utf-8','replace'),z.stderr.decode('utf-8','replace')
    except subprocess.TimeoutExpired:
        return 124,'','timeout'
def heads(url):
    rc,out,err=run([git,'ls-remote','--heads',url])
    d={}
    if rc==0:
        for line in out.splitlines():
            p=line.split()
            if len(p)==2:d[p[1]]=p[0]
    return rc,d,err[:300]
rows=[]
for name,path in repos:
    gh=f'https://github.com/tyj1987/{name}.git'
    gl=f'https://gitlab.52trz.com/52trz/{name}.git'
    gr,g,ge=heads(gh); lr,l,le=heads(gl)
    allrefs=sorted(set(g)|set(l))
    diffs=[{'ref':r,'github':g.get(r),'gitlab':l.get(r)} for r in allrefs if g.get(r)!=l.get(r)]
    hr,ho,he=run([git,'-C',path,'rev-parse','--verify','HEAD'])
    br,bo,be=run([git,'-C',path,'branch','--show-current'])
    row={'repository':name,'path':path,'github_rc':gr,'gitlab_rc':lr,'github_heads':len(g),'gitlab_heads':len(l),
         'all_heads_equal':gr==0 and lr==0 and not diffs,'differences':diffs,
         'local_head':ho.strip() if hr==0 else None,'local_head_rc':hr,'local_branch':bo.strip() if br==0 else ''}
    if name in ('jianglanlu','52trz-platform'):
        ref='refs/heads/migration/rog-20260923-synced'
        row['canonical_sync_branch']=ref.replace('refs/heads/','')
        row['canonical_github']=g.get(ref);row['canonical_gitlab']=l.get(ref)
        row['canonical_equal']=bool(g.get(ref)) and g.get(ref)==l.get(ref)
        rr,ro,re=run([git,'-C',path,'rev-parse','--verify',ref])
        row['canonical_local']=ro.strip() if rr==0 else None
        row['canonical_local_equal']=rr==0 and row['canonical_equal'] and ro.strip()==g.get(ref)
    rows.append(row)
# Probe any known local references to a GitLab Moxiang mapping without creating anything.
mox=r'E:\Workspaces\moxiang\repo'
rc,out,err=run([git,'-C',mox,'remote','-v'])
mox_remotes=out.splitlines() if rc==0 else []
# Search local config text for gitlab Moxiang URL.
candidate=[]
for p in [Path(r'E:\Workspaces\moxiang\repo\.git\config'),Path(r'E:\Workspaces\moxiang\repo\.git\config.worktree')]:
    if p.exists():
        text=p.read_text(encoding='utf-8',errors='replace')
        for line in text.splitlines():
            if 'gitlab.52trz.com' in line.lower():candidate.append(line.strip())
result={'device':'ROG','observed_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'repositories':rows,
        'moxiang_remote_lines':mox_remotes,'moxiang_gitlab_config_candidates':candidate}
out=Path(r'E:\Workspaces\_control\final-remote-audit-20260923.json')
out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps({
 'file':str(out),
 'summary':[{'repository':r['repository'],'github_heads':r['github_heads'],'gitlab_heads':r['gitlab_heads'],
             'all_heads_equal':r['all_heads_equal'],'canonical_equal':r.get('canonical_equal'),
             'canonical_local_equal':r.get('canonical_local_equal'),'difference_count':len(r['differences'])} for r in rows],
 'moxiang_gitlab_config_candidates':candidate
},ensure_ascii=True))
