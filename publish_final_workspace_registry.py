import os,json,subprocess,hashlib,shutil,datetime
from pathlib import Path

ROOT=Path(r'E:\Workspaces')
CTL=ROOT/'_control'
GIT=r'C:\Program Files\Git\cmd\git.exe'
ENV=dict(os.environ,GIT_OPTIONAL_LOCKS='0',GIT_TERMINAL_PROMPT='0',GCM_INTERACTIVE='Never')
REV='ROG-E-WORKSPACES-20260923-FINAL-01'
NOW=datetime.datetime.now(datetime.timezone.utc).isoformat()

def read_json(p):
    return json.loads(Path(p).read_text(encoding='utf-8-sig'))

def run_git(path,args,timeout=45):
    try:
        z=subprocess.run([GIT,'--no-optional-locks','-c','core.fsmonitor=false','-C',str(path)]+args,capture_output=True,timeout=timeout,env=ENV)
        return z.returncode,z.stdout.decode('utf-8','replace').strip()
    except subprocess.TimeoutExpired:
        return 124,''

def git_state(path):
    path=Path(path)
    rc,head=run_git(path,['rev-parse','--verify','HEAD'])
    cr,common=run_git(path,['rev-parse','--path-format=absolute','--git-common-dir'])
    sr,status=run_git(path,['status','--porcelain=v1','--untracked-files=normal'])
    br,branch=run_git(path,['branch','--show-current'])
    return {
        'is_git':cr==0,'head_rc':rc,'head':head if rc==0 else None,
        'branch':branch if br==0 else '','status_rc':sr,
        'dirty_records':len(status.splitlines()) if sr==0 and status else 0,
        'common_git_dir':common if cr==0 else None,
        'git_storage_on_E':cr==0 and os.path.splitdrive(os.path.realpath(common))[0].lower()=='e:'
    }

def real(p):
    return os.path.normpath(os.path.realpath(str(p)))

def on_e(p):
    return os.path.splitdrive(real(p))[0].lower()=='e:'

def backup_and_write(path,text):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    if path.exists():
        backup=path.with_name(path.name+'.before-final-20260923')
        if not backup.exists():
            shutil.copy2(path,backup)
    tmp=path.with_name(path.name+'.tmp-final-20260923')
    tmp.write_text(text,encoding='utf-8',newline='')
    os.replace(tmp,path)

plan=read_json(CTL/'migration-capacity.json')
remote_audit=read_json(CTL/'final-remote-audit-20260923.json')
remote_by_name={r['repository']:r for r in remote_audit['repositories']}

path_entries=[]
for x in plan:
    src=Path(x['source']);dst=Path(x['destination'])
    se=os.path.lexists(src);de=os.path.lexists(dst)
    sr=real(src) if se else None;dr=real(dst) if de else None
    same=bool(se and de and os.path.normcase(sr)==os.path.normcase(dr))
    path_entries.append({
        'project':x['project'],'previous_path':x['source'],'workspace_path':x['destination'],
        'previous_exists':se,'workspace_exists':de,'previous_realpath':sr,'workspace_realpath':dr,
        'same_physical_target':same,'physical_on_E':bool(de and on_e(dst)),
        'verified':bool(de and on_e(dst) and same),
        'planned_bytes':x.get('bytes'),'planned_files':x.get('files')
    })

extra=[
 ('jianglanlu',r'E:\Workspaces\jianglanlu\development\dev\jianglan-dev',r'E:\Workspaces\jianglanlu\repo'),
 ('billiards-web',r'E:\Workspaces\infra\repo\billiards-web',r'E:\Workspaces\billiards-web\repo'),
 ('mercedes-e300l',r'E:\Workspaces\mercedes-e300l\assets',r'E:\Workspaces\mercedes-e300l\assets'),
 ('chatlink',r'E:\Workspaces\chatlink\repositories\runtime-stability',r'E:\Workspaces\chatlink\repositories\runtime-stability')
]
for project,srcs,dsts in extra:
    src=Path(srcs);dst=Path(dsts)
    se=os.path.lexists(src);de=os.path.lexists(dst)
    same=bool(se and de and os.path.normcase(real(src))==os.path.normcase(real(dst)))
    path_entries.append({
        'project':project,'previous_path':str(src),'workspace_path':str(dst),
        'previous_exists':se,'workspace_exists':de,
        'previous_realpath':real(src) if se else None,'workspace_realpath':real(dst) if de else None,
        'same_physical_target':same,'physical_on_E':bool(de and on_e(dst)),
        'verified':bool(de and on_e(dst) and same)
    })

project_defs={
 'broker':{'ide':ROOT/'broker'/'broker-ROG.code-workspace','entries':{'repo':ROOT/'broker'/'repo'},'remote':'broker'},
 'chatlink':{'ide':ROOT/'chatlink'/'chatlink-ROG.code-workspace','entries':{'runtime':ROOT/'chatlink'/'repositories'/'runtime-stability','commercial':ROOT/'chatlink'/'repo','git_objects':ROOT/'chatlink'/'repositories'/'desktop-link'},'remote':'desktop-link'},
 'woai-download':{'ide':ROOT/'woai-download'/'woai-download-ROG.code-workspace','entries':{'store':ROOT/'woai-download'/'worktrees'/'woai-store-validation-20260920','commerce':ROOT/'woai-download'/'repo'},'remote':'woai-download'},
 'lumia950-linux-desktop':{'ide':ROOT/'lumia950-linux-desktop'/'lumia950-linux-desktop-ROG.code-workspace','entries':{'repo':ROOT/'lumia950-linux-desktop'/'repo'},'remote':'lumia950-linux-desktop'},
 'moxiang':{'ide':ROOT/'moxiang'/'moxiang-ROG.code-workspace','entries':{'repo':ROOT/'moxiang'/'repo','sql_runtime':ROOT/'moxiang'/'runtime-data'/'sql'},'remote':None},
 'moxian-terminal':{'ide':ROOT/'moxian-terminal'/'moxian-terminal-ROG.code-workspace','entries':{'repo':ROOT/'moxian-terminal'/'repo'},'remote':'moxian-terminal'},
 'jianglanlu':{'ide':ROOT/'jianglanlu'/'jianglanlu-ROG.code-workspace','entries':{'repo':ROOT/'jianglanlu'/'repo','development':ROOT/'jianglanlu'/'development'},'remote':'jianglanlu'},
 '52trz-platform':{'ide':ROOT/'52trz-platform'/'52trz-platform-ROG.code-workspace','entries':{'repo':ROOT/'52trz-platform'/'repo'},'remote':'52trz-platform'},
 'infra':{'ide':ROOT/'infra'/'infra-ROG.code-workspace','entries':{'repo':ROOT/'infra'/'repo'},'remote':None},
 'billiards-web':{'ide':ROOT/'billiards-web'/'billiards-web-ROG.code-workspace','entries':{'repo':ROOT/'billiards-web'/'repo'},'remote':None},
 'open-webui':{'ide':ROOT/'open-webui'/'open-webui-ROG.code-workspace','entries':{'repo':ROOT/'open-webui'/'repo'},'remote':None},
 'textbook-parser':{'ide':ROOT/'textbook-parser'/'textbook-parser-ROG.code-workspace','entries':{'repo':ROOT/'textbook-parser'/'repo'},'remote':None},
 'qinglan-art':{'ide':ROOT/'qinglan-art'/'qinglan-art-ROG.code-workspace','entries':{'assets':ROOT/'qinglan-art'/'assets'},'remote':None},
 'mercedes-e300l':{'ide':ROOT/'mercedes-e300l'/'mercedes-e300l-ROG.code-workspace','entries':{'assets':ROOT/'mercedes-e300l'/'assets'},'remote':None}
}

projects=[]
for name,d in project_defs.items():
    entry_info={}
    for role,p in d['entries'].items():
        exists=os.path.lexists(p)
        gi=git_state(p) if exists and Path(p).is_dir() and role!='sql_runtime' else None
        entry_info[role]={
            'path':str(p),'exists':exists,'physical_path':real(p) if exists else None,
            'physical_on_E':bool(exists and on_e(p)),'git':gi
        }
    remote_name=d['remote']
    if remote_name:
        rr=remote_by_name[remote_name]
        remote_status={
            'repository':remote_name,'github_heads':rr['github_heads'],'gitlab_heads':rr['gitlab_heads'],
            'all_heads_equal':rr['all_heads_equal'],'difference_count':len(rr['differences']),
            'canonical_sync_branch':rr.get('canonical_sync_branch'),
            'canonical_github':rr.get('canonical_github'),'canonical_gitlab':rr.get('canonical_gitlab'),
            'canonical_equal':rr.get('canonical_equal')
        }
    elif name=='moxiang':
        rc,rv=run_git(ROOT/'moxiang'/'repo',['remote','-v'])
        remote_status={
            'repository':'MoxiangReborn','github_origin_configured':rc==0 and 'github.com' in rv.lower(),
            'gitlab_mapping_confirmed':False,
            'gitlab_probe_names':['MoxiangReborn','moxiang','moxiang-reborn'],
            'gitlab_probe_result':'no existing repository confirmed'
        }
    elif name in ('open-webui','textbook-parser'):
        remote_status={'mode':'upstream-third-party','dual_remote_sync_required':False}
    else:
        remote_status={'mode':'not_configured_or_non_git_asset','dual_remote_sync_required':False}
    projects.append({
        'project':name,'ide_workspace':str(d['ide']),'ide_exists':d['ide'].is_file(),
        'entries':entry_info,'remote':remote_status
    })

path_exceptions=[e for e in path_entries if not e['verified']]
remote_exceptions=[]
for p in projects:
    rr=p['remote']
    if rr.get('all_heads_equal') is False:
        remote_exceptions.append({'project':p['project'],'remote':rr})
    if p['project']=='moxiang' and not rr.get('gitlab_mapping_confirmed'):
        remote_exceptions.append({'project':'moxiang','remote':rr})

registry={
 'schema_version':3,'revision':REV,'authoritative':True,'device':'ROG','generated_utc':NOW,
 'workspace_root':str(ROOT),
 'user_decision':'All identified active project development uses per-project workspaces under E:\\Workspaces. Old paths remain compatibility entries and rollback copies are retained.',
 'projects':projects,'path_entries':path_entries,
 'path_verification':{'total':len(path_entries),'verified':sum(e['verified'] for e in path_entries),'exceptions':path_exceptions},
 'remote_verification':{
    'source':str(CTL/'final-remote-audit-20260923.json'),
    'dual_remote_repositories':[
        {'repository':r['repository'],'github_heads':r['github_heads'],'gitlab_heads':r['gitlab_heads'],
         'all_heads_equal':r['all_heads_equal'],'differences':r['differences']}
        for r in remote_audit['repositories']
    ],
    'all_configured_dual_remotes_equal':all(r['all_heads_equal'] for r in remote_audit['repositories']),
    'exceptions':remote_exceptions
 },
 'database_runtime':{
    'moxiang_sql_path':str(ROOT/'moxiang'/'runtime-data'/'sql'),
    'databases':['mhcmember','mhgame','mhlog','mhcnews'],
    'online_and_checkdb_verified':True,
    'evidence':str(CTL/'sql-relocation-20260923-retry'/'results.json')
 },
 'rollback_policy':{'retired_suffix':'.rog-retired-20260923','retained':True,'do_not_use_as_active_baseline':True},
 'broadcast':{
    'local_rules':str(ROOT/'AGENTS.md'),'codex_global_rules':r'C:\CodexData\AGENTS.md',
    'project_notice_name':'WORKSPACE_NOTICE.md','chatgpt_global_memory_updated':False,'recipient_acknowledgements':[]
 },
 'durable_plan_id':'Sl-PZaL3_XDpd3tbFEeSUua5inWgACi1NxfZRcKBs2o'
}

memory={
 'type':'local_shared_project_memory','revision':REV,'device':'ROG','recorded_utc':NOW,
 'workspace_root':str(ROOT),'authoritative_registry':str(ROOT/'WORKSPACE_REGISTRY.json'),
 'rules':[
   'Read E:\\Workspaces\\AGENTS.md, WORKSPACE_REGISTRY.json, and the target project WORKSPACE_NOTICE.md before development.',
   'Old C or D paths are compatibility junctions; active development uses E:\\Workspaces.',
   'Do not reset, clean, force-push, or overwrite independent WIP for directory tidiness.',
   'Keep ChatLink runtime vs commercial and Woai Store vs commerce worktrees separate.',
   'Re-query local, GitHub, and GitLab before reporting sync status.'
 ],
 'canonical_entries':{p['project']:{k:v['path'] for k,v in p['entries'].items()} for p in projects},
 'dual_remote_status':{
    r['repository']:{'github_heads':r['github_heads'],'gitlab_heads':r['gitlab_heads'],'equal':r['all_heads_equal']}
    for r in remote_audit['repositories']
 },
 'known_exception':{
    'moxiang':'GitHub origin exists; no confirmed corresponding GitLab repository or mapping was found. Do not invent a target repository.',
    'non_git_assets':'Qinglan and Mercedes assets are local E-drive assets, not Git dual-remote repositories.'
 },
 'chatgpt_global_memory_updated':False,'closed_or_other_sessions_acknowledged':False,
 'local_broadcast_published':True,'durable_plan_id':registry['durable_plan_id']
}

agents="""# ROG 项目开发接续

本机项目统一开发根目录：E:\\Workspaces。本规则由用户于 2026-09-23 确认。

## 开始开发前
1. 读取 E:\\Workspaces\\WORKSPACE_REGISTRY.json。
2. 读取目标项目的 WORKSPACE_NOTICE.md 与项目自身 AGENTS.md（若存在）。
3. 核对真实路径、当前 Git HEAD、暂存区和未提交文件；不要凭旧聊天猜路径或分支。

## 开发入口
使用每个项目的 <项目名>-ROG.code-workspace。ChatLink 运行时/商业功能、Woai 商店版/商业版必须分别接续，不得因整理目录而合并。

## 数据保护
旧 C/D 路径中的 Junction 只是兼容入口；.rog-retired-20260923 是回滚副本，不是活动开发基线。禁止为“干净整洁”执行 reset --hard、clean -fdx、强推或覆盖独有改动。

## 同步
WORKSPACE_REGISTRY.json 是当前本机权威目录清单。配置了 GitHub+GitLab 的仓库只有重新查询两端 refs 后才能报告同步。未提交 WIP、数据库和大型资产必须单独判断，不能因 refs 一致而宣称已上传。

## 广播边界
本机规则已写入 E:\\Workspaces\\AGENTS.md、C:\\CodexData\\AGENTS.md 和各项目 WORKSPACE_NOTICE.md。这不代表已关闭会话或其他模型已经读取；确认读取前不得声称已通知。
"""

report=['# ROG E 盘统一工作区最终登记','',
        '修订：'+REV,'生成时间（UTC）：'+NOW,'统一根目录：E:\\Workspaces',
        '原计划路径核验：%d/%d 通过'%(registry['path_verification']['verified'],registry['path_verification']['total']),
        '配置双远端的仓库：%d 个；全分支 GitHub/GitLab 一致：%s'%(len(remote_audit['repositories']),registry['remote_verification']['all_configured_dual_remotes_equal']),
        '墨香数据库：4 库均已迁入 E 盘，ONLINE 且已完成 CHECKDB 验证。','','## 项目入口','',
        '| 项目 | IDE / 主入口 | 本地状态 | 双端状态 |','|---|---|---|---|']
for p in projects:
    gitinfo=next((v['git'] for v in p['entries'].values() if v.get('git') and v['git'].get('is_git')),None)
    local='非 Git / 资产' if not gitinfo else (str(gitinfo['dirty_records'])+' 条本地状态' if gitinfo['dirty_records'] else 'Git 工作区干净')
    rr=p['remote']
    if rr.get('all_heads_equal') is True:
        remote='GitHub/GitLab 全分支一致'
    elif p['project']=='moxiang':
        remote='GitHub 已配置；无已确认 GitLab 对应仓库'
    elif rr.get('mode')=='upstream-third-party':
        remote='第三方上游副本'
    else:
        remote='未配置双端 / 非 Git 资产'
    report.append('| %s | %s | %s | %s |'%(p['project'],p['ide_workspace'],local,remote))
report += ['','## 保护规则','',
           '- .rog-retired-20260923 回滚副本继续保留；不是活动工作区。',
           '- 本轮没有通过 reset/clean/强推制造“干净”状态。',
           '- 本地未提交内容继续保留，需由对应开发任务决定何时提交。',
           '- ChatGPT 全局记忆没有可用写入工具；本机文件与 ChatLink 持久计划是实际广播载体。','']
migration_md='\n'.join(report)

backup_and_write(ROOT/'WORKSPACE_REGISTRY.json',json.dumps(registry,ensure_ascii=False,indent=2)+'\n')
backup_and_write(ROOT/'MEMORY.json',json.dumps(memory,ensure_ascii=False,indent=2)+'\n')
backup_and_write(ROOT/'AGENTS.md',agents)
backup_and_write(ROOT/'WORKSPACE-MIGRATION-20260923.md',migration_md)

codex=Path(r'C:\CodexData\AGENTS.md')
codex_text=codex.read_text(encoding='utf-8-sig')
start='<!-- rog-workspace-location-20260923:start -->'
end='<!-- rog-workspace-location-20260923:end -->'
new_block="""<!-- rog-workspace-location-20260923:start -->
## ROG 项目目录交接（2026-09-23）

用户指定的活动开发统一根目录是 E:\\Workspaces。接续任何项目前，读取 E:\\Workspaces\\AGENTS.md、E:\\Workspaces\\WORKSPACE_REGISTRY.json 和目标项目 WORKSPACE_NOTICE.md，再核对实际 HEAD、暂存区和未提交内容。

WORKSPACE_REGISTRY.json 修订为 ROG-E-WORKSPACES-20260923-FINAL-01，是当前本机权威目录清单。旧 C/D 路径 Junction 仅兼容旧工具；.rog-retired-20260923 只用于回滚。ChatLink 运行时/商业分支和 Woai 商店版/商业分支必须分别处理。

配置了 GitHub/GitLab 的仓库仍须在每次报告前重新查询两端；本地 WIP、数据库和资产不因 refs 相等而自动视为已上传。不得因目录整理强推、reset 或 clean。发布文件不代表关闭会话或其他模型已经阅读。
<!-- rog-workspace-location-20260923:end -->"""
if start in codex_text and end in codex_text:
    a=codex_text.index(start);b=codex_text.index(end,a)+len(end)
    codex_new=codex_text[:a]+new_block+codex_text[b:]
else:
    codex_new=codex_text.rstrip()+'\n\n'+new_block+'\n'
backup_and_write(codex,codex_new)

for p in projects:
    pr=ROOT/p['project']
    lines=['# '+p['project']+' 工作区交接','',
           '设备：ROG。登记修订：'+REV+'。','',
           'IDE 入口：'+p['ide_workspace']+'。','','活动入口：']
    for role,e in p['entries'].items():
        lines.append('- '+role+': '+e['path'])
    rr=p['remote']
    lines += ['','同步状态：']
    if rr.get('all_heads_equal') is True:
        lines.append('- '+rr['repository']+'：GitHub %d 个分支 / GitLab %d 个分支，当前全分支一致。'%(rr['github_heads'],rr['gitlab_heads']))
        if rr.get('canonical_sync_branch'):
            lines.append('- 规范迁移分支：'+str(rr['canonical_sync_branch'])+'。')
    elif p['project']=='moxiang':
        lines.append('- GitHub origin 已配置；没有确认到对应 GitLab 仓库。不得猜测仓库名或自行推送到未知目标。')
    elif rr.get('mode')=='upstream-third-party':
        lines.append('- 这是第三方上游副本，不按用户自有双端仓库处理。')
    else:
        lines.append('- 当前不是已配置的 GitHub/GitLab 双端代码仓库；按本地或资产项目处理。')
    git_infos=[e['git'] for e in p['entries'].values() if e.get('git') and e['git'].get('is_git')]
    if git_infos:
        lines += ['','本地状态：']
        for role,e in p['entries'].items():
            if e.get('git') and e['git'].get('is_git'):
                g=e['git']
                lines.append('- %s: branch=%s, HEAD=%s, dirty_records=%s。'%(role,g['branch'],g['head'],g['dirty_records']))
    lines += ['','接续规则：先读取 E:\\Workspaces\\AGENTS.md 与 E:\\Workspaces\\WORKSPACE_REGISTRY.json；不要从旧聊天复制旧路径。',
              '未提交内容必须保留；不要为整理执行 reset/clean/强推。旧 Junction 仅兼容路径，回滚副本不是活动基线。',
              '本公告已落盘，但不代表其他会话或模型已经读取。','']
    backup_and_write(pr/'WORKSPACE_NOTICE.md','\n'.join(lines))

published=[ROOT/'WORKSPACE_REGISTRY.json',ROOT/'MEMORY.json',ROOT/'AGENTS.md',ROOT/'WORKSPACE-MIGRATION-20260923.md',codex]
published += [ROOT/p['project']/'WORKSPACE_NOTICE.md' for p in projects]
published += [Path(p['ide_workspace']) for p in projects]
file_records=[]
for p in published:
    if p.exists():
        file_records.append({'path':str(p),'bytes':p.stat().st_size,'sha256':hashlib.sha256(p.read_bytes()).hexdigest()})

broadcast={
 'revision':REV,'device':'ROG','published_utc':NOW,'files':file_records,
 'authoritative_registry':str(ROOT/'WORKSPACE_REGISTRY.json'),'local_broadcast_published':True,
 'chatgpt_global_memory_updated':False,'recipient_acknowledgements':[],
 'statement':'Local persistent files and ChatLink durable plan were updated. No claim is made that closed conversations or other models have read them.'
}
backup_and_write(ROOT/'WORKSPACE_BROADCAST.json',json.dumps(broadcast,ensure_ascii=False,indent=2)+'\n')
receipt={
 'revision':REV,'device':'ROG','verified_utc':NOW,
 'registry_readback_revision':read_json(ROOT/'WORKSPACE_REGISTRY.json')['revision'],
 'memory_readback_revision':read_json(ROOT/'MEMORY.json')['revision'],
 'published_files':len(file_records)+1,
 'broadcast_sha256':hashlib.sha256((ROOT/'WORKSPACE_BROADCAST.json').read_bytes()).hexdigest(),
 'all_project_notices_exist':all((ROOT/p['project']/'WORKSPACE_NOTICE.md').is_file() for p in projects),
 'all_ide_workspaces_exist':all(Path(p['ide_workspace']).is_file() for p in projects),
 'path_entries_verified':registry['path_verification']['verified'],
 'path_entries_total':registry['path_verification']['total'],
 'path_exceptions':path_exceptions,
 'configured_dual_remotes_all_equal':registry['remote_verification']['all_configured_dual_remotes_equal'],
 'remote_exceptions':remote_exceptions,'recipient_acknowledgements':[]
}
(CTL/'final-broadcast-receipt-20260923.json').write_text(json.dumps(receipt,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
print(json.dumps({
 'revision':REV,'projects':len(projects),'path_entries_verified':receipt['path_entries_verified'],
 'path_entries_total':receipt['path_entries_total'],'path_exceptions':len(path_exceptions),
 'configured_dual_remotes_all_equal':receipt['configured_dual_remotes_all_equal'],
 'remote_exceptions':remote_exceptions,'published_files':receipt['published_files'],
 'all_notices':receipt['all_project_notices_exist'],'all_ide':receipt['all_ide_workspaces_exist'],
 'receipt':str(CTL/'final-broadcast-receipt-20260923.json')
},ensure_ascii=True))
