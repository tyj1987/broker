import re,json
from pathlib import Path
root=Path(r'E:\Workspaces\52trz-platform\repo')
targets=[
 ('apps/business-service/api/database.py.orig',32),
 ('notes/phase-13/W13.5-SECURITY-P0.md',53),
 ('ops/blog/fix-fs-method.py',14),
 ('ops/security/tests/test_tracked_secret_scanner.py',27),
]
def redact(s):
    # protect quoted or assignment values following sensitive labels
    s=re.sub(r"(?i)((?:JWT_SECRET|POSTGRES_PASSWORD|TRZ_FEISHU_SECRET|MYSQL_ROOT_PASSWORD|PASSWORD|SECRET)\s*[:=]\s*)([^\s,;#)]+|['\"][^'\"]*['\"])",r"\1[REDACTED_VALUE]",s)
    s=re.sub(r"(?i)(['\"]TRZ_FEISHU_SECRET['\"]\s*,\s*)['\"][^'\"]*['\"]",r"\1'[REDACTED_VALUE]'",s)
    s=re.sub(r"[A-Za-z0-9_\-+/=]{20,}", "[REDACTED_TOKENLIKE]", s)
    return s
out=[]
for rel,n in targets:
    p=root/rel
    lines=p.read_text(encoding='utf-8',errors='replace').splitlines()
    ctx=[]
    for i in range(max(1,n-3),min(len(lines),n+3)+1):
        ctx.append({'line':i,'text':redact(lines[i-1])[:700]})
    out.append({'file':rel,'target_line':n,'context':ctx})
print(json.dumps(out,ensure_ascii=True,indent=2))
