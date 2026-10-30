import re,json
from pathlib import Path
root=Path(r'E:\Workspaces\52trz-platform\repo')
targets=[
 'apps/business-service/api/database.py.orig',
 'notes/phase-13/W13.5-SECURITY-P0.md',
 'ops/blog/fix-fs-method.py',
]
def redact(s):
    s=re.sub(r"(?i)((?:JWT_SECRET|POSTGRES_PASSWORD|REDIS_PASSWORD|MYSQL_ROOT_PASSWORD|TRZ_FEISHU_SECRET|PASSWORD|SECRET)\s*[:=]\s*)([^\s,;#)]+|['\"][^'\"]*['\"])",r"\1[REDACTED_VALUE]",s)
    s=re.sub(r"(?i)(['\"]TRZ_FEISHU_SECRET['\"]\s*,\s*)['\"][^'\"]*['\"]",r"\1'[REDACTED_VALUE]'",s)
    s=re.sub(r"(?i)(postgres(?:ql)?://[^:\s/]+:)[^@\s/]+@",r"\1[REDACTED_VALUE]@",s)
    s=re.sub(r"(?i)(mysql://[^:\s/]+:)[^@\s/]+@",r"\1[REDACTED_VALUE]@",s)
    s=re.sub(r"[A-Za-z0-9_\-+/=]{28,}", "[REDACTED_TOKENLIKE]", s)
    return s
for rel in targets:
    p=root/rel
    print('---FILE',rel,'---')
    lines=p.read_text(encoding='utf-8',errors='replace').splitlines()
    for i,line in enumerate(lines,1):
        print(f'{i:04d}: {redact(line)}')
