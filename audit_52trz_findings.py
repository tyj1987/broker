import json,re,hashlib
from pathlib import Path
scan=Path(r'D:\03_Data\ROG-Migration-Audit\20260923-033102\round2\52trz-filtered-full-scan.json')
root=Path(r'E:\Workspaces\52trz-platform\repo')
data=json.loads(scan.read_text(encoding='utf-8-sig'))
out=[]
placeholder_words=('example','dummy','fake','test','placeholder','changeme','sample','your_','replace','redacted','demo')
for f in data:
    rel=f['File']; line_no=int(f['StartLine'])
    p=root/rel
    rec={'file':rel,'line':line_no,'rule':f['RuleID'],'exists':p.is_file()}
    if p.is_file():
        try:
            lines=p.read_text(encoding='utf-8',errors='replace').splitlines()
            line=lines[line_no-1] if 0<line_no<=len(lines) else ''
            secret=f.get('Secret','') or ''
            match=f.get('Match','') or ''
            red=line
            if secret: red=red.replace(secret,'[REDACTED]')
            # redact long token-like literals conservatively
            red=re.sub(r'(?i)(token|secret|api[_-]?key|password|bearer)(\s*[:=]\s*[\'\"]?)[^\s\'\",}\]]+',r'\1\2[REDACTED]',red)
            red=re.sub(r'[A-Za-z0-9_\-+/=]{24,}', '[REDACTED_TOKENLIKE]', red)
            low=(line+' '+secret+' '+match).lower()
            rec.update(secret_sha256=hashlib.sha256(secret.encode()).hexdigest() if secret else None,
                       secret_length=len(secret),
                       placeholder_hint=any(w in low for w in placeholder_words),
                       path_role=('test' if 'test' in rel.lower() else 'docs' if rel.lower().startswith(('docs/','notes/')) else 'ops' if rel.lower().startswith('ops/') else 'source'),
                       redacted_line=red[:500])
        except Exception as e:
            rec['error']=str(e)
    out.append(rec)
print(json.dumps(out,ensure_ascii=True,indent=2))
