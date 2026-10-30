import json,re
from pathlib import Path
scan=Path(r'D:\03_Data\ROG-Migration-Audit\20260923-033102\round2\52trz-filtered-full-scan.json')
root=Path(r'E:\Workspaces\52trz-platform\repo')
data=json.loads(scan.read_text(encoding='utf-8-sig'))
out=[]
for f in data:
    rel=f['File']; n=int(f['StartLine']); p=root/rel
    lines=p.read_text(encoding='utf-8',errors='replace').splitlines() if p.is_file() else []
    line=lines[n-1] if 0<n<=len(lines) else ''
    upper=line.upper()
    identifiers=[x for x in ['JWT_SECRET','POSTGRES_PASSWORD','TRZ_FEISHU_SECRET','MYSQL_ROOT_PASSWORD','API_KEY','TOKEN','PASSWORD','SECRET'] if x in upper]
    is_assignment=bool(re.search(r'(?i)(secret|password|token|api[_-]?key)[A-Z0-9_\-]*\s*[:=]',line))
    uses_env=bool(re.search(r'(?i)(os\.getenv|environ|getenv|\$\{|process\.env)',line))
    allow_fixture='allow-test-fixture' in line.lower()
    is_image=bool(re.search(r'(?i)(image:|sha256:|pinned-|docker|gateway:)',line))
    is_comment=line.lstrip().startswith(('#','//','*','- ','|'))
    quoted_literals=re.findall(r"""['"]([^'"]{4,})['"]""",line)
    placeholder_words=('changeme','change-me','example','dummy','fake','test','placeholder','sample','replace','redacted','development','dev-only')
    placeholder_hint=any(any(w in q.lower() for w in placeholder_words) for q in quoted_literals)
    out.append({
      'file':rel,'line':n,'role':'test' if 'test' in rel.lower() else 'docs' if rel.lower().startswith(('docs/','notes/')) else 'ops' if rel.lower().startswith('ops/') else 'source',
      'identifiers':identifiers,'credential_assignment':is_assignment,'uses_env_reference':uses_env,
      'allow_test_fixture':allow_fixture,'image_or_digest_context':is_image,'comment_or_doc_line':is_comment,
      'quoted_literal_count':len(quoted_literals),'placeholder_literal_hint':placeholder_hint,
      'risk':'high_review' if is_assignment and not uses_env and not allow_fixture and not is_image else 'likely_fixture_or_false_positive'
    })
print(json.dumps(out,ensure_ascii=True,indent=2))
